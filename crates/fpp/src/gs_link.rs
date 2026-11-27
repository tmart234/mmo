//! Unified game-server ↔ Server Liveness control link over our owned
//! `Noise_IK` TCP transport (`crate::transport::sync`) and deterministic CBOR
//! messages (`crate::control`).
//!
//! Pure `std` — zero `tokio`, zero `quinn`, zero `rustls`, zero `bincode`.
//! Shared by BOTH `fpp-ffi` (`fpp_gs_link_*`) AND Rust game servers
//! (`fpp-sim`), eliminating the previous duplicate implementations in
//! `gs-sim` and `fpp-ffi/src/gs_link.rs`.

use crate::bundle::KeyBundle;
use crate::control::{
    join_quote_nonce, join_request_sign_bytes, AttestChallenge, ChallengeRequest, CheckpointSubmit,
    CredentialChallenge, CredentialResponse, JoinAccept, JoinRequest, Purpose, ToGameServer,
    CONTROL_VERSION, MAX_CONTROL_FRAME,
};
use crate::crypto::{ed25519_sign, now_ms, now_s, KeySet};
use crate::tokens::SarChain;
use crate::tpm2_collect::{Tpm2, Tpm2Options, BOOT_LOG, IMA_LOG};
use crate::transport::sync::{NoiseReceiver, NoiseSender, NoiseStream};
use crate::types::Reason;
use ed25519_dalek::SigningKey;
use rand::{rngs::OsRng, RngCore};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

/// Parameters for joining Server Liveness.
pub struct GsLinkConfig {
    pub liveness: SocketAddr,
    /// Regional key bundle (provides Server Liveness signing key + pinned
    /// Noise static transport key).
    pub bundle: KeyBundle,
    pub gs_id: String,
    pub game_addr: String,
    pub gs_key: SigningKey,
    pub instance_pub: [u8; 32],
    pub noise_pub: [u8; 32],
    pub sw_hash: [u8; 32],
    /// Optional TPM 2.0 options (`Some(default_tpm2_options())` for `--tpm2`).
    pub tpm2: Option<Tpm2Options>,
    pub timeout: Duration,
}

/// Default Linux TPM 2.0 options for a game server.
pub fn default_gs_tpm2_options() -> Tpm2Options {
    Tpm2Options {
        tcti: None,
        workdir: std::env::temp_dir().join(format!("fpp-gs-tpm2-{}", std::process::id())),
        pcrs: vec![0, 1, 2, 3, 4, 5, 6, 7, 10],
        ek_intermediates: Vec::new(),
        boot_log: Some(PathBuf::from(BOOT_LOG)),
        ima_log: Some(PathBuf::from(IMA_LOG)),
    }
}

/// Events produced by the Server Liveness link.
#[derive(Clone, Debug)]
pub enum GsLinkEvent {
    /// Verified next SAR in this server's chain (certifies our keys).
    Sar(Vec<u8>),
    /// Signed `RevocationEvent` relayed from Enforcement.
    Revocation(Vec<u8>),
    /// Link closed or SAR chain invalid (`reason`).
    Closed(Reason),
}

#[derive(Debug)]
pub struct GsLinkError(pub String);

impl core::fmt::Display for GsLinkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for GsLinkError {}

/// Live full-duplex control link from a game server to Server Liveness.
/// Runs two tiny std threads (reader + writer) over the split Noise TCP stream.
pub struct GsLink {
    match_id: [u8; 16],
    events: Arc<Mutex<VecDeque<GsLinkEvent>>>,
    checkpoints: Option<mpsc::Sender<Vec<u8>>>,
    closed: Arc<AtomicBool>,
    shutdown_sender: Option<Arc<Mutex<Option<NoiseSender>>>>,
    reader_thread: Option<std::thread::JoinHandle<()>>,
    writer_thread: Option<std::thread::JoinHandle<()>>,
}

impl GsLink {
    /// Join Server Liveness and start streaming SARs, revocations, and checkpoints.
    pub fn connect(cfg: GsLinkConfig) -> Result<Self, GsLinkError> {
        let server_pub = cfg
            .bundle
            .transport_key("liveness")
            .map_err(|e| GsLinkError(format!("key bundle: {e}")))?;
        let keys = cfg.bundle.keyset();

        let tpm = match cfg.tpm2 {
            Some(opts) => Some(Tpm2::open(opts).map_err(|e| GsLinkError(format!("tpm2: {e}")))?),
            None => None,
        };

        let mut stream = NoiseStream::connect(cfg.liveness, &server_pub, None, cfg.timeout)
            .map_err(|e| GsLinkError(format!("connect: {e}")))?;

        stream
            .send(&ChallengeRequest {
                version: CONTROL_VERSION,
                purpose: Purpose::GsJoin,
            })
            .map_err(|e| GsLinkError(format!("ChallengeRequest: {e}")))?;
        let challenge: AttestChallenge = stream
            .recv()
            .map_err(|e| GsLinkError(format!("AttestChallenge: {e}")))?;

        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);
        let now = now_ms();
        let to_sign = join_request_sign_bytes(
            &cfg.gs_id,
            &cfg.sw_hash,
            now,
            &nonce,
            &cfg.instance_pub,
            &cfg.noise_pub,
            &cfg.game_addr,
        );
        let tpm2_ev = match &tpm {
            Some(t) => Some(Box::new(
                t.evidence(&join_quote_nonce(&challenge.nonce, &to_sign))
                    .map_err(|e| GsLinkError(format!("tpm2 evidence: {e}")))?,
            )),
            None => None,
        };
        let req = JoinRequest {
            gs_id: cfg.gs_id,
            sw_hash: cfg.sw_hash,
            t_unix_ms: now,
            nonce,
            ephemeral_pub: cfg.instance_pub,
            noise_static: cfg.noise_pub,
            game_addr: cfg.game_addr,
            sig_gs: ed25519_sign(&cfg.gs_key, &to_sign),
            gs_pub: cfg.gs_key.verifying_key().to_bytes(),
            tpm2: tpm2_ev,
        };
        stream
            .send(&req)
            .map_err(|e| GsLinkError(format!("JoinRequest: {e}")))?;

        if let Some(t) = &tpm {
            let cred: CredentialChallenge = stream
                .recv()
                .map_err(|e| GsLinkError(format!("CredentialChallenge: {e}")))?;
            let secret = t
                .activate(&cred)
                .map_err(|e| GsLinkError(format!("TPM activate: {e}")))?;
            stream
                .send(&CredentialResponse { secret })
                .map_err(|e| GsLinkError(format!("CredentialResponse: {e}")))?;
        }

        let accept: JoinAccept = stream
            .recv()
            .map_err(|e| GsLinkError(format!("JoinAccept: {e}")))?;

        // Streaming phase: clear the admission timeout on the reader.
        stream
            .set_read_timeout(None)
            .map_err(|e| GsLinkError(format!("set timeout: {e}")))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .map_err(|e| GsLinkError(format!("set timeout: {e}")))?;

        let (sender, receiver, _) = stream.split();
        let events = Arc::new(Mutex::new(VecDeque::new()));
        let closed = Arc::new(AtomicBool::new(false));
        let (cp_tx, cp_rx) = mpsc::channel::<Vec<u8>>();
        let shared_sender = Arc::new(Mutex::new(Some(sender)));

        let reader_thread = {
            let events = events.clone();
            let closed = closed.clone();
            let instance = cfg.instance_pub;
            let noise = cfg.noise_pub;
            std::thread::Builder::new()
                .name("fpp-gs-rx".into())
                .spawn(move || {
                    read_loop(receiver, keys, instance, noise, events, closed);
                })
                .map_err(|e| GsLinkError(format!("spawn rx thread: {e}")))?
        };

        let writer_thread = {
            let shared_sender = shared_sender.clone();
            let events = events.clone();
            let closed = closed.clone();
            std::thread::Builder::new()
                .name("fpp-gs-tx".into())
                .spawn(move || {
                    write_loop(shared_sender, cp_rx, events, closed);
                })
                .map_err(|e| GsLinkError(format!("spawn tx thread: {e}")))?
        };

        Ok(Self {
            match_id: accept.session_id,
            events,
            checkpoints: Some(cp_tx),
            closed,
            shutdown_sender: Some(shared_sender),
            reader_thread: Some(reader_thread),
            writer_thread: Some(writer_thread),
        })
    }

    pub fn match_id(&self) -> [u8; 16] {
        self.match_id
    }

    pub fn poll_event(&self) -> Option<GsLinkEvent> {
        self.events.lock().ok()?.pop_front()
    }

    /// Peek at the next event without popping (used by C ABI for `BufferTooSmall`).
    pub fn with_front<R>(&self, f: impl FnOnce(Option<&GsLinkEvent>) -> (R, bool)) -> R {
        let mut q = self.events.lock().expect("gs_link events lock");
        let (res, pop) = f(q.front());
        if pop {
            q.pop_front();
        }
        res
    }

    pub fn submit_checkpoint(&self, checkpoint: Vec<u8>) -> Result<(), GsLinkError> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(GsLinkError("link closed".into()));
        }
        self.checkpoints
            .as_ref()
            .ok_or_else(|| GsLinkError("link closed".into()))?
            .send(checkpoint)
            .map_err(|_| GsLinkError("link writer closed".into()))
    }
}

impl Drop for GsLink {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::SeqCst);
        self.checkpoints.take();
        if let Some(s) = self.shutdown_sender.take() {
            if let Ok(guard) = s.lock() {
                if let Some(sender) = guard.as_ref() {
                    sender.shutdown();
                }
            }
        }
        if let Some(t) = self.writer_thread.take() {
            let _ = t.join();
        }
        if let Some(t) = self.reader_thread.take() {
            let _ = t.join();
        }
    }
}

fn push_closed(
    events: &Arc<Mutex<VecDeque<GsLinkEvent>>>,
    closed: &Arc<AtomicBool>,
    reason: Reason,
) {
    if !closed.swap(true, Ordering::SeqCst) {
        if let Ok(mut q) = events.lock() {
            q.push_back(GsLinkEvent::Closed(reason));
        }
    }
}

fn read_loop(
    mut receiver: NoiseReceiver,
    keys: KeySet,
    instance: [u8; 32],
    noise: [u8; 32],
    events: Arc<Mutex<VecDeque<GsLinkEvent>>>,
    closed: Arc<AtomicBool>,
) {
    let mut chain: Option<SarChain> = None;
    loop {
        let msg: ToGameServer = match receiver.recv_max(MAX_CONTROL_FRAME) {
            Ok(m) => m,
            Err(_) => {
                push_closed(&events, &closed, Reason::SarLapsed);
                break;
            }
        };
        match msg {
            ToGameServer::Revocation(signed) => {
                if let Ok(mut q) = events.lock() {
                    q.push_back(GsLinkEvent::Revocation(signed));
                }
            }
            ToGameServer::Sar(sar) => {
                let now = now_s();
                let verified = match chain.as_mut() {
                    None => SarChain::start(&sar, &keys, now).map(|c| chain = Some(c)),
                    Some(c) => c.update(&sar, &keys, now),
                };
                let ours = chain.as_ref().is_some_and(|c| {
                    c.current().cnf == instance && c.current().noise_static == Some(noise)
                });
                if verified.is_err() || !ours {
                    eprintln!("[fpp gs-link] rejected SAR ({verified:?}, ours: {ours})");
                    push_closed(&events, &closed, Reason::SarLapsed);
                    break;
                }
                if let Ok(mut q) = events.lock() {
                    q.push_back(GsLinkEvent::Sar(sar));
                }
            }
        }
    }
}

fn write_loop(
    shared_sender: Arc<Mutex<Option<NoiseSender>>>,
    rx: mpsc::Receiver<Vec<u8>>,
    events: Arc<Mutex<VecDeque<GsLinkEvent>>>,
    closed: Arc<AtomicBool>,
) {
    while let Ok(checkpoint) = rx.recv() {
        let res = {
            let mut guard = shared_sender.lock().expect("sender lock");
            match guard.as_mut() {
                Some(s) => s.send(&CheckpointSubmit { checkpoint }),
                None => break,
            }
        };
        if let Err(e) = res {
            if !closed.load(Ordering::Relaxed) {
                eprintln!("[fpp gs-link] checkpoint submit failed: {e}");
                push_closed(&events, &closed, Reason::SarLapsed);
            }
            break;
        }
    }
}
