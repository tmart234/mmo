//! A dedicated game server's control link to Server Liveness (feature
//! `gs-link`; stage H5 of docs/anticheat/08): what `gs-sim` does, for C
//! callers. The server joins with its long-term key (and, with `tpm2`, its
//! TPM's evidence), receives its match and a SAR chain certifying its
//! instance key and `fpp_p2p_*` static key, relays Revocation Feed events,
//! and submits one signed Checkpoint per epoch.
//!
//! The link runs on a thread of its own (QUIC needs a runtime); the game
//! polls it from its own loop. Unlike the rest of the SDK this part does
//! network I/O, so it is built only with `--features gs-link` (header
//! guard `FPP_GS_LINK`), keeping players' builds free of it.

use super::{emit, fixed, free, guard, handle, handle_mut, input, FppKeys, FppStatus};
use common::{
    crypto::{join_request_sign_bytes, now_ms},
    framing::{recv_msg, send_msg, send_msg_continue},
    keys::KeyBundle,
    proto::{CheckpointSubmit, CredentialChallenge, CredentialResponse, JoinAccept, JoinRequest},
    tpm::join_quote_nonce,
};
use ed25519_dalek::SigningKey;
use fpp_crypto::KeySet;
use fpp_tokens::SarChain;
use fpp_types::Reason;
use rand::{rngs::OsRng, RngCore};
use std::collections::VecDeque;
use std::ffi::{c_char, CStr};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

/// Load a regional key bundle (`keys/fpp_key_bundle.json`, as `fpp-cell
/// bundle` gathers it) into a key set for the rest of the SDK.
///
/// # Safety
/// `path` a NUL-terminated string; `out` valid for a pointer write.
#[no_mangle]
pub unsafe extern "C" fn fpp_keys_load_bundle(
    path: *const c_char,
    out: *mut *mut FppKeys,
) -> FppStatus {
    guard(|| {
        let path = unsafe { text(path) }?;
        let bundle = KeyBundle::load(path).map_err(|_| FppStatus::InvalidArgument)?;
        unsafe {
            emit(
                out,
                FppKeys {
                    inner: bundle.keyset(),
                },
            )
        }
    })
}

/// # Safety
/// `ptr` NULL or a NUL-terminated string.
unsafe fn text<'a>(ptr: *const c_char) -> Result<&'a str, FppStatus> {
    if ptr.is_null() {
        return Err(FppStatus::NullPointer);
    }
    // SAFETY: non-null and NUL-terminated per the caller contract.
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|_| FppStatus::InvalidArgument)
}

/// What the server joins with.
#[repr(C)]
pub struct FppGsLinkConfig {
    /// Server Liveness, "ip:port".
    pub liveness: *const c_char,
    /// The CA (DER file) Server Liveness's TLS certificate must chain to.
    pub ca_cert: *const c_char,
    /// The regional key bundle (JSON file): SARs and revocation events are
    /// checked under it.
    pub bundle: *const c_char,
    /// A label for this server.
    pub gs_id: *const c_char,
    /// The address players dial, "ip:port" (the Broker hands it out).
    pub game_addr: *const c_char,
    /// 32-byte seed of the server's long-term Ed25519 key: Server Liveness
    /// knows the server by it.
    pub gs_key_seed: *const u8,
    /// 32-byte Ed25519 key that signs this run's Checkpoints (an
    /// `FppSigner`'s public key); every SAR certifies it.
    pub instance_public_key: *const u8,
    /// 32-byte static X25519 key of the server's `fpp_p2p_host`
    /// (`fpp_p2p_public_key`); every SAR binds it, and players dial it.
    pub noise_public_key: *const u8,
    /// 32-byte SHA-256 of the server's executable, or NULL to hash the
    /// running one. With `tpm2`, Server Liveness uses the kernel's
    /// measurement instead.
    pub sw_hash: *const u8,
    /// 1: prove the server's boot and build with a TPM 2.0 through
    /// tpm2-tools (as `gs-sim --tpm2`).
    pub tpm2: u8,
    /// Give up joining after this long (0: 10 s).
    pub timeout_ms: u32,
}

/// `FppGsEvent.kind`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FppGsEventKind {
    /// data = the next SAR, already checked: it continues the chain and
    /// certifies this server's keys. Send it to every player
    /// (`fpp_control_sar_update`).
    Sar = 1,
    /// data = a signed RevocationEvent (`fpp_admission_revocation`).
    Revocation = 2,
    /// The link is gone (`reason`): the server is no longer blessed. End
    /// the match; players drop on their own once its SARs stop.
    Closed = 3,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FppGsEvent {
    pub kind: FppGsEventKind,
    /// `fpp_types::Reason` code (Closed).
    pub reason: u16,
    pub data_len: usize,
}

enum Event {
    Sar(Vec<u8>),
    Revocation(Vec<u8>),
    Closed(Reason),
}

/// A server's link to Server Liveness.
pub struct FppGsLink {
    match_id: [u8; 16],
    events: Arc<Mutex<VecDeque<Event>>>,
    checkpoints: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for FppGsLink {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

struct Join {
    liveness: SocketAddr,
    ca_der: Vec<u8>,
    keys: KeySet,
    gs_id: String,
    game_addr: String,
    gs_key: SigningKey,
    instance: [u8; 32],
    noise: [u8; 32],
    sw_hash: [u8; 32],
    tpm2: bool,
}

/// Join Server Liveness and start the link. Blocks until joined (or
/// `timeout_ms`). `FPP_STATUS_GS_LINK` if it cannot reach or join Server
/// Liveness (it logs why to stderr).
///
/// # Safety
/// `config` valid, its strings NUL-terminated and its keys valid for 32
/// bytes; `out` valid for a pointer write.
#[no_mangle]
pub unsafe extern "C" fn fpp_gs_link_connect(
    config: *const FppGsLinkConfig,
    out: *mut *mut FppGsLink,
) -> FppStatus {
    guard(|| {
        let c = unsafe { handle(config) }?;
        let liveness: SocketAddr = unsafe { text(c.liveness) }?
            .parse()
            .map_err(|_| FppStatus::InvalidArgument)?;
        let game_addr = unsafe { text(c.game_addr) }?.to_string();
        game_addr
            .parse::<SocketAddr>()
            .map_err(|_| FppStatus::InvalidArgument)?;
        let ca_der =
            common::pki::load_ca(unsafe { text(c.ca_cert) }?).map_err(|e| link_error("CA", e))?;
        let keys = KeyBundle::load(unsafe { text(c.bundle) }?)
            .map_err(|e| link_error("key bundle", e))?
            .keyset();
        let sw_hash = if c.sw_hash.is_null() {
            let exe = std::env::current_exe().map_err(|_| FppStatus::GsLink)?;
            common::crypto::file_sha256(&exe).map_err(|_| FppStatus::GsLink)?
        } else {
            unsafe { fixed(c.sw_hash) }?
        };
        let join = Join {
            liveness,
            ca_der,
            keys,
            gs_id: unsafe { text(c.gs_id) }?.to_string(),
            game_addr,
            gs_key: SigningKey::from_bytes(&unsafe { fixed(c.gs_key_seed) }?),
            instance: unsafe { fixed(c.instance_public_key) }?,
            noise: unsafe { fixed(c.noise_public_key) }?,
            sw_hash,
            tpm2: c.tpm2 != 0,
        };
        let timeout = Duration::from_millis(match c.timeout_ms {
            0 => 10_000,
            t => t.into(),
        });
        let link = start(join, timeout)?;
        unsafe { emit(out, link) }
    })
}

fn link_error(what: &str, e: impl std::fmt::Display) -> FppStatus {
    eprintln!("[fpp gs-link] {what}: {e:#}");
    FppStatus::GsLink
}

fn start(join: Join, timeout: Duration) -> Result<FppGsLink, FppStatus> {
    let events = Arc::new(Mutex::new(VecDeque::new()));
    let (cp_tx, cp_rx) = tokio::sync::mpsc::unbounded_channel();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let (joined_tx, joined_rx) = mpsc::channel();
    let thread = {
        let events = events.clone();
        std::thread::Builder::new()
            .name("fpp-gs-link".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        let _ = joined_tx.send(Err(link_error("runtime", e)));
                        return;
                    }
                };
                rt.block_on(run(join, events, cp_rx, stop_rx, joined_tx));
            })
            .map_err(|e| link_error("thread", e))?
    };
    let mut link = FppGsLink {
        match_id: [0; 16],
        events,
        checkpoints: cp_tx,
        stop: Some(stop_tx),
        thread: Some(thread),
    };
    match joined_rx.recv_timeout(timeout) {
        Ok(Ok(match_id)) => {
            link.match_id = match_id;
            Ok(link)
        }
        Ok(Err(status)) => Err(status),
        Err(_) => Err(link_error("join", "timed out")),
    }
}

async fn run(
    join: Join,
    events: Arc<Mutex<VecDeque<Event>>>,
    mut checkpoints: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    mut stop: tokio::sync::oneshot::Receiver<()>,
    joined: mpsc::Sender<Result<[u8; 16], FppStatus>>,
) {
    let push = |e: Event| events.lock().expect("events").push_back(e);
    let conn = match open(&join).await {
        Ok((conn, match_id)) => {
            let _ = joined.send(Ok(match_id));
            conn
        }
        Err(e) => {
            let _ = joined.send(Err(link_error("join", e)));
            return;
        }
    };
    let mut chain: Option<SarChain> = None;
    let reason = loop {
        tokio::select! {
            _ = &mut stop => {
                conn.close(0u32.into(), b"done");
                return;
            }
            Some(checkpoint) = checkpoints.recv() => {
                let sent = async {
                    let mut uni = conn.open_uni().await?;
                    send_msg(&mut uni, &CheckpointSubmit { checkpoint }).await
                };
                if let Err(e) = sent.await {
                    eprintln!("[fpp gs-link] checkpoint submit failed: {e:#}");
                    break Reason::SarLapsed;
                }
            }
            uni = conn.accept_uni() => {
                let Ok(mut uni) = uni else {
                    break Reason::SarLapsed;
                };
                let Ok(msg) = recv_msg::<common::proto::ToGameServer>(&mut uni).await else {
                    continue;
                };
                match msg {
                    common::proto::ToGameServer::Revocation(signed) => push(Event::Revocation(signed)),
                    common::proto::ToGameServer::Sar(sar) => {
                        let now = now_ms() / 1000;
                        let verified = match chain.as_mut() {
                            None => SarChain::start(&sar, &join.keys, now).map(|c| {
                                chain = Some(c);
                            }),
                            Some(c) => c.update(&sar, &join.keys, now),
                        };
                        // (a SAR that does not certify this server's own keys
                        // is no blessing)
                        let ours = chain.as_ref().is_some_and(|c| {
                            c.current().cnf == join.instance
                                && c.current().noise_static == Some(join.noise)
                        });
                        if verified.is_err() || !ours {
                            eprintln!("[fpp gs-link] rejected a SAR ({verified:?}, ours: {ours})");
                            break Reason::SarLapsed;
                        }
                        push(Event::Sar(sar));
                    }
                }
            }
        }
    };
    conn.close(0u32.into(), b"lapsed");
    push(Event::Closed(reason));
    // (wait to be dropped)
    let _ = stop.await;
}

/// The join of `gs-sim`: challenge, JoinRequest (with TPM evidence and
/// credential activation if asked), JoinAccept.
async fn open(join: &Join) -> anyhow::Result<(quinn::Connection, [u8; 16])> {
    let tpm2 = if join.tpm2 {
        Some(common::tpm2::Tpm2::open(common::tpm2::Tpm2Options {
            tcti: None,
            workdir: std::env::temp_dir().join(format!("fpp-gs-tpm2-{}", std::process::id())),
            pcrs: vec![0, 1, 2, 3, 4, 5, 6, 7, 10],
            ek_intermediates: Vec::new(),
            boot_log: Some(PathBuf::from(common::tpm2::BOOT_LOG)),
            ima_log: Some(PathBuf::from(common::tpm2::IMA_LOG)),
        })?)
    } else {
        None
    };
    let opened =
        common::admission::request_challenge(&join.ca_der, join.liveness, "liveness").await?;
    let (conn, mut send, mut recv) = (opened.conn, opened.send, opened.recv);
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    let now = now_ms();
    let to_sign = join_request_sign_bytes(
        &join.gs_id,
        &join.sw_hash,
        now,
        &nonce,
        &join.instance,
        &join.noise,
        &join.game_addr,
    );
    let request = JoinRequest {
        gs_id: join.gs_id.clone(),
        sw_hash: join.sw_hash,
        t_unix_ms: now,
        nonce,
        ephemeral_pub: join.instance,
        noise_static: join.noise,
        game_addr: join.game_addr.clone(),
        sig_gs: common::crypto::sign(&join.gs_key, &to_sign).to_vec(),
        gs_pub: join.gs_key.verifying_key().to_bytes(),
        tpm2: match &tpm2 {
            Some(t) => Some(t.evidence(&join_quote_nonce(&opened.challenge, &to_sign))?),
            None => None,
        },
    };
    if let Some(t) = &tpm2 {
        send_msg_continue(&mut send, &request).await?;
        let credential: CredentialChallenge = recv_msg(&mut recv).await?;
        let secret = t.activate(&credential)?;
        send_msg(&mut send, &CredentialResponse { secret }).await?;
    } else {
        send_msg(&mut send, &request).await?;
    }
    let accept: JoinAccept = recv_msg(&mut recv).await?;
    Ok((conn, accept.session_id))
}

/// The match Server Liveness gave this server: SATs name it, and the
/// server's Checkpoints must (`fpp_checkpoint_begin`).
///
/// # Safety
/// `link` a live handle; `out` valid for 16 bytes.
#[no_mangle]
pub unsafe extern "C" fn fpp_gs_link_match_id(link: *const FppGsLink, out: *mut u8) -> FppStatus {
    guard(|| {
        let l = unsafe { handle(link) }?;
        unsafe { super::write_fixed(out, &l.match_id) }
    })
}

/// Next event, or `FPP_STATUS_EMPTY`. Its bytes go to `(data, cap)`; if
/// they do not fit the event stays queued and `FPP_STATUS_BUFFER_TOO_SMALL`
/// is returned with `event->data_len` set.
///
/// # Safety
/// `link` a live handle; `event` valid for a write; `data` NULL or valid
/// for `cap` bytes.
#[no_mangle]
pub unsafe extern "C" fn fpp_gs_link_poll(
    link: *mut FppGsLink,
    event: *mut FppGsEvent,
    data: *mut u8,
    cap: usize,
) -> FppStatus {
    guard(|| {
        let l = unsafe { handle_mut(link) }?;
        let event = unsafe { event.as_mut() }.ok_or(FppStatus::NullPointer)?;
        let mut q = l.events.lock().map_err(|_| FppStatus::Internal)?;
        let Some(front) = q.front() else {
            return Err(FppStatus::Empty);
        };
        let (kind, reason, bytes): (_, u16, &[u8]) = match front {
            Event::Sar(b) => (FppGsEventKind::Sar, 0, b),
            Event::Revocation(b) => (FppGsEventKind::Revocation, 0, b),
            Event::Closed(r) => (FppGsEventKind::Closed, *r as u16, &[]),
        };
        *event = FppGsEvent {
            kind,
            reason,
            data_len: bytes.len(),
        };
        if !bytes.is_empty() {
            if data.is_null() || cap < bytes.len() {
                return Err(FppStatus::BufferTooSmall);
            }
            // SAFETY: `data` is valid for `cap >= bytes.len()` bytes.
            unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), data, bytes.len()) };
        }
        q.pop_front();
        Ok(())
    })
}

/// Submit a signed Checkpoint (one per epoch, from epoch 0, each `prev`
/// the last one's digest). Server Liveness revokes a server whose chain
/// breaks or that goes quiet for 30 s, so a match sends one even in its
/// lobby.
///
/// # Safety
/// `link` a live handle; `checkpoint` valid for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn fpp_gs_link_submit_checkpoint(
    link: *mut FppGsLink,
    checkpoint: *const u8,
    len: usize,
) -> FppStatus {
    guard(|| {
        let l = unsafe { handle_mut(link) }?;
        let checkpoint = unsafe { input(checkpoint, len) }?.to_vec();
        l.checkpoints
            .send(checkpoint)
            .map_err(|_| FppStatus::GsLink)
    })
}

/// Close the link (leave Server Liveness) and free it.
///
/// # Safety
/// `link` NULL or a live handle, not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn fpp_gs_link_free(link: *mut FppGsLink) {
    unsafe { free(link) }
}
