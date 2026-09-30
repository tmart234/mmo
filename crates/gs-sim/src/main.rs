//! Prototype game server: joins Server Liveness, keeps its SAR chain,
//! submits one signed Checkpoint per epoch, and serves one match to clients
//! over fpp-session (see `game.rs`).
use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use common::{
    crypto::{file_sha256, join_request_sign_bytes, now_ms, sign},
    framing::{recv_msg, send_msg, send_msg_continue},
    keys::KeyBundle,
    proto::{
        CheckpointSubmit, CredentialChallenge, CredentialResponse, JoinAccept, JoinRequest,
        SarIssue, Sig,
    },
    tpm::join_quote_nonce,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use fpp_crypto::Ed25519Signer;
use fpp_session::{Host, HostConfig, StaticKeypair};
use fpp_tokens::SarChain;
use fpp_types::{BuildId, DeviceTier, MatchId};
use gs_sim::{
    game::{self, Match, MatchConfig},
    ledger::Ledger,
};
use rand::{rngs::OsRng, RngCore};
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};
use tokio::sync::{mpsc, watch};

#[derive(Parser, Debug)]
struct Opts {
    /// Server Liveness address (ip:port).
    #[arg(long, default_value = "127.0.0.1:4444")]
    liveness: SocketAddr,

    /// UDP address of the game port clients join (fpp-session).
    #[arg(long, default_value = "127.0.0.1:50000")]
    game_addr: String,

    /// Serve for `--test-secs` seconds, then exit.
    #[arg(long)]
    test_once: bool,
    #[arg(long, default_value_t = 15)]
    test_secs: u64,

    /// Logical GS ID label
    #[arg(long, default_value = "gs-sim-local")]
    gs_id: String,

    /// Paths to GS *long-term* keypair
    #[arg(long, default_value = "keys/gs_ed25519.pk8")]
    gs_sk: String,
    #[arg(long, default_value = "keys/gs_ed25519.pub")]
    gs_pk: String,

    /// A real TPM 2.0, through tpm2-tools (`TPM2TOOLS_TCTI`; default the
    /// kernel's resource manager): the EK certificate, a quote over Server Liveness's
    /// challenge, the boot and IMA logs, and credential activation. Server Liveness
    /// then knows this binary's build from the kernel's measurement, not
    /// from the binary (F06).
    #[arg(long)]
    tpm2: bool,
    /// PCRs to quote with `--tpm2`.
    #[arg(long, value_delimiter = ',', default_value = "0,1,2,3,4,5,6,7,10")]
    tpm2_pcrs: Vec<u8>,
    /// Intermediate CA certificates (PEM) between the EK certificate and
    /// the manufacturer's root, if the TPM does not store them.
    #[arg(long)]
    tpm2_ek_intermediates: Option<PathBuf>,
    /// The firmware's measured-boot log (none if missing).
    #[arg(long, default_value = gs_sim::tpm2::BOOT_LOG)]
    boot_log: PathBuf,
    /// The kernel's IMA log (none if missing).
    #[arg(long, default_value = gs_sim::tpm2::IMA_LOG)]
    ima_log: PathBuf,

    /// Key bundle: Verifier, Broker and Server Liveness keys.
    #[arg(long, default_value = common::keys::DEFAULT_BUNDLE)]
    bundle: String,

    /// CA certificate (DER) Server Liveness's TLS certificate must chain to.
    #[arg(long, default_value = common::pki::DEFAULT_CA_CERT)]
    ca_cert: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Opts::parse();

    let (gs_sk_long, gs_pk_long) = load_or_make_keys(&opts.gs_sk, &opts.gs_pk)?;
    let ca_der = common::pki::load_ca(&opts.ca_cert)?;
    let bundle = KeyBundle::load(&opts.bundle)?;
    let keyset = bundle.keyset();

    // Instance key (signs Checkpoints; certified by SARs) and the game
    // port's static key, both fresh per run.
    let instance_sk = SigningKey::generate(&mut OsRng);
    let instance_pub = instance_sk.verifying_key().to_bytes();
    let noise = StaticKeypair::generate();

    let exe = std::env::current_exe()?;
    let sw_hash = file_sha256(&exe)?;

    let tpm2 = if opts.tpm2 {
        let intermediates = match &opts.tpm2_ek_intermediates {
            Some(path) => {
                let pem = std::fs::read_to_string(path).context("read --tpm2-ek-intermediates")?;
                attest_core::x509::pem_certificates(&pem)
                    .map_err(|e| anyhow!("--tpm2-ek-intermediates: {e}"))?
            }
            None => Vec::new(),
        };
        let t = gs_sim::tpm2::Tpm2::open(gs_sim::tpm2::Tpm2Options {
            tcti: None,
            workdir: std::env::temp_dir().join(format!("gs-sim-tpm2-{}", std::process::id())),
            pcrs: opts.tpm2_pcrs.clone(),
            ek_intermediates: intermediates,
            boot_log: Some(opts.boot_log.clone()),
            ima_log: Some(opts.ima_log.clone()),
        })
        .context("TPM 2.0 (--tpm2)")?;
        println!("[GS] TPM 2.0: EK certificate and attestation key ready");
        Some(t)
    } else {
        None
    };

    // Bind the game port first: we advertise it in the JoinRequest.
    let game_addr: SocketAddr = opts.game_addr.parse().context("bad --game-addr")?;
    let socket = tokio::net::UdpSocket::bind(game_addr)
        .await
        .with_context(|| format!("bind game port {game_addr}"))?;

    // ---- Control link to Server Liveness (QUIC, pinned CA). Its
    //      challenge comes first, so the quote covers a nonce it chose (F04).
    let opened = common::admission::request_challenge(&ca_der, opts.liveness, "liveness").await?;
    let (conn, mut jsend, mut jrecv) = (opened.conn, opened.send, opened.recv);
    println!("[GS] connected to Server Liveness at {}", opts.liveness);

    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    let now = now_ms();
    let to_sign = join_request_sign_bytes(
        &opts.gs_id,
        &sw_hash,
        now,
        &nonce,
        &instance_pub,
        &noise.public,
        &opts.game_addr,
    );
    let sig_gs: Sig = sign(&gs_sk_long, &to_sign).to_vec();
    let jr = JoinRequest {
        gs_id: opts.gs_id.clone(),
        sw_hash,
        t_unix_ms: now,
        nonce,
        ephemeral_pub: instance_pub,
        noise_static: noise.public,
        game_addr: opts.game_addr.clone(),
        sig_gs,
        gs_pub: gs_pk_long.to_bytes(),
        tpm2: match &tpm2 {
            Some(t) => Some(
                t.evidence(&join_quote_nonce(&opened.challenge, &to_sign))
                    .context("TPM 2.0 evidence")?,
            ),
            None => None,
        },
    };
    if let Some(t) = &tpm2 {
        // credential activation: a secret only this TPM opens
        send_msg_continue(&mut jsend, &jr).await?;
        let credential: CredentialChallenge = recv_msg(&mut jrecv)
            .await
            .context("recv CredentialChallenge (TPM evidence refused?)")?;
        let secret = t.activate(&credential)?;
        send_msg(&mut jsend, &CredentialResponse { secret }).await?;
    } else {
        send_msg(&mut jsend, &jr).await?;
    }
    // (over TLS to the pinned CA and name: no one else could have sent this
    // JoinAccept; what blesses us is the SAR chain below)
    let ja: JoinAccept = recv_msg(&mut jrecv).await?;
    let session_id = ja.session_id;
    println!("[GS] joined; match {}..", hex::encode(&session_id[..4]));

    // ---- SAR chain from Server Liveness: verified, and must certify our own keys.
    let (sar_tx, sar_rx) = watch::channel::<Option<Vec<u8>>>(None);
    {
        let conn = conn.clone();
        let keyset = keyset.clone();
        tokio::spawn(async move {
            let mut chain: Option<SarChain> = None;
            loop {
                let Ok(mut uni) = conn.accept_uni().await else {
                    break;
                };
                let Ok(issue) = recv_msg::<SarIssue>(&mut uni).await else {
                    continue;
                };
                let now = now_ms() / 1000;
                let verified = match chain.as_mut() {
                    None => SarChain::start(&issue.sar, &keyset, now).map(|c| {
                        chain = Some(c);
                    }),
                    Some(c) => c.update(&issue.sar, &keyset, now),
                };
                let ours = chain.as_ref().is_some_and(|c| {
                    c.current().cnf == instance_pub
                        && c.current().noise_static == Some(noise.public)
                });
                if let Err(e) = verified.map_err(|e| e.to_string()).and_then(|_| {
                    ours.then_some(())
                        .ok_or("SAR does not certify our keys".to_string())
                }) {
                    eprintln!("[GS] rejected SAR: {e}; stopping");
                    break;
                }
                if sar_tx.send(Some(issue.sar)).is_err() {
                    break;
                }
            }
            // Dropping `sar_tx` tells the match it lost its blessing.
        });
    }

    // ---- Checkpoints to Server Liveness.
    let (cp_tx, mut cp_rx) = mpsc::unbounded_channel::<(u32, Vec<u8>)>();
    {
        let conn = conn.clone();
        tokio::spawn(async move {
            while let Some((_epoch, checkpoint)) = cp_rx.recv().await {
                let submit = CheckpointSubmit { checkpoint };
                let sent = async {
                    let mut uni = conn.open_uni().await?;
                    send_msg(&mut uni, &submit).await
                };
                if let Err(e) = sent.await {
                    eprintln!("[GS] checkpoint submit failed: {e:#}");
                    break;
                }
            }
        });
    }

    // ---- The match.
    let mut host_cfg = HostConfig::new(noise);
    host_cfg.max_peers = 64;
    let m = Match::new(
        MatchConfig {
            match_id: MatchId(session_id),
            instance: Ed25519Signer::new(instance_sk),
            build_id: BuildId(sw_hash),
            keys: keyset,
            min_tier: DeviceTier::D0Unknown,
            sar_grace_ms: game::SAR_GRACE_MS,
        },
        Host::new(host_cfg),
    );
    let ledger = Ledger::open_for_session(&hex::encode(&session_id[..2])).ok();
    let stop = Arc::new(AtomicBool::new(false));
    println!("[GS] game port (fpp-session/UDP) on {game_addr}");
    let game_task = tokio::spawn(game::run(socket, m, sar_rx, cp_tx, ledger, stop.clone()));

    if opts.test_once {
        tokio::time::sleep(Duration::from_secs(opts.test_secs)).await;
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    game_task.await.map_err(|e| anyhow!("game task: {e}"))??;
    conn.close(0u32.into(), b"done");
    println!("[GS] match over.");
    if !opts.test_once {
        bail!("match ended: SAR chain lapsed");
    }
    Ok(())
}

/// Load GS long-term Ed25519 keypair from disk or create dev keys.
fn load_or_make_keys(sk_path: &str, pk_path: &str) -> Result<(SigningKey, VerifyingKey)> {
    let skp = PathBuf::from(sk_path);
    let pkp = PathBuf::from(pk_path);

    if skp.exists() && pkp.exists() {
        let sk_bytes = std::fs::read(&skp).context("read gs_sk")?;
        let pk_bytes = std::fs::read(&pkp).context("read gs_pk")?;
        let sk = SigningKey::from_bytes(
            &sk_bytes
                .try_into()
                .map_err(|_| anyhow!("sk length != 32"))?,
        );
        let pk = VerifyingKey::from_bytes(
            &pk_bytes
                .try_into()
                .map_err(|_| anyhow!("pk length != 32"))?,
        )?;
        Ok((sk, pk))
    } else {
        std::fs::create_dir_all("keys").context("mkdir keys")?;
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key();
        std::fs::write(&skp, sk.to_bytes()).context("write gs_sk")?;
        std::fs::write(&pkp, pk.to_bytes()).context("write gs_pk")?;
        println!(
            "[GS] generated dev keypair at {}, {}",
            skp.display(),
            pkp.display()
        );
        Ok((sk, pk))
    }
}
