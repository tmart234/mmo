//! `fppd` — Unified Fair-Play Protocol authority daemon and CLI.
//!
//! Subcommands (zero-dep CLI parser, no clap/proc-macros):
//!   fppd init     [--dir cell] [--bundle keys/fpp_key_bundle.json]
//!                 [--policy FILE] [--domain DOMAIN]
//!   fppd serve    [--dir cell] [--bundle keys/fpp_key_bundle.json] [--bind 127.0.0.1:4444]
//!                 [--policy FILE] [--domain DOMAIN] [--region REGION] [--policy-ver N]
//!                 [--max-slots N] [--queue NAME:TIER]... [--sar-interval-s N] [--sar-ttl-s N]
//!                 [--tpm-ek-roots PEM] [--build-registry FILE] [--gs-program PATH]
//!                 [--require-secure-boot] [--client-builds FILE] [--no-witness]
//!                 [--witness-interval-s 1]
//!   fppd role     witness [--dir cell] [--log 127.0.0.1:4444] [--bundle ...] [--interval-s 1]
//!   fppd enforce  [--dir cell] [--authority 127.0.0.1:4444] [--bundle ...]
//!                 <kick|ban-device|ban-account|ban-build|revoke-instance> <hex-id>
//!                 [--note TEXT] [--duration-s N] [--region R] [--queue Q]
//!   fppd evidence [--dir cell] [--authority 127.0.0.1:4444] [--bundle ...]
//!                 <list <match-hex> | get <digest-hex>>
//!   fppd audit    <bundle.fppb>...
//!   fppd ticket   [--authority 127.0.0.1:4444] [--bundle keys/fpp_key_bundle.json]
//!                 [--queue open] [--client-build HEX | --client-binary PATH]
//!                 [--wait-secs 30] [--out ticket.fpp]

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::SigningKey;
use fpp::audit;
use fpp::bundle::{KeyBundle, DEFAULT_BUNDLE};
use fpp::control::{
    evidence_request_sign_bytes, match_request_sign_bytes, EvidenceAnswer, EvidenceRequest,
    MatchAnswer, MatchRequest, Purpose, MAX_CONTROL_FRAME,
};
use fpp::crypto::{file_sha256, now_s, Ed25519Signer, SessionSigner, Signer};
use fpp::log::Witness;
use fpp::tokens::{verify_ar, verify_sat};
use fpp::types::Reason;
use fpp::wire::{Action, Scope, SubjectKind};
use fpp_attest::tpm::Registry;
use fppd::keys::{self, CellKeys};
use fppd::liveness::LivenessConfig;
use fppd::policy::AuthorityPolicy;
use fppd::revocation::Order;
use fppd::verifier::{ClientAttestation, ClientBuilds};
use fppd::{
    external_witness_round, open_control, rpc_enforce, rpc_evidence_get, rpc_evidence_list,
    Authority,
};
use rand::RngCore;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;
use tokio::net::TcpListener;

fn usage() -> &'static str {
    "usage: fppd <init|serve|role|enforce|evidence|audit|ticket> [options]"
}

struct Args {
    items: Vec<String>,
    pos: usize,
}

impl Args {
    fn new(items: Vec<String>) -> Self {
        Self { items, pos: 0 }
    }

    fn next(&mut self) -> Option<String> {
        if self.pos < self.items.len() {
            let s = self.items[self.pos].clone();
            self.pos += 1;
            Some(s)
        } else {
            None
        }
    }

    fn value(&mut self, flag: &str) -> Result<String> {
        self.next()
            .ok_or_else(|| anyhow!("{flag} requires a value"))
    }
}

fn main() -> ExitCode {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.is_empty() || matches!(raw[0].as_str(), "-h" | "--help" | "help") {
        eprintln!("{}", usage());
        return ExitCode::from(2);
    }
    if raw[0] == "audit" {
        return run_audit(&raw[1..]);
    }
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("fppd: runtime: {e}");
            return ExitCode::from(1);
        }
    };
    match rt.block_on(dispatch(Args::new(raw))) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("fppd: {e:#}");
            ExitCode::from(1)
        }
    }
}

async fn dispatch(mut args: Args) -> Result<()> {
    match args.next().as_deref() {
        Some("init") => cmd_init(args),
        Some("serve") => cmd_serve(args).await,
        Some("role") => cmd_role(args).await,
        Some("enforce") => cmd_enforce(args).await,
        Some("evidence") => cmd_evidence(args).await,
        Some("ticket") => cmd_ticket(args).await,
        _ => bail!("{}", usage()),
    }
}

fn cmd_init(mut args: Args) -> Result<()> {
    let mut dir = PathBuf::from("cell");
    let mut bundle = PathBuf::from(DEFAULT_BUNDLE);
    let mut policy = AuthorityPolicy::default();
    let mut domain_override: Option<String> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--dir" => dir = PathBuf::from(args.value("--dir")?),
            "--bundle" => bundle = PathBuf::from(args.value("--bundle")?),
            "--policy" => {
                let p = PathBuf::from(args.value("--policy")?);
                let text =
                    std::fs::read_to_string(&p).with_context(|| format!("read {}", p.display()))?;
                policy = AuthorityPolicy::parse(&text)?;
            }
            "--domain" => domain_override = Some(args.value("--domain")?),
            other => bail!("init: unknown flag {other}"),
        }
    }
    if let Some(d) = domain_override {
        policy.domain = d;
    }
    policy.validate()?;
    let keys = CellKeys::open(&dir)?;
    keys.bundle_for(&policy)
        .save(&bundle)
        .map_err(|e| anyhow!("save bundle: {e}"))?;
    println!(
        "[fppd] initialized isolated role keys for {} in {} and wrote {}",
        policy.domain,
        dir.display(),
        bundle.display()
    );
    Ok(())
}

async fn cmd_serve(mut args: Args) -> Result<()> {
    let mut dir = PathBuf::from("cell");
    let mut bundle = PathBuf::from(DEFAULT_BUNDLE);
    let mut bind: SocketAddr = "127.0.0.1:4444".parse()?;
    let mut policy = AuthorityPolicy::default();
    let mut policy_file: Option<PathBuf> = None;
    let mut domain_override: Option<String> = None;
    let mut region_override: Option<String> = None;
    let mut policy_ver_override: Option<u64> = None;
    let mut max_slots_override: Option<u16> = None;
    let mut sar_interval_override: Option<u64> = None;
    let mut sar_ttl_override: Option<u64> = None;
    let mut extra_queues: Vec<(String, fpp::types::DeviceTier)> = Vec::new();
    let mut ek_roots: Option<PathBuf> = None;
    let mut build_registry: Option<PathBuf> = None;
    let mut client_builds: Option<PathBuf> = None;
    let mut gs_program_override: Option<String> = None;
    let mut require_secure_boot = false;
    let mut no_witness = false;
    let mut witness_interval_s = 1u64;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--dir" => dir = PathBuf::from(args.value("--dir")?),
            "--bundle" => bundle = PathBuf::from(args.value("--bundle")?),
            "--bind" => bind = args.value("--bind")?.parse()?,
            "--policy" => policy_file = Some(PathBuf::from(args.value("--policy")?)),
            "--domain" => domain_override = Some(args.value("--domain")?),
            "--region" => region_override = Some(args.value("--region")?),
            "--policy-ver" => policy_ver_override = Some(args.value("--policy-ver")?.parse()?),
            "--max-slots" => max_slots_override = Some(args.value("--max-slots")?.parse()?),
            "--sar-interval-s" => {
                sar_interval_override = Some(args.value("--sar-interval-s")?.parse()?)
            }
            "--sar-ttl-s" => sar_ttl_override = Some(args.value("--sar-ttl-s")?.parse()?),
            "--queue" => {
                extra_queues.push(AuthorityPolicy::parse_queue_spec(&args.value("--queue")?)?)
            }
            "--tpm-ek-roots" => ek_roots = Some(PathBuf::from(args.value("--tpm-ek-roots")?)),
            "--build-registry" => {
                build_registry = Some(PathBuf::from(args.value("--build-registry")?))
            }
            "--client-builds" => {
                client_builds = Some(PathBuf::from(args.value("--client-builds")?))
            }
            "--gs-program" => gs_program_override = Some(args.value("--gs-program")?),
            "--require-secure-boot" => require_secure_boot = true,
            "--no-witness" => no_witness = true,
            "--witness-interval-s" => {
                witness_interval_s = args.value("--witness-interval-s")?.parse()?
            }
            other => bail!("serve: unknown flag {other}"),
        }
    }

    if let Some(p) = &policy_file {
        let text = std::fs::read_to_string(p).with_context(|| format!("read {}", p.display()))?;
        policy = AuthorityPolicy::parse(&text)?;
    }
    if let Some(d) = domain_override {
        policy.domain = d;
    }
    if let Some(r) = region_override {
        policy.region = r;
    }
    if let Some(v) = policy_ver_override {
        policy.policy_ver = v;
    }
    if let Some(n) = max_slots_override {
        policy.max_slots = n;
    }
    if let Some(s) = sar_interval_override {
        policy.sar_interval_s = s.max(1);
    }
    if let Some(s) = sar_ttl_override {
        policy.sar_ttl_s = s.max(2);
    }
    if let Some(g) = gs_program_override {
        policy.gs_program_path = g;
    }
    for (name, tier) in extra_queues {
        policy.queues.insert(name, tier);
    }

    let mut liveness_cfg = LivenessConfig {
        require_secure_boot,
        ..LivenessConfig::default()
    };
    let mut attestation = ClientAttestation::default();

    if let Some(p) = &ek_roots {
        let pem = std::fs::read_to_string(p).with_context(|| format!("read {}", p.display()))?;
        let roots =
            fpp_attest::x509::pem_certificates(&pem).map_err(|e| anyhow!("--tpm-ek-roots: {e}"))?;
        liveness_cfg.tpm_ek_roots = roots.clone();
        attestation.tpm_ek_roots = roots;
    }
    if let Some(p) = &build_registry {
        let text = std::fs::read_to_string(p).with_context(|| format!("read {}", p.display()))?;
        let reg = Registry::parse(&text).map_err(|e| anyhow!("--build-registry: {e}"))?;
        for (hash, label) in reg.builds {
            let h: [u8; 32] = hash
                .try_into()
                .map_err(|_| anyhow!("registry hash not 32 bytes"))?;
            liveness_cfg.build_registry.insert(h, label);
        }
    }
    if let Some(p) = &client_builds {
        let text = std::fs::read_to_string(p).with_context(|| format!("read {}", p.display()))?;
        attestation.client_builds = ClientBuilds::parse(&text)?;
    }

    let domain = policy.domain.clone();
    let region = policy.region.clone();
    let witness_interval = (!no_witness).then(|| Duration::from_secs(witness_interval_s.max(1)));
    let running = Authority::open_with_policy(
        &dir,
        Some(&bundle),
        policy,
        liveness_cfg,
        attestation,
        witness_interval,
    )?;
    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("bind {bind}"))?;
    let actual = listener.local_addr()?;
    println!(
        "[fppd] ready on {actual} (domain: {domain}, region: {region}, bundle: {}, transport: {}..)",
        bundle.display(),
        hex::encode(&running.bundle.transport_pub[..6])
    );

    let auth = running.authority.clone();
    tokio::select! {
        _ = auth.serve(listener) => {}
        _ = tokio::signal::ctrl_c() => {
            println!("[fppd] stopping");
        }
    }
    drop(running);
    Ok(())
}

async fn cmd_role(mut args: Args) -> Result<()> {
    match args.next().as_deref() {
        Some("witness") => {
            let mut dir = PathBuf::from("cell");
            let mut log_addr: SocketAddr = "127.0.0.1:4444".parse()?;
            let mut bundle_path = PathBuf::from(DEFAULT_BUNDLE);
            let mut interval_s = 1u64;
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--dir" => dir = PathBuf::from(args.value("--dir")?),
                    "--log" => log_addr = args.value("--log")?.parse()?,
                    "--bundle" => bundle_path = PathBuf::from(args.value("--bundle")?),
                    "--interval-s" => interval_s = args.value("--interval-s")?.parse()?,
                    other => bail!("role witness: unknown flag {other}"),
                }
            }
            let bundle = KeyBundle::load(&bundle_path).map_err(|e| anyhow!("{e}"))?;
            let server_pub = bundle.transport_key("log").map_err(|e| anyhow!("{e}"))?;
            let log_keys = bundle
                .log
                .ok_or_else(|| anyhow!("bundle has no Transparency Log keys"))?;
            let admin = keys::load_noise(&dir, "admin")?;
            let sk = keys::load_ed25519(&dir, "witness")?;
            let my_pub = sk.verifying_key().to_bytes();
            let witness_name = log_keys
                .witnesses
                .iter()
                .find(|(_, k)| *k == my_pub)
                .map(|(n, _)| n.clone())
                .unwrap_or_else(|| format!("{}/witness", log_keys.origin.trim_end_matches("/log")));
            let mut witness = Witness::open(
                &witness_name,
                sk,
                &log_keys.origin,
                log_keys.ed25519,
                log_keys.ml_dsa,
                dir.join("witness/state"),
            )
            .map_err(|e| anyhow!("{e}"))?;
            println!(
                "[witness] {witness_name} following {log_addr} ({})",
                log_keys.origin
            );
            let mut last_logged = u64::MAX;
            loop {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => break,
                    _ = tokio::time::sleep(Duration::from_secs(interval_s.max(1))) => {
                        match external_witness_round(log_addr, &server_pub, &admin, &mut witness).await {
                            Ok(Some(size)) if size != last_logged => {
                                println!("[witness] cosigned size {size}");
                                last_logged = size;
                            }
                            Ok(_) => {}
                            Err(e) => eprintln!("[witness] {e:#}"),
                        }
                    }
                }
            }
            Ok(())
        }
        other => bail!("role: supported standalone role is `witness`, got {other:?}"),
    }
}

async fn cmd_enforce(mut args: Args) -> Result<()> {
    let mut dir = PathBuf::from("cell");
    let mut authority: SocketAddr = "127.0.0.1:4444".parse()?;
    let mut bundle_path = PathBuf::from(DEFAULT_BUNDLE);
    let mut action_str: Option<String> = None;
    let mut subject_str: Option<String> = None;
    let mut note = String::new();
    let mut duration_s: Option<u64> = None;
    let mut scope = Scope::default();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--dir" => dir = PathBuf::from(args.value("--dir")?),
            "--authority" => authority = args.value("--authority")?.parse()?,
            "--bundle" => bundle_path = PathBuf::from(args.value("--bundle")?),
            "--note" => note = args.value("--note")?,
            "--duration-s" => duration_s = Some(args.value("--duration-s")?.parse()?),
            "--region" => scope.regions.push(args.value("--region")?),
            "--queue" => scope.queues.push(args.value("--queue")?),
            v if !v.starts_with("--") => {
                if action_str.is_none() {
                    action_str = Some(v.to_string());
                } else if subject_str.is_none() {
                    subject_str = Some(v.to_string());
                } else {
                    bail!("unexpected argument {v}");
                }
            }
            other => bail!("enforce: unknown flag {other}"),
        }
    }

    let action_name = action_str.ok_or_else(|| anyhow!("missing action"))?;
    let subject_raw = subject_str.ok_or_else(|| anyhow!("missing subject id"))?;
    let (action, default_kind) = match action_name.as_str() {
        "kick" => (Action::Kick, SubjectKind::Session),
        "deny-admission" => (Action::DenyAdmission, SubjectKind::Account),
        "suspend" => (Action::Suspend, SubjectKind::Account),
        "ban" => (Action::Ban, SubjectKind::Account),
        "ban-device" => (Action::Ban, SubjectKind::Device),
        "ban-account" => (Action::Ban, SubjectKind::Account),
        "ban-build" => (Action::DenyAdmission, SubjectKind::Build),
        "revoke-instance" => (Action::Kick, SubjectKind::GsInstance),
        other => bail!("unknown action {other}"),
    };
    let (subject_kind, hex_id) = match subject_raw.split_once(':') {
        Some(("account", h)) => (SubjectKind::Account, h),
        Some(("device", h)) => (SubjectKind::Device, h),
        Some(("session", h)) => (SubjectKind::Session, h),
        Some(("sat", h)) => (SubjectKind::Sat, h),
        Some(("gs", h)) | Some(("instance", h)) => (SubjectKind::GsInstance, h),
        Some(("build", h)) => (SubjectKind::Build, h),
        None => (default_kind, subject_raw.as_str()),
        Some((k, _)) => bail!("unknown subject kind {k}"),
    };
    let subject_id = hex::decode(hex_id).context("subject hex")?;
    let order = Order {
        subject_kind,
        subject_id,
        action,
        scope,
        reason: Reason::Revoked as u16,
        duration_s,
        note,
    };

    let bundle = KeyBundle::load(&bundle_path).map_err(|e| anyhow!("{e}"))?;
    let server_pub = bundle
        .transport_key("revocation")
        .map_err(|e| anyhow!("{e}"))?;
    let admin = keys::load_noise(&dir, "admin")?;
    let enf_key = Ed25519Signer::new(keys::load_ed25519(&dir, "enforcement")?);

    let (seq, rec_idx, ev_idx) =
        rpc_enforce(authority, &server_pub, &admin, &enf_key, &order).await?;
    println!(
        "[enforce] published revocation #{seq} (record log index {rec_idx}, event log index {ev_idx:?})"
    );
    Ok(())
}

async fn cmd_evidence(mut args: Args) -> Result<()> {
    let mut dir = PathBuf::from("cell");
    let mut authority: SocketAddr = "127.0.0.1:4444".parse()?;
    let mut bundle_path = PathBuf::from(DEFAULT_BUNDLE);
    let mut op: Option<String> = None;
    let mut id_hex: Option<String> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--dir" => dir = PathBuf::from(args.value("--dir")?),
            "--authority" => authority = args.value("--authority")?.parse()?,
            "--bundle" => bundle_path = PathBuf::from(args.value("--bundle")?),
            v if !v.starts_with("--") => {
                if op.is_none() {
                    op = Some(v.to_string());
                } else if id_hex.is_none() {
                    id_hex = Some(v.to_string());
                } else {
                    bail!("unexpected argument {v}");
                }
            }
            other => bail!("evidence: unknown flag {other}"),
        }
    }

    let bundle = KeyBundle::load(&bundle_path).map_err(|e| anyhow!("{e}"))?;
    let server_pub = bundle
        .transport_key("evidence")
        .map_err(|e| anyhow!("{e}"))?;
    let admin = keys::load_noise(&dir, "admin")?;
    let hex_str = id_hex.ok_or_else(|| anyhow!("missing hex id"))?;
    match op.as_deref() {
        Some("list") => {
            let id: [u8; 16] = hex::decode(&hex_str)?
                .try_into()
                .map_err(|_| anyhow!("match id must be 16 bytes"))?;
            let digests = rpc_evidence_list(authority, &server_pub, &admin, id).await?;
            for d in digests {
                println!("{}", hex::encode(d));
            }
        }
        Some("get") => {
            let d: [u8; 32] = hex::decode(&hex_str)?
                .try_into()
                .map_err(|_| anyhow!("digest must be 32 bytes"))?;
            match rpc_evidence_get(authority, &server_pub, &admin, d).await? {
                Some(bytes) => std::io::stdout().write_all(&bytes)?,
                None => bail!("not found"),
            }
        }
        other => bail!("evidence: expected `list` or `get`, got {other:?}"),
    }
    Ok(())
}

async fn cmd_ticket(mut args: Args) -> Result<()> {
    let mut authority: SocketAddr = "127.0.0.1:4444".parse()?;
    let mut bundle_path = PathBuf::from(DEFAULT_BUNDLE);
    let mut queue = "open".to_string();
    let mut client_build_hex: Option<String> = None;
    let mut client_binary: Option<PathBuf> = None;
    let mut wait_secs = 30u64;
    let mut out = PathBuf::from("ticket.fpp");

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--authority" => authority = args.value("--authority")?.parse()?,
            "--bundle" => bundle_path = PathBuf::from(args.value("--bundle")?),
            "--queue" => queue = args.value("--queue")?,
            "--client-build" => client_build_hex = Some(args.value("--client-build")?),
            "--client-binary" => {
                client_binary = Some(PathBuf::from(args.value("--client-binary")?))
            }
            "--wait-secs" => wait_secs = args.value("--wait-secs")?.parse()?,
            "--out" => out = PathBuf::from(args.value("--out")?),
            other => bail!("ticket: unknown flag {other}"),
        }
    }

    let bundle = KeyBundle::load(&bundle_path).map_err(|e| anyhow!("{e}"))?;
    let server_pub = bundle
        .transport_key("verifier")
        .map_err(|e| anyhow!("{e}"))?;
    let keys = bundle.keyset();
    let build: [u8; 32] = match (&client_build_hex, &client_binary) {
        (Some(h), _) => hex::decode(h)?
            .try_into()
            .map_err(|_| anyhow!("--client-build: 64 hex digits"))?,
        (None, Some(p)) => file_sha256(p).with_context(|| format!("read {}", p.display()))?,
        (None, None) => file_sha256(&std::env::current_exe()?)?,
    };
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let signer = Ed25519Signer::new(SigningKey::from_bytes(&seed));
    let session_key = signer.session_key();
    let session_pub = session_key.to_bytes();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(wait_secs);
    let (ar, sat, sat_claims, gs_addr, gs_noise_static) = loop {
        // 1) Verifier -> AR
        let (mut vs, vchal) = open_control(authority, &server_pub, None, Purpose::Evidence).await?;
        let platform = std::env::consts::OS.to_string();
        let msg = evidence_request_sign_bytes(&vchal, &session_pub, &platform, &build, &[]);
        let pop_sig: [u8; 64] = signer.sign(&msg).try_into().expect("64 bytes");
        vs.send(&EvidenceRequest {
            session_pub: session_pub.clone(),
            pop_sig,
            platform,
            client_build: build,
            evidence: Vec::new(),
        })
        .await?;
        let ar = match vs.recv_max::<EvidenceAnswer>(MAX_CONTROL_FRAME).await? {
            EvidenceAnswer::Ar(ar) => ar,
            EvidenceAnswer::Refused { code } => bail!("verifier refused ({code})"),
            EvidenceAnswer::Activate(_) => bail!("unexpected TPM activation"),
        };
        let ar_claims = verify_ar(&ar, &keys, now_s()).map_err(|e| anyhow!("AR: {e}"))?;
        if ar_claims.cnf != session_key || ar_claims.nonce != vchal {
            bail!("AR binding mismatch");
        }

        // 2) Broker -> SAT
        let broker_pub = bundle.transport_key("broker").map_err(|e| anyhow!("{e}"))?;
        let (mut bs, bchal) = open_control(authority, &broker_pub, None, Purpose::Match).await?;
        let mmsg = match_request_sign_bytes(&bchal, &ar, &queue);
        let mpop: [u8; 64] = signer.sign(&mmsg).try_into().expect("64 bytes");
        bs.send(&MatchRequest {
            ar: ar.clone(),
            queue: queue.clone(),
            pop_sig: mpop,
        })
        .await?;
        match bs.recv_max::<MatchAnswer>(MAX_CONTROL_FRAME).await? {
            MatchAnswer::Granted {
                sat,
                gs_addr,
                gs_noise_static,
            } => {
                let sat_claims =
                    verify_sat(&sat, &keys, now_s()).map_err(|e| anyhow!("SAT: {e}"))?;
                break (ar, sat, sat_claims, gs_addr, gs_noise_static);
            }
            MatchAnswer::Refused { code }
                if code == Reason::ServerDraining as u16
                    && tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            MatchAnswer::Refused { code } => bail!("broker refused ({code})"),
        }
    };

    let text = format!(
        "fpp-ticket 1\nsession_seed {}\ngs_addr {}\ngs_noise_static {}\nsat {}\nar {}\nliveness_key {}\ndid {}\n",
        hex::encode(seed),
        gs_addr,
        hex::encode(gs_noise_static),
        hex::encode(&sat),
        hex::encode(&ar),
        hex::encode(bundle.server_liveness.to_bytes()),
        hex::encode(sat_claims.did.0),
    );
    let mut file = {
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        o.open(&out)
            .with_context(|| format!("write {}", out.display()))?
    };
    file.write_all(text.as_bytes())?;
    println!(
        "[ticket] {} in match {}.. slot {} on {} (queue {}, tier D{}): {}",
        hex::encode(&sat_claims.sub[..4]),
        hex::encode(&sat_claims.match_id.0[..4]),
        sat_claims.slot,
        gs_addr,
        sat_claims.queue,
        sat_claims.tier as u8,
        out.display()
    );
    Ok(())
}

fn run_audit(paths: &[String]) -> ExitCode {
    if paths.is_empty() {
        eprintln!("usage: fppd audit <bundle.fppb>...");
        return ExitCode::from(2);
    }
    let mut bundles = Vec::new();
    let mut found = false;
    for path in paths {
        let bundle = match std::fs::read(path)
            .map_err(|e| e.to_string())
            .and_then(|b| audit::parse(&b).map_err(|e| e.to_string()))
        {
            Ok(b) => b,
            Err(e) => {
                eprintln!("{path}: {e}");
                return ExitCode::from(2);
            }
        };
        let report = audit::audit(&bundle);
        let role = match bundle.meta.as_ref().map(|m| m.role) {
            Some(audit::ROLE_HOST) => "host",
            _ => "player",
        };
        println!(
            "{path}: {role}, {} commits, {} frames, {} units, {} checkpoints, {} outcomes: {}",
            report.commits,
            report.frames,
            report.units,
            report.checkpoints,
            report.outcomes,
            if report.clean() { "clean" } else { "FINDINGS" }
        );
        for finding in &report.findings {
            println!("  finding: {finding}");
        }
        for note in &report.notes {
            println!("  note: {note}");
        }
        found |= !report.clean();
        bundles.push(bundle);
    }
    for finding in audit::equivocations(&bundles) {
        println!("across bundles: {finding}");
        found = true;
    }
    if found {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
