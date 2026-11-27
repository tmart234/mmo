//! P3 PC client hardware attestation exit tests against real `fppd` and real
//! TPMs 2.0 (`swtpm` + `tpm2-tools`):
//! - clean Windows + HVCI -> D2 (`hvci: true`), joins `verified` and plays 2
//!   epochs with its TPM-resident key signing AdmitPop and InputCommits; refused
//!   by `hardened` (D3)
//! - Windows without HVCI -> D2, `hvci: false`, warned (`hvci-off`)
//! - Windows test-signing / Secure Boot off -> D0, refused by `verified`
//! - Linux Secure Boot -> D1 (`os-not-measured`), refused by `verified`
//! - Unpinned software TPM EK -> D0 (`evidence-rejected`)
//! - Replayed quote -> D0 (`evidence-rejected`)
//! - Guessed credential activation -> D0 (`evidence-rejected`)
//! - TPM evidence presented for external software session key -> D0

use anyhow::{anyhow, bail, ensure, Context, Result};
use fpp::control::CredentialChallenge;
use fpp::crypto::{now_s, P256Signer};
use fpp::tokens::{verify_ar, AttestationResult};
use fpp::tpm2_collect::swtpm::{self, Swtpm};
use fpp::tpm2_collect::{Tpm2Options, TpmSessionKey};
use fpp::types::{DeviceTier, Reason};
use fpp_attest::tpm::eventlog::{
    self, Event, EFI_GLOBAL_VARIABLE, EV_EFI_VARIABLE_DRIVER_CONFIG, EV_SEPARATOR,
};
use fpp_attest::tpm::public::hash;
use fpp_attest::tpm::wbcl::{sipa, sipa_event, EV_EVENT_TAG};
use fpp_sim::client::{
    request_admission_attested, Attestor, ClientTrust, Credentials, GameClient, Services,
    SessionEnd, SessionSigning,
};
use fpp_sim::game_wire::ClientCmd;
use fpp_sim::harness::TestCell;
use fpp_sim::server::{spawn_server, ServerConfig};
use fpp_sim::tpm::{TpmDevice, CLIENT_PCRS};
use std::sync::Mutex;
use std::time::Duration;

#[derive(Clone, Copy)]
struct Boot {
    secure_boot: bool,
    windows: Option<(bool, bool)>,
}

struct Machine {
    name: &'static str,
    tpm: Swtpm,
    device: TpmDevice,
    key: TpmSessionKey,
}

fn sha256(data: &[u8]) -> Vec<u8> {
    hash(fpp_attest::tpm::alg::SHA256, data).expect("SHA-256")
}

fn machine(name: &'static str, boot: Boot) -> Result<Machine> {
    let dir = std::env::temp_dir().join(format!("fpp-exit-{name}-{}", std::process::id()));
    let tpm = Swtpm::start(dir.clone())
        .map_err(|e| anyhow!("{e}"))
        .with_context(|| format!("swtpm for {name}"))?;
    let mut events = Vec::new();
    let mut measure = |pcr: u32, kind: u32, data: Vec<u8>| -> Result<()> {
        let digest = sha256(&data);
        tpm.extend(pcr as u8, &digest).map_err(|e| anyhow!("{e}"))?;
        events.push(Event {
            pcr,
            kind,
            sha256: digest,
            data,
        });
        Ok(())
    };
    measure(
        7,
        EV_EFI_VARIABLE_DRIVER_CONFIG,
        eventlog::variable_data(EFI_GLOBAL_VARIABLE, "SecureBoot", &[boot.secure_boot as u8]),
    )?;
    measure(7, EV_SEPARATOR, vec![0; 4])?;
    if let Some((test_signing, hvci)) = boot.windows {
        let config = [
            sipa_event(sipa::BOOTDEBUGGING, &[0]),
            sipa_event(sipa::OSKERNELDEBUG, &[0]),
            sipa_event(sipa::CODEINTEGRITY, &[1]),
            sipa_event(sipa::TESTSIGNING, &[test_signing as u8]),
            sipa_event(sipa::HYPERVISOR_LAUNCH_TYPE, &1u64.to_le_bytes()),
            sipa_event(sipa::VSM_LAUNCH_TYPE, &1u64.to_le_bytes()),
            sipa_event(sipa::VBS_HVCI_POLICY, &(hvci as u64).to_le_bytes()),
            sipa_event(sipa::HYPERVISOR_BOOT_DMA_PROTECTION, &[1]),
        ]
        .concat();
        measure(12, EV_EVENT_TAG, sipa_event(sipa::TRUSTBOUNDARY, &config))?;
    }
    let log = dir.join("boot.log");
    std::fs::write(&log, eventlog::encode(&events, None))?;
    let intermediate = std::fs::read_to_string(tpm.intermediate_pem())?;
    let (device, key) = TpmDevice::open(Tpm2Options {
        tcti: Some(tpm.tcti()),
        workdir: dir.join("work"),
        pcrs: CLIENT_PCRS.to_vec(),
        ek_intermediates: fpp_attest::x509::pem_certificates(&intermediate)
            .map_err(|e| anyhow!("{e}"))?,
        boot_log: Some(log),
        ima_log: None,
    })?;
    Ok(Machine {
        name,
        tpm,
        device,
        key,
    })
}

struct Replay<'a> {
    device: &'a TpmDevice,
    first: Mutex<Option<Vec<u8>>>,
}

impl Attestor for Replay<'_> {
    fn evidence(&self, challenge: &[u8; 32], session_pub: &[u8]) -> Result<Vec<u8>> {
        let mut first = self.first.lock().expect("lock");
        if first.is_none() {
            *first = Some(self.device.evidence(challenge, session_pub)?);
        }
        Ok(first.clone().expect("set"))
    }
    fn activate(&self, c: &CredentialChallenge) -> Result<Vec<u8>> {
        self.device.activate(c)
    }
}

struct Guess<'a>(&'a TpmDevice);

impl Attestor for Guess<'_> {
    fn evidence(&self, challenge: &[u8; 32], session_pub: &[u8]) -> Result<Vec<u8>> {
        self.0.evidence(challenge, session_pub)
    }
    fn activate(&self, _: &CredentialChallenge) -> Result<Vec<u8>> {
        Ok(vec![0x42; 32])
    }
}

struct Run {
    services: Services,
    trust: ClientTrust,
}

impl Run {
    async fn admit(
        &self,
        queue: &str,
        session: impl Fn() -> SessionSigning,
        attestor: &dyn Attestor,
    ) -> Result<Credentials> {
        for _ in 0..40 {
            match request_admission_attested(
                &self.services,
                &self.trust,
                queue,
                session(),
                Some(attestor),
            )
            .await
            {
                Err(e)
                    if matches!(
                        e.downcast_ref::<SessionEnd>(),
                        Some(SessionEnd::Refused(c)) if *c == Reason::ServerDraining as u16
                    ) =>
                {
                    tokio::time::sleep(Duration::from_millis(200)).await
                }
                r => return r,
            }
        }
        bail!("the game server never joined")
    }

    async fn ar(
        &self,
        session: impl Fn() -> SessionSigning,
        attestor: &dyn Attestor,
    ) -> Result<AttestationResult> {
        let creds = self.admit("open", session, attestor).await?;
        verify_ar(&creds.ar, &self.trust.keyset(), now_s()).map_err(|e| anyhow!("AR: {e}"))
    }

    async fn refused_for_tier(
        &self,
        queue: &str,
        session: impl Fn() -> SessionSigning,
        attestor: &dyn Attestor,
    ) -> Result<bool> {
        match self.admit(queue, session, attestor).await {
            Ok(_) => Ok(false),
            Err(e) => match e.downcast_ref::<SessionEnd>() {
                Some(SessionEnd::Refused(c)) if *c == Reason::TierInsufficient as u16 => Ok(true),
                _ => Err(e),
            },
        }
    }
}

fn tpm_session(m: &Machine) -> impl Fn() -> SessionSigning + '_ {
    move || Box::new(m.key.clone())
}

fn show(name: &str, ar: &AttestationResult) {
    println!(
        "[EXIT] {name}: tier D{}, secure_boot {:?}, hvci {:?}, key_in_hw {:?}, warnings {:?}",
        ar.tier as u8,
        ar.features.secure_boot,
        ar.features.hvci,
        ar.features.key_in_hw,
        ar.warnings
    );
}

async fn run(cell: &TestCell, machines: &[Machine], rogue: &Machine) -> Result<()> {
    let _gs = spawn_server(ServerConfig {
        liveness: cell.addr,
        bundle: cell.bundle.clone(),
        game_bind: "127.0.0.1:0".parse()?,
        gs_id: "attest-gs".into(),
        min_tier: DeviceTier::D0Unknown,
        equivocate_from: None,
        ignore_revocations: false,
        ledger_dir: None,
    })
    .await?;

    let r = Run {
        services: Services::single(cell.addr),
        trust: ClientTrust::from_bundle(cell.bundle.clone()),
    };
    let m = |name: &str| machines.iter().find(|m| m.name == name).expect("machine");

    // ---- tiers from measured boot
    let clean = m("windows-hvci");
    let ar = r.ar(tpm_session(clean), &clean.device).await?;
    show(clean.name, &ar);
    ensure!(
        ar.tier == DeviceTier::D2Hardware,
        "clean Windows with HVCI: D2"
    );
    ensure!(ar.features.hvci == Some(true) && ar.features.key_in_hw == Some(true));
    ensure!(
        !r.refused_for_tier("verified", tpm_session(clean), &clean.device)
            .await?
    );
    ensure!(
        r.refused_for_tier("hardened", tpm_session(clean), &clean.device)
            .await?
    );
    println!(
        "[EXIT] {}: admitted to `verified` (D2), refused by `hardened` (D3)",
        clean.name
    );

    let no_hvci = m("windows-no-hvci");
    let ar = r.ar(tpm_session(no_hvci), &no_hvci.device).await?;
    show(no_hvci.name, &ar);
    ensure!(ar.tier == DeviceTier::D2Hardware && ar.features.hvci == Some(false));
    ensure!(ar.warnings.iter().any(|w| w == "hvci-off"));
    ensure!(
        !r.refused_for_tier("verified", tpm_session(no_hvci), &no_hvci.device)
            .await?
    );
    ensure!(
        r.refused_for_tier("hardened", tpm_session(no_hvci), &no_hvci.device)
            .await?
    );

    for (name, warning, tier) in [
        (
            "windows-test-signing",
            "test-signing",
            DeviceTier::D0Unknown,
        ),
        (
            "windows-secure-boot-off",
            "secure-boot-off",
            DeviceTier::D0Unknown,
        ),
        (
            "linux-secure-boot",
            "os-not-measured",
            DeviceTier::D1Software,
        ),
    ] {
        let mm = m(name);
        let ar = r.ar(tpm_session(mm), &mm.device).await?;
        show(name, &ar);
        ensure!(
            ar.tier == tier,
            "{name}: D{} not D{}",
            ar.tier as u8,
            tier as u8
        );
        ensure!(
            ar.warnings.iter().any(|w| w == warning),
            "{name}: no {warning}"
        );
        ensure!(
            r.refused_for_tier("verified", tpm_session(mm), &mm.device)
                .await?
        );
        println!("[EXIT] {name}: refused by `verified`");
    }

    // ---- red team
    let rejected = |what: &str, ar: &AttestationResult| -> Result<()> {
        show(what, ar);
        ensure!(
            ar.tier == DeviceTier::D0Unknown,
            "{what}: D{}",
            ar.tier as u8
        );
        ensure!(
            ar.warnings
                .iter()
                .any(|w| w.starts_with("evidence-rejected")),
            "{what}: {:?}",
            ar.warnings
        );
        Ok(())
    };
    let ar = r.ar(tpm_session(rogue), &rogue.device).await?;
    rejected("software TPM (EK from no pinned manufacturer)", &ar)?;

    let replay = Replay {
        device: &clean.device,
        first: Mutex::new(None),
    };
    let fresh = r.ar(tpm_session(clean), &replay).await?;
    ensure!(fresh.tier == DeviceTier::D2Hardware, "first use is fresh");
    let ar = r.ar(tpm_session(clean), &replay).await?;
    rejected("replayed quote", &ar)?;

    let ar = r.ar(tpm_session(clean), &Guess(&clean.device)).await?;
    rejected("guessed credential", &ar)?;

    let software_key = || -> SessionSigning { Box::new(P256Signer::generate()) };
    let ar = r.ar(software_key, &clean.device).await?;
    rejected("TPM evidence for a session key outside the TPM", &ar)?;

    // ---- the D2 machine plays, its TPM signing the session
    let creds = r
        .admit("verified", tpm_session(clean), &clean.device)
        .await?;
    let mut game = GameClient::connect(creds, &r.trust, Duration::from_secs(10)).await?;
    while game.heads.len() < 2 {
        game.step(&ClientCmd::Move { dx: 0.1, dy: 0.0 }).await?;
    }
    game.bye().await?;
    println!(
        "[EXIT] {}: played in `verified` through 2 epochs, its TPM signing AdmitPop and InputCommits",
        clean.name
    );
    Ok(())
}

fn main() -> Result<()> {
    if !swtpm::available() {
        if std::env::var_os("FPP_REQUIRE_SWTPM").is_some() {
            bail!("FPP_REQUIRE_SWTPM is set, and swtpm or tpm2-tools is missing");
        }
        println!("[EXIT] swtpm or tpm2-tools missing: skipped");
        return Ok(());
    }
    let windows = |test_signing, hvci| Boot {
        secure_boot: true,
        windows: Some((test_signing, hvci)),
    };
    let machines = vec![
        machine("windows-hvci", windows(false, true))?,
        machine("windows-no-hvci", windows(false, false))?,
        machine("windows-test-signing", windows(true, true))?,
        machine(
            "windows-secure-boot-off",
            Boot {
                secure_boot: false,
                windows: Some((false, true)),
            },
        )?,
        machine(
            "linux-secure-boot",
            Boot {
                secure_boot: true,
                windows: None,
            },
        )?,
    ];
    let rogue = machine("unpinned", windows(false, true))?;
    let roots: String = machines
        .iter()
        .map(|m| std::fs::read_to_string(m.tpm.root_pem()))
        .collect::<std::io::Result<_>>()?;
    let roots_path =
        std::env::temp_dir().join(format!("fpp-exit-roots-{}.pem", std::process::id()));
    std::fs::write(&roots_path, roots)?;

    let cell = TestCell::start(
        "attest-exit",
        false,
        &["--tpm-ek-roots".into(), roots_path.display().to_string()],
    )?;
    let result = tokio::runtime::Runtime::new()?.block_on(run(&cell, &machines, &rogue));
    drop(cell);
    let _ = std::fs::remove_file(&roots_path);
    match &result {
        Ok(()) => println!("[EXIT] P3 exit tests passed"),
        Err(e) => println!("[EXIT] FAILED: {e:#}"),
    }
    result
}
