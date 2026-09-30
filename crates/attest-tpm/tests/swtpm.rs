//! Against a real TPM 2.0: swtpm (the reference TPM implementation, libtpms)
//! driven by tpm2-tools, provisioned with an EK certificate by swtpm's own
//! CA as a manufacturer would. What the TPM produces is checked by this
//! crate; what this crate produces (a credential) is opened by the TPM.
//!
//! Needs `swtpm`, `swtpm_setup`, `swtpm_localca` and tpm2-tools 5 (Debian
//! and Ubuntu: `apt install swtpm swtpm-tools tpm2-tools`). Without them
//! the tests pass trivially, unless FPP_REQUIRE_SWTPM is set (CI sets it).

use std::collections::BTreeMap;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use attest_core::x509::pem_certificates;
use attest_tpm::eventlog::{
    self, Event, EFI_GLOBAL_VARIABLE, EV_EFI_VARIABLE_DRIVER_CONFIG, EV_SEPARATOR,
};
use attest_tpm::ima::ima_ng_record;
use attest_tpm::public::hash;
use attest_tpm::{
    alg, appraise, make_credential, verify_ek, verify_quote, Evidence, Pcrs, Policy, Public,
    Registry, TpmError,
};

fn available() -> bool {
    let found = [
        "swtpm",
        "swtpm_setup",
        "swtpm_localca",
        "tpm2_quote",
        "tpm2_activatecredential",
    ]
    .iter()
    .all(|tool| {
        Command::new("sh")
            .arg("-c")
            .arg(format!("command -v {tool}"))
            .stdout(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    });
    if !found && std::env::var_os("FPP_REQUIRE_SWTPM").is_some() {
        panic!("FPP_REQUIRE_SWTPM is set, and swtpm or tpm2-tools is missing");
    }
    if !found {
        eprintln!("swtpm or tpm2-tools missing: skipped");
    }
    found
}

/// A swtpm with an EK certificate, running until dropped.
struct Tpm {
    dir: PathBuf,
    port: u16,
    child: Child,
}

impl Drop for Tpm {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn free_port_pair() -> u16 {
    loop {
        let a = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = a.local_addr().unwrap().port();
        if port < 65535 && TcpListener::bind(("127.0.0.1", port + 1)).is_ok() {
            return port;
        }
    }
}

impl Tpm {
    fn start(name: &str) -> Tpm {
        let dir = std::env::temp_dir().join(format!("attest-tpm-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let state = dir.join("state");
        let ca = dir.join("localca");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::create_dir_all(&ca).unwrap();
        // (a CA of our own, as swtpm-create-user-config-files would make)
        std::fs::write(
            dir.join("swtpm-localca.conf"),
            format!(
                "statedir = {0}\nsigningkey = {0}/signkey.pem\nissuercert = {0}/issuercert.pem\ncertserial = {0}/certserial\n",
                ca.display()
            ),
        )
        .unwrap();
        std::fs::write(
            dir.join("swtpm-localca.options"),
            "--platform-manufacturer fpp-test\n--platform-version 2.1\n--platform-model fpp-test\n",
        )
        .unwrap();
        let localca = String::from_utf8(
            Command::new("sh")
                .arg("-c")
                .arg("command -v swtpm_localca")
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap();
        std::fs::write(
            dir.join("swtpm_setup.conf"),
            format!(
                "create_certs_tool = {}\ncreate_certs_tool_config = {}\ncreate_certs_tool_options = {}\nactive_pcr_banks = sha256\n",
                localca.trim(),
                dir.join("swtpm-localca.conf").display(),
                dir.join("swtpm-localca.options").display()
            ),
        )
        .unwrap();
        let setup = Command::new("swtpm_setup")
            .args([
                "--tpm2",
                "--create-ek-cert",
                "--create-platform-cert",
                "--lock-nvram",
                "--overwrite",
                "--tpmstate",
            ])
            .arg(&state)
            .arg("--config")
            .arg(dir.join("swtpm_setup.conf"))
            .output()
            .unwrap();
        assert!(
            setup.status.success(),
            "swtpm_setup: {}",
            String::from_utf8_lossy(&setup.stderr)
        );
        let port = free_port_pair();
        let child = Command::new("swtpm")
            .args(["socket", "--tpm2", "--flags", "not-need-init,startup-clear"])
            .arg("--tpmstate")
            .arg(format!("dir={}", state.display()))
            .arg("--server")
            .arg(format!("type=tcp,port={port}"))
            .arg("--ctrl")
            .arg(format!("type=tcp,port={}", port + 1))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let tpm = Tpm { dir, port, child };
        for _ in 0..50 {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return tpm;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        panic!("swtpm did not start");
    }

    fn path(&self, file: &str) -> PathBuf {
        self.dir.join(file)
    }

    /// A tpm2-tools command against this TPM; transient objects flushed
    /// after (swtpm holds only three).
    fn run(&self, args: &[&str]) -> std::process::Output {
        let tcti = format!("swtpm:host=127.0.0.1,port={}", self.port);
        let out = Command::new(args[0])
            .args(&args[1..])
            .current_dir(&self.dir)
            .env("TPM2TOOLS_TCTI", &tcti)
            .output()
            .unwrap();
        for kind in ["-t", "-s"] {
            let _ = Command::new("tpm2_flushcontext")
                .arg(kind)
                .env("TPM2TOOLS_TCTI", &tcti)
                .output();
        }
        out
    }

    fn ok(&self, args: &[&str]) -> Vec<u8> {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        out.stdout
    }

    fn read(&self, file: &str) -> Vec<u8> {
        std::fs::read(self.path(file)).unwrap()
    }

    fn extend(&self, pcr: u8, digest: &[u8]) {
        self.ok(&[
            "tpm2_pcrextend",
            &format!("{pcr}:sha256={}", hex::encode(digest)),
        ]);
    }

    /// PCR values (SHA-256 bank) as the TPM reports them.
    fn pcrs(&self, indices: &[u8]) -> Pcrs {
        let list = indices
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let text =
            String::from_utf8(self.ok(&["tpm2_pcrread", &format!("sha256:{list}")])).unwrap();
        let mut out = BTreeMap::new();
        for line in text.lines() {
            if let Some((index, value)) = line.trim().split_once(':') {
                if let (Ok(index), Some(value)) =
                    (index.trim().parse(), value.trim().strip_prefix("0x"))
                {
                    out.insert(index, hex::decode(value).unwrap());
                }
            }
        }
        assert_eq!(out.len(), indices.len(), "{text}");
        out
    }

    /// Quote `indices` with the AK in `ak.ctx`.
    fn quote(&self, ak: &str, nonce: &[u8], indices: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let list = indices
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",");
        self.ok(&[
            "tpm2_quote",
            "-c",
            ak,
            "-l",
            &format!("sha256:{list}"),
            "-q",
            &hex::encode(nonce),
            "-m",
            "quote.msg",
            "-s",
            "quote.sig",
            "-g",
            "sha256",
        ]);
        (self.read("quote.msg"), self.read("quote.sig"))
    }

    /// The manufacturer's (our CA's) root and intermediate.
    fn roots(&self) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let root =
            std::fs::read_to_string(self.path("localca/swtpm-localca-rootca-cert.pem")).unwrap();
        let issuer = std::fs::read_to_string(self.path("localca/issuercert.pem")).unwrap();
        (
            pem_certificates(&root).unwrap(),
            pem_certificates(&issuer).unwrap(),
        )
    }

    /// Hand a credential to the TPM, as tpm2_makecredential's file would;
    /// what ActivateCredential gives back.
    fn activate(
        &self,
        ak_ctx: &str,
        ek_ctx: &str,
        id_object: &[u8],
        encrypted_secret: &[u8],
    ) -> Result<Vec<u8>, String> {
        let mut file = 0xBADC_C0DEu32.to_be_bytes().to_vec();
        file.extend_from_slice(&1u32.to_be_bytes());
        file.extend_from_slice(&(id_object.len() as u16).to_be_bytes());
        file.extend_from_slice(id_object);
        file.extend_from_slice(&(encrypted_secret.len() as u16).to_be_bytes());
        file.extend_from_slice(encrypted_secret);
        std::fs::write(self.path("credential.blob"), file).unwrap();
        // (the EK's policy: the endorsement hierarchy's secret)
        let tcti = format!("swtpm:host=127.0.0.1,port={}", self.port);
        let script = format!(
            "set -e; tpm2_startauthsession --policy-session -S session.ctx; \
             tpm2_policysecret -S session.ctx -c e >/dev/null; \
             tpm2_activatecredential -c {ak_ctx} -C {ek_ctx} -i credential.blob -o secret.out -P session:session.ctx; \
             tpm2_flushcontext session.ctx"
        );
        let out = Command::new("sh")
            .arg("-c")
            .arg(script)
            .current_dir(&self.dir)
            .env("TPM2TOOLS_TCTI", &tcti)
            .output()
            .unwrap();
        for kind in ["-t", "-s"] {
            let _ = Command::new("tpm2_flushcontext")
                .arg(kind)
                .env("TPM2TOOLS_TCTI", &tcti)
                .output();
        }
        if out.status.success() {
            Ok(self.read("secret.out"))
        } else {
            Err(String::from_utf8_lossy(&out.stderr).into_owned())
        }
    }
}

fn public(path: &Path) -> Public {
    Public::from_tpm2b(&std::fs::read(path).unwrap()).unwrap()
}

#[test]
fn rsa_endorsement_credential_and_quote() {
    if !available() {
        return;
    }
    let tpm = Tpm::start("rsa");
    tpm.ok(&["tpm2_createek", "-c", "ek.ctx", "-G", "rsa", "-u", "ek.pub"]);
    tpm.ok(&[
        "tpm2_createak",
        "-C",
        "ek.ctx",
        "-c",
        "ak.ctx",
        "-G",
        "rsa",
        "-g",
        "sha256",
        "-s",
        "rsassa",
        "-u",
        "ak.pub",
        "-n",
        "ak.name",
        "-f",
        "tss",
    ]);
    tpm.ok(&["tpm2_nvread", "0x1c00002", "-o", "ek.der"]);
    let ek = public(&tpm.path("ek.pub"));
    let ak = public(&tpm.path("ak.pub"));

    // the Name this crate computes is the TPM's
    assert_eq!(ak.name().unwrap(), tpm.read("ak.name"));

    // the EK certificate chains to the manufacturer's root, and certifies this EK
    let (roots, intermediates) = tpm.roots();
    let chain = vec![tpm.read("ek.der"), intermediates[0].clone()];
    let endorsement = verify_ek(&ek, &chain, &roots, None).unwrap();
    assert_eq!(
        endorsement.ek_digest.to_vec(),
        hash(alg::SHA256, &ek.bytes).unwrap()
    );
    // ... and no other root
    assert!(verify_ek(
        &ek,
        &chain,
        &intermediates[..0]
            .iter()
            .chain(&[tpm.read("ek.der")])
            .cloned()
            .collect::<Vec<_>>(),
        None
    )
    .is_err());
    // ... and not the AK (a signing key is no EK)
    assert!(verify_ek(&ak, &chain, &roots, None).is_err());

    // credential activation: the TPM opens what this crate made for its AK
    let secret = b"fpp credential activation test!!";
    let challenge = make_credential(&ek, &ak.name().unwrap(), secret).unwrap();
    assert_eq!(
        tpm.activate(
            "ak.ctx",
            "ek.ctx",
            &challenge.id_object,
            &challenge.encrypted_secret
        )
        .unwrap(),
        secret
    );
    // ... and not for another key's Name (an AK the TPM does not hold)
    let mut other = ak.name().unwrap();
    other[5] ^= 1;
    let wrong = make_credential(&ek, &other, secret).unwrap();
    assert!(tpm
        .activate(
            "ak.ctx",
            "ek.ctx",
            &wrong.id_object,
            &wrong.encrypted_secret
        )
        .is_err());

    // a quote over PCRs 0, 7 and 10
    tpm.extend(10, &[7u8; 32]);
    let nonce = [0x42u8; 32];
    let (attest, sig) = tpm.quote("ak.ctx", &nonce, &[0, 7, 10]);
    let pcrs = tpm.pcrs(&[0, 7, 10]);
    let quote = verify_quote(&ak, &attest, &sig, &nonce, &pcrs).unwrap();
    assert_eq!(quote.pcrs, pcrs);
    assert_eq!(quote.attest.extra_data, nonce);

    // what a forger would try
    assert_eq!(
        verify_quote(&ak, &attest, &sig, &[0x43u8; 32], &pcrs).unwrap_err(),
        TpmError::NonceMismatch
    );
    let mut lying = pcrs.clone();
    lying.insert(10, vec![0u8; 32]);
    assert_eq!(
        verify_quote(&ak, &attest, &sig, &nonce, &lying).unwrap_err(),
        TpmError::PcrDigestMismatch
    );
    let mut changed = attest.clone();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    assert_eq!(
        verify_quote(&ak, &changed, &sig, &nonce, &pcrs).unwrap_err(),
        TpmError::BadSignature
    );
    let mut fewer = pcrs.clone();
    fewer.remove(&7);
    assert!(verify_quote(&ak, &attest, &sig, &nonce, &fewer).is_err());
    // (the EK is not an attestation key, whatever it would sign)
    assert!(matches!(
        verify_quote(&ek, &attest, &sig, &nonce, &pcrs),
        Err(TpmError::Policy(_))
    ));
}

#[test]
fn ecc_attestation_key_and_endorsement_key() {
    if !available() {
        return;
    }
    let tpm = Tpm::start("ecc");
    tpm.ok(&["tpm2_createek", "-c", "ek.ctx", "-G", "ecc", "-u", "ek.pub"]);
    tpm.ok(&[
        "tpm2_createak",
        "-C",
        "ek.ctx",
        "-c",
        "ak.ctx",
        "-G",
        "ecc",
        "-g",
        "sha256",
        "-s",
        "ecdsa",
        "-u",
        "ak.pub",
        "-n",
        "ak.name",
        "-f",
        "tss",
    ]);
    let ek = public(&tpm.path("ek.pub"));
    let ak = public(&tpm.path("ak.pub"));
    assert_eq!(ak.name().unwrap(), tpm.read("ak.name"));

    // credential activation through ECDH to a P-256 EK
    let secret = [9u8; 32];
    let challenge = make_credential(&ek, &ak.name().unwrap(), &secret).unwrap();
    assert_eq!(
        tpm.activate(
            "ak.ctx",
            "ek.ctx",
            &challenge.id_object,
            &challenge.encrypted_secret
        )
        .unwrap(),
        secret
    );

    let nonce = [1u8; 32];
    let (attest, sig) = tpm.quote("ak.ctx", &nonce, &[10]);
    let pcrs = tpm.pcrs(&[10]);
    verify_quote(&ak, &attest, &sig, &nonce, &pcrs).unwrap();
    let mut changed = attest.clone();
    changed[10] ^= 1;
    assert_eq!(
        verify_quote(&ak, &changed, &sig, &nonce, &pcrs).unwrap_err(),
        TpmError::BadSignature
    );
}

fn secure_boot_event(on: bool) -> Event {
    let data = eventlog::variable_data(EFI_GLOBAL_VARIABLE, "SecureBoot", &[on as u8]);
    Event {
        pcr: 7,
        kind: EV_EFI_VARIABLE_DRIVER_CONFIG,
        sha256: hash(alg::SHA256, &data).unwrap(),
        data,
    }
}

fn separator(pcr: u32) -> Event {
    let data = vec![0u8; 4];
    Event {
        pcr,
        kind: EV_SEPARATOR,
        sha256: hash(alg::SHA256, &data).unwrap(),
        data,
    }
}

/// A machine that booted with Secure Boot and ran the game server: its
/// firmware's and kernel's measurements extended into the TPM exactly as
/// firmware and IMA would, then a quote, then appraisal against a Build
/// Registry (finding F06: the server's build is what the kernel measured,
/// not what the server says).
#[test]
fn measured_boot_and_program_appraisal() {
    if !available() {
        return;
    }
    let tpm = Tpm::start("measured");
    tpm.ok(&["tpm2_createek", "-c", "ek.ctx", "-G", "rsa", "-u", "ek.pub"]);
    tpm.ok(&[
        "tpm2_createak",
        "-C",
        "ek.ctx",
        "-c",
        "ak.ctx",
        "-G",
        "rsa",
        "-g",
        "sha256",
        "-s",
        "rsassa",
        "-u",
        "ak.pub",
        "-f",
        "tss",
    ]);
    let ak = public(&tpm.path("ak.pub"));

    // firmware: Secure Boot on (PCR 7), separators
    let boot_events = vec![secure_boot_event(true), separator(7), separator(4)];
    for e in &boot_events {
        tpm.extend(e.pcr as u8, &e.sha256);
    }
    let boot_log = eventlog::encode(&boot_events, None);

    // kernel (IMA): a shell, then the game server
    let good_gs = hash(alg::SHA256, b"gs build 1.0 from CI").unwrap();
    let mut ima_log = Vec::new();
    for (file, path) in [
        (hash(alg::SHA256, b"bash").unwrap(), "/usr/bin/bash"),
        (good_gs.clone(), "/opt/fpp/gs"),
    ] {
        let (record, extend) = ima_ng_record(&file, path);
        tpm.extend(10, &extend);
        ima_log.extend(record);
    }

    let registry = Registry::parse(&format!(
        "# CI builds with provenance\n{}  gs 1.0 (build 42)\n",
        hex::encode(&good_gs)
    ))
    .unwrap();
    let policy = Policy {
        registry: &registry,
        program: Some("/opt/fpp/gs"),
        require_secure_boot: true,
        allow_ima_violations: false,
    };
    let nonce = [5u8; 32];
    let (attest, signature) = tpm.quote("ak.ctx", &nonce, &[4, 7, 10]);
    let evidence = Evidence {
        attest,
        signature,
        pcrs: tpm.pcrs(&[4, 7, 10]),
        boot_log: Some(boot_log.clone()),
        ima_log: Some(ima_log.clone()),
    };
    let appraisal = appraise(&ak, &evidence, &nonce, &policy).unwrap();
    assert_eq!(appraisal.secure_boot, Some(true));
    assert_eq!(
        appraisal.program,
        Some((good_gs.clone(), "gs 1.0 (build 42)".to_string()))
    );
    assert_eq!(appraisal.measurements.len(), 2);

    // a build not in the registry
    let empty = Registry::default();
    assert!(appraise(
        &ak,
        &evidence,
        &nonce,
        &Policy {
            registry: &empty,
            ..policy.clone()
        }
    )
    .is_err());

    // a log claiming Secure Boot on, where the firmware measured it off
    let mut lying_boot = evidence.clone();
    lying_boot.boot_log = Some(eventlog::encode(
        &[secure_boot_event(false), separator(7), separator(4)],
        None,
    ));
    assert!(appraise(&ak, &lying_boot, &nonce, &policy).is_err());

    // a log naming the registered build, where the kernel measured another
    let (swapped, _) = ima_ng_record(&hash(alg::SHA256, b"bash").unwrap(), "/usr/bin/bash");
    let (claimed, _) = ima_ng_record(&hash(alg::SHA256, b"a modified gs").unwrap(), "/opt/fpp/gs");
    let mut lying_ima = evidence.clone();
    lying_ima.ima_log = Some([swapped.clone(), claimed].concat());
    assert!(appraise(&ak, &lying_ima, &nonce, &policy).is_err());

    // the modified server that really ran: the log replays, the build is unknown
    let modified = hash(alg::SHA256, b"a modified gs").unwrap();
    let (record, extend) = ima_ng_record(&modified, "/opt/fpp/gs");
    tpm.extend(10, &extend);
    let nonce2 = [6u8; 32];
    let (attest, signature) = tpm.quote("ak.ctx", &nonce2, &[4, 7, 10]);
    let later = Evidence {
        attest,
        signature,
        pcrs: tpm.pcrs(&[4, 7, 10]),
        boot_log: Some(boot_log),
        ima_log: Some([ima_log, record].concat()),
    };
    assert_eq!(
        appraise(&ak, &later, &nonce2, &policy).unwrap_err(),
        TpmError::Policy("the program is not a registered build")
    );
    // (and the earlier evidence is no good for the new nonce)
    assert!(appraise(&ak, &evidence, &nonce2, &policy).is_err());
}
