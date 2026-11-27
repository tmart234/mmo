//! TPM 2.0 evidence collection via `tpm2-tools` (the TCTI in `TPM2TOOLS_TCTI`,
//! default the kernel's resource manager): EK and NV certificate, Attestation
//! Key, quotes over a challenge nonce, measured-boot and IMA logs, session key
//! creation/certification, and credential activation.
//!
//! Pure `std` — zero `aws-lc-rs`, zero `tokio`, zero `anyhow`. Produces the
//! unified [`crate::tokens::evidence::TpmEvidence`] used by both game servers
//! and PC clients.

use crate::bundle::{hex_decode, hex_encode};
use crate::control::CredentialChallenge;
use crate::crypto::{self, SessionSigner, Signer};
use crate::tokens::evidence::TpmEvidence;
use crate::types::{Kid, SessionKey};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Where Linux publishes the firmware and kernel measurement logs.
pub const BOOT_LOG: &str = "/sys/kernel/security/tpm0/binary_bios_measurements";
pub const IMA_LOG: &str = "/sys/kernel/security/ima/binary_runtime_measurements";
/// The RSA EK certificate's NV index (TCG EK Credential Profile).
pub const EK_CERT_NV: &str = "0x1c00002";

#[derive(Debug)]
pub struct Tpm2Error(pub String);

impl core::fmt::Display for Tpm2Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Tpm2Error {}

impl From<std::io::Error> for Tpm2Error {
    fn from(e: std::io::Error) -> Self {
        Tpm2Error(e.to_string())
    }
}

fn err(msg: impl Into<String>) -> Tpm2Error {
    Tpm2Error(msg.into())
}

pub struct Tpm2Options {
    /// The TPM (`TPM2TOOLS_TCTI` form, e.g. `swtpm:port=2321`); `None` uses
    /// `tpm2-tools`' default or the environment.
    pub tcti: Option<String>,
    /// Scratch directory for key contexts.
    pub workdir: PathBuf,
    /// PCRs to quote (SHA-256 bank).
    pub pcrs: Vec<u8>,
    /// Intermediate CA certificates (DER) between the EK certificate and the
    /// manufacturer's root, when NV does not hold them.
    pub ek_intermediates: Vec<Vec<u8>>,
    pub boot_log: Option<PathBuf>,
    pub ima_log: Option<PathBuf>,
}

pub struct Tpm2 {
    opts: Tpm2Options,
    ek_public: Vec<u8>,
    ek_certificate: Vec<u8>,
    ak_public: Vec<u8>,
}

struct Tools<'a> {
    dir: &'a Path,
    tcti: Option<&'a str>,
}

impl Tools<'_> {
    fn command(&self, program: &str) -> Command {
        let mut c = Command::new(program);
        c.current_dir(self.dir);
        if let Some(tcti) = self.tcti {
            c.env("TPM2TOOLS_TCTI", tcti);
        }
        c
    }

    fn run_keep(&self, args: &[&str]) -> Result<Vec<u8>, Tpm2Error> {
        let out = self
            .command(args[0])
            .args(&args[1..])
            .output()
            .map_err(|e| err(format!("run {} (tpm2-tools): {e}", args[0])))?;
        if !out.status.success() {
            self.flush();
            return Err(err(format!(
                "{}: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(out.stdout)
    }

    fn flush(&self) {
        for kind in ["-t", "-s"] {
            let _ = self.command("tpm2_flushcontext").arg(kind).output();
        }
    }

    fn run(&self, args: &[&str]) -> Result<Vec<u8>, Tpm2Error> {
        let out = self.run_keep(args);
        self.flush();
        out
    }
}

fn read_optional(path: &Option<PathBuf>) -> Result<Vec<u8>, Tpm2Error> {
    match path {
        Some(p) if p.exists() => {
            std::fs::read(p).map_err(|e| err(format!("read {}: {e}", p.display())))
        }
        _ => Ok(Vec::new()),
    }
}

/// `tpm2_pcrread` output: `  <index> : 0x<hex>` lines.
pub fn parse_pcrread(text: &str) -> BTreeMap<u8, Vec<u8>> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        if let Some((index, value)) = line.trim().split_once(':') {
            if let (Ok(index), Some(value)) =
                (index.trim().parse(), value.trim().strip_prefix("0x"))
            {
                if let Some(value) = hex_decode(value) {
                    out.insert(index, value);
                }
            }
        }
    }
    out
}

impl Tpm2 {
    /// Create the EK (TCG default RSA template) and an AK under it, and read the NV EK cert.
    pub fn open(opts: Tpm2Options) -> Result<Self, Tpm2Error> {
        std::fs::create_dir_all(&opts.workdir)?;
        let dir = opts.workdir.clone();
        let t = Tools {
            dir: &dir,
            tcti: opts.tcti.as_deref(),
        };
        t.run(&["tpm2_createek", "-c", "ek.ctx", "-G", "rsa", "-u", "ek.pub"])?;
        t.run(&[
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
        ])?;
        t.run(&["tpm2_nvread", EK_CERT_NV, "-o", "ek.der"])
            .map_err(|e| err(format!("read EK certificate from NV: {e}")))?;
        Ok(Tpm2 {
            ek_public: std::fs::read(dir.join("ek.pub"))?,
            ek_certificate: std::fs::read(dir.join("ek.der"))?,
            ak_public: std::fs::read(dir.join("ak.pub"))?,
            opts,
        })
    }

    fn tools(&self) -> Tools<'_> {
        Tools {
            dir: &self.opts.workdir,
            tcti: self.opts.tcti.as_deref(),
        }
    }

    /// Gather unified [`TpmEvidence`] quoting `nonce`.
    pub fn evidence(&self, nonce: &[u8; 32]) -> Result<TpmEvidence, Tpm2Error> {
        let dir = &self.opts.workdir;
        let t = self.tools();
        let list = self
            .opts
            .pcrs
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let selection = format!("sha256:{list}");
        let boot_log = read_optional(&self.opts.boot_log)?;
        let ima_log = read_optional(&self.opts.ima_log)?;
        t.run(&[
            "tpm2_quote",
            "-c",
            "ak.ctx",
            "-l",
            &selection,
            "-q",
            &hex_encode(nonce),
            "-m",
            "quote.msg",
            "-s",
            "quote.sig",
            "-g",
            "sha256",
        ])?;
        let pcrs: Vec<(u8, Vec<u8>)> = parse_pcrread(&String::from_utf8_lossy(
            &t.run(&["tpm2_pcrread", &selection])?,
        ))
        .into_iter()
        .collect();
        let mut ek_chain = vec![self.ek_certificate.clone()];
        ek_chain.extend(self.opts.ek_intermediates.iter().cloned());
        Ok(TpmEvidence {
            ek_public: self.ek_public.clone(),
            ek_chain,
            ak_public: self.ak_public.clone(),
            quote: std::fs::read(dir.join("quote.msg"))?,
            quote_signature: std::fs::read(dir.join("quote.sig"))?,
            pcrs,
            boot_log,
            ima_log,
            session_public: Vec::new(),
            certify: Vec::new(),
            certify_signature: Vec::new(),
        })
    }

    /// `TPM2_ActivateCredential`: open the authority's secret for this EK + AK.
    pub fn activate(&self, challenge: &CredentialChallenge) -> Result<Vec<u8>, Tpm2Error> {
        let dir = &self.opts.workdir;
        let t = self.tools();
        let mut file = 0xBADC_C0DEu32.to_be_bytes().to_vec();
        file.extend_from_slice(&1u32.to_be_bytes());
        for part in [&challenge.id_object, &challenge.encrypted_secret] {
            let size = u16::try_from(part.len()).map_err(|_| err("credential size"))?;
            file.extend_from_slice(&size.to_be_bytes());
            file.extend_from_slice(part);
        }
        std::fs::write(dir.join("credential.blob"), file)?;
        t.run_keep(&[
            "tpm2_startauthsession",
            "--policy-session",
            "-S",
            "session.ctx",
        ])
        .and_then(|_| t.run_keep(&["tpm2_policysecret", "-S", "session.ctx", "-c", "e"]))
        .and_then(|_| {
            t.run(&[
                "tpm2_activatecredential",
                "-c",
                "ak.ctx",
                "-C",
                "ek.ctx",
                "-i",
                "credential.blob",
                "-o",
                "secret.out",
                "-P",
                "session:session.ctx",
            ])
        })
        .map_err(|e| err(format!("credential activation: {e}")))?;
        Ok(std::fs::read(dir.join("secret.out"))?)
    }

    /// Make an ECDSA P-256 session key in the TPM.
    pub fn session_key(&self) -> Result<TpmSessionKey, Tpm2Error> {
        let t = self.tools();
        t.run(&[
            "tpm2_createprimary",
            "-C",
            "o",
            "-g",
            "sha256",
            "-G",
            "ecc",
            "-c",
            "primary.ctx",
        ])?;
        t.run(&[
            "tpm2_create",
            "-C",
            "primary.ctx",
            "-G",
            "ecc256:ecdsa-sha256",
            "-a",
            "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign",
            "-u",
            "skey.pub",
            "-r",
            "skey.priv",
        ])?;
        t.run(&[
            "tpm2_load",
            "-C",
            "primary.ctx",
            "-u",
            "skey.pub",
            "-r",
            "skey.priv",
            "-c",
            "skey.ctx",
        ])?;
        let public_area = std::fs::read(self.opts.workdir.join("skey.pub"))?;
        let n = public_area.len();
        if n < 4 + 32 + 2 + 32 {
            return Err(err("session key public area"));
        }
        let mut sec1 = vec![4u8];
        sec1.extend_from_slice(&public_area[n - 66..n - 34]);
        sec1.extend_from_slice(&public_area[n - 32..]);
        let key = SessionKey::from_bytes(&sec1).ok_or_else(|| err("session key"))?;
        Ok(TpmSessionKey {
            dir: self.opts.workdir.clone(),
            tcti: self.opts.tcti.clone(),
            kid: crypto::session_kid(&key),
            key,
            public_area,
        })
    }

    /// `TPM2_Certify` of the session key by the AK: (`TPMS_ATTEST`, `TPMT_SIGNATURE`).
    pub fn certify(&self, _key: &TpmSessionKey) -> Result<(Vec<u8>, Vec<u8>), Tpm2Error> {
        let t = self.tools();
        t.run(&[
            "tpm2_certify",
            "-c",
            "skey.ctx",
            "-C",
            "ak.ctx",
            "-g",
            "sha256",
            "-o",
            "certify.attest",
            "-s",
            "certify.sig",
        ])?;
        let dir = &self.opts.workdir;
        Ok((
            std::fs::read(dir.join("certify.attest"))?,
            std::fs::read(dir.join("certify.sig"))?,
        ))
    }
}

/// A player's ECDSA P-256 session key held inside the TPM (`tpm2_sign`).
#[derive(Clone)]
pub struct TpmSessionKey {
    dir: PathBuf,
    tcti: Option<String>,
    key: SessionKey,
    kid: Kid,
    pub public_area: Vec<u8>,
}

impl TpmSessionKey {
    fn tools(&self) -> Tools<'_> {
        Tools {
            dir: &self.dir,
            tcti: self.tcti.as_deref(),
        }
    }

    fn try_sign(&self, msg: &[u8]) -> Result<[u8; 64], Tpm2Error> {
        let t = self.tools();
        std::fs::write(self.dir.join("skey.msg"), msg)?;
        t.run(&[
            "tpm2_sign",
            "-c",
            "skey.ctx",
            "-g",
            "sha256",
            "-s",
            "ecdsa",
            "-o",
            "skey.sig",
            "skey.msg",
        ])?;
        let tss = std::fs::read(self.dir.join("skey.sig"))?;
        let field = |at: usize| -> Result<(&[u8], usize), Tpm2Error> {
            let size = u16::from_be_bytes(
                tss.get(at..at + 2)
                    .ok_or_else(|| err("signature"))?
                    .try_into()
                    .expect("2 bytes"),
            ) as usize;
            Ok((
                tss.get(at + 2..at + 2 + size)
                    .ok_or_else(|| err("signature"))?,
                at + 2 + size,
            ))
        };
        if tss.get(..4) != Some(&[0x00, 0x18, 0x00, 0x0b]) {
            return Err(err("not an ECDSA/SHA-256 signature"));
        }
        let (r, next) = field(4)?;
        let (s, _) = field(next)?;
        let pad = |v: &[u8]| -> Result<[u8; 32], Tpm2Error> {
            let v = &v[v.iter().take_while(|b| **b == 0).count()..];
            if v.len() > 32 {
                return Err(err("ECDSA value size"));
            }
            let mut out = [0u8; 32];
            out[32 - v.len()..].copy_from_slice(v);
            Ok(out)
        };
        let mut rs = [0u8; 64];
        rs[..32].copy_from_slice(&pad(r)?);
        rs[32..].copy_from_slice(&pad(s)?);
        crypto::es256_normalize(&rs).ok_or_else(|| err("ECDSA signature"))
    }
}

impl Signer for TpmSessionKey {
    fn alg(&self) -> i64 {
        self.key.alg()
    }

    fn kid(&self) -> Kid {
        self.kid
    }

    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        match self.try_sign(msg) {
            Ok(sig) => sig.to_vec(),
            Err(e) => {
                eprintln!("[tpm] signing with the session key: {e}");
                vec![0; 64]
            }
        }
    }
}

impl SessionSigner for TpmSessionKey {
    fn session_key(&self) -> SessionKey {
        self.key
    }
}

/// Software TPM (`swtpm`) harness for tests and local labs. Stopped and
/// cleaned up when dropped.
pub mod swtpm {
    use super::{err, Tpm2Error};
    use crate::bundle::hex_encode;
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};

    pub struct Swtpm {
        pub dir: PathBuf,
        pub port: u16,
        child: Child,
    }

    impl Drop for Swtpm {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    pub fn available() -> bool {
        [
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
        })
    }

    fn free_port_pair() -> u16 {
        loop {
            let a = TcpListener::bind("127.0.0.1:0").expect("bind");
            let port = a.local_addr().expect("addr").port();
            if port < 65535 && TcpListener::bind(("127.0.0.1", port + 1)).is_ok() {
                return port;
            }
        }
    }

    impl Swtpm {
        pub fn start(dir: PathBuf) -> Result<Swtpm, Tpm2Error> {
            let _ = std::fs::remove_dir_all(&dir);
            let state = dir.join("state");
            let ca = dir.join("localca");
            std::fs::create_dir_all(&state)?;
            std::fs::create_dir_all(&ca)?;
            std::fs::write(
                dir.join("swtpm-localca.conf"),
                format!(
                    "statedir = {0}\nsigningkey = {0}/signkey.pem\nissuercert = {0}/issuercert.pem\ncertserial = {0}/certserial\n",
                    ca.display()
                ),
            )?;
            std::fs::write(
                dir.join("swtpm-localca.options"),
                "--platform-manufacturer fpp-test\n--platform-version 2.1\n--platform-model fpp-test\n",
            )?;
            let localca = Command::new("sh")
                .arg("-c")
                .arg("command -v swtpm_localca")
                .output()?
                .stdout;
            std::fs::write(
                dir.join("swtpm_setup.conf"),
                format!(
                    "create_certs_tool = {}\ncreate_certs_tool_config = {}\ncreate_certs_tool_options = {}\nactive_pcr_banks = sha256\n",
                    String::from_utf8_lossy(&localca).trim(),
                    dir.join("swtpm-localca.conf").display(),
                    dir.join("swtpm-localca.options").display()
                ),
            )?;
            let setup = Command::new("swtpm_setup")
                .args([
                    "--tpm2",
                    "--create-ek-cert",
                    "--create-platform-cert",
                    "--lock-nvram",
                    "--overwrite",
                ])
                .arg("--tpmstate")
                .arg(&state)
                .arg("--config")
                .arg(dir.join("swtpm_setup.conf"))
                .output()?;
            if !setup.status.success() {
                return Err(err(format!(
                    "swtpm_setup: {}",
                    String::from_utf8_lossy(&setup.stderr)
                )));
            }
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
                .spawn()?;
            let tpm = Swtpm { dir, port, child };
            for _ in 0..50 {
                if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                    return Ok(tpm);
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(err("swtpm did not start"))
        }

        pub fn tcti(&self) -> String {
            format!("swtpm:host=127.0.0.1,port={}", self.port)
        }

        pub fn root_pem(&self) -> PathBuf {
            self.dir.join("localca/swtpm-localca-rootca-cert.pem")
        }

        pub fn intermediate_pem(&self) -> PathBuf {
            self.dir.join("localca/issuercert.pem")
        }

        pub fn extend(&self, pcr: u8, sha256: &[u8]) -> Result<(), Tpm2Error> {
            let out = Command::new("tpm2_pcrextend")
                .arg(format!("{pcr}:sha256={}", hex_encode(sha256)))
                .env("TPM2TOOLS_TCTI", self.tcti())
                .output()?;
            if !out.status.success() {
                return Err(err(format!(
                    "tpm2_pcrextend: {}",
                    String::from_utf8_lossy(&out.stderr)
                )));
            }
            Ok(())
        }
    }
}
