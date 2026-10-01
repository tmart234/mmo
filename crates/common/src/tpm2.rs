//! A game server's TPM 2.0 evidence, gathered with tpm2-tools (the TCTI in
//! `TPM2TOOLS_TCTI`, default the kernel's resource manager): the EK and its
//! certificate from NV, an Attestation Key, quotes over Server Liveness's challenge,
//! the firmware's and kernel's measurement logs, and credential
//! activation. Server Liveness appraises it (`svc-liveness/src/tpm2.rs`, `attest-tpm`).
//!
//! For the kernel to measure the GS binary, the machine needs an IMA policy
//! that measures executables (boot with `ima_policy=tcb`, or a policy with
//! `measure func=BPRM_CHECK`) and `ima_hash=sha256`.

use crate::proto::{CredentialChallenge, Tpm2Evidence};
use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Where Linux publishes the logs.
pub const BOOT_LOG: &str = "/sys/kernel/security/tpm0/binary_bios_measurements";
pub const IMA_LOG: &str = "/sys/kernel/security/ima/binary_runtime_measurements";
/// The RSA EK certificate's NV index (TCG EK Credential Profile).
pub const EK_CERT_NV: &str = "0x1c00002";

pub struct Tpm2Options {
    /// The TPM (`TPM2TOOLS_TCTI` form, e.g. `swtpm:port=2321`); `None`:
    /// tpm2-tools' own default, or the environment's.
    pub tcti: Option<String>,
    /// Scratch directory for the key contexts.
    pub workdir: PathBuf,
    /// PCRs to quote (SHA-256 bank).
    pub pcrs: Vec<u8>,
    /// Intermediate CA certificates (DER) between the EK certificate and
    /// the manufacturer's root, when the TPM's NV does not hold them.
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

/// tpm2-tools against one TPM, in one directory.
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

    /// A command, keeping what it loaded (a session in use).
    fn run_keep(&self, args: &[&str]) -> Result<Vec<u8>> {
        let out = self
            .command(args[0])
            .args(&args[1..])
            .output()
            .with_context(|| format!("run {} (tpm2-tools)", args[0]))?;
        if !out.status.success() {
            self.flush();
            bail!(
                "{}: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(out.stdout)
    }

    /// Transient objects and sessions out: a TPM holds only a few.
    fn flush(&self) {
        for kind in ["-t", "-s"] {
            let _ = self.command("tpm2_flushcontext").arg(kind).output();
        }
    }

    /// A command, then a flush.
    fn run(&self, args: &[&str]) -> Result<Vec<u8>> {
        let out = self.run_keep(args);
        self.flush();
        out
    }
}

fn read_optional(path: &Option<PathBuf>) -> Result<Option<Vec<u8>>> {
    match path {
        Some(p) if p.exists() => Ok(Some(
            std::fs::read(p).with_context(|| format!("read {}", p.display()))?,
        )),
        _ => Ok(None),
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
                if let Ok(value) = hex::decode(value) {
                    out.insert(index, value);
                }
            }
        }
    }
    out
}

impl Tpm2 {
    /// Create the EK (the TCG default RSA template, the one its NV
    /// certificate is for) and an AK under it, and read the certificate.
    pub fn open(opts: Tpm2Options) -> Result<Self> {
        std::fs::create_dir_all(&opts.workdir).context("TPM work directory")?;
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
            .context("read the EK certificate from NV")?;
        Ok(Tpm2 {
            ek_public: std::fs::read(dir.join("ek.pub"))?,
            ek_certificate: std::fs::read(dir.join("ek.der"))?,
            ak_public: std::fs::read(dir.join("ak.pub"))?,
            opts,
        })
    }

    /// A quote over `nonce` with the logs and the EK's certificate chain.
    fn tools(&self) -> Tools<'_> {
        Tools {
            dir: &self.opts.workdir,
            tcti: self.opts.tcti.as_deref(),
        }
    }

    pub fn evidence(&self, nonce: &[u8; 32]) -> Result<Tpm2Evidence> {
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
        // (the logs first: a measurement between reading them and quoting
        // would make them stale, and Server Liveness would refuse the join)
        let boot_log = read_optional(&self.opts.boot_log)?;
        let ima_log = read_optional(&self.opts.ima_log)?;
        t.run(&[
            "tpm2_quote",
            "-c",
            "ak.ctx",
            "-l",
            &selection,
            "-q",
            &hex::encode(nonce),
            "-m",
            "quote.msg",
            "-s",
            "quote.sig",
            "-g",
            "sha256",
        ])?;
        let pcrs = parse_pcrread(&String::from_utf8_lossy(
            &t.run(&["tpm2_pcrread", &selection])?,
        ));
        let mut ek_chain = vec![self.ek_certificate.clone()];
        ek_chain.extend(self.opts.ek_intermediates.iter().cloned());
        Ok(Tpm2Evidence {
            ek_public: self.ek_public.clone(),
            ek_chain,
            ak_public: self.ak_public.clone(),
            attest: std::fs::read(dir.join("quote.msg"))?,
            signature: std::fs::read(dir.join("quote.sig"))?,
            pcrs,
            boot_log,
            ima_log,
        })
    }

    /// `TPM2_ActivateCredential`: Server Liveness's secret, if it was made for this
    /// TPM's EK and AK.
    pub fn activate(&self, challenge: &CredentialChallenge) -> Result<Vec<u8>> {
        let dir = &self.opts.workdir;
        let t = self.tools();
        // (tpm2_makecredential's file format)
        let mut file = 0xBADC_C0DEu32.to_be_bytes().to_vec();
        file.extend_from_slice(&1u32.to_be_bytes());
        for part in [&challenge.id_object, &challenge.encrypted_secret] {
            let size = u16::try_from(part.len()).context("credential size")?;
            file.extend_from_slice(&size.to_be_bytes());
            file.extend_from_slice(part);
        }
        std::fs::write(dir.join("credential.blob"), file)?;
        // (the EK's authorization: the endorsement hierarchy's policy)
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
        .context("credential activation")?;
        Ok(std::fs::read(dir.join("secret.out"))?)
    }
}

/// A player's session key in the TPM (roadmap P3): an ECDSA P-256 signing
/// key the TPM made under the owner hierarchy and keeps (`fixedTPM`,
/// `fixedParent`, `sensitiveDataOrigin`), certified by the AK. It signs
/// every FPP object of the session (ES256) through `tpm2_sign`.
#[derive(Clone)]
pub struct TpmSessionKey {
    dir: PathBuf,
    tcti: Option<String>,
    key: fpp_types::SessionKey,
    kid: fpp_types::Kid,
    /// `TPM2B_PUBLIC`, for the Verifier.
    pub public_area: Vec<u8>,
}

impl TpmSessionKey {
    fn tools(&self) -> Tools<'_> {
        Tools {
            dir: &self.dir,
            tcti: self.tcti.as_deref(),
        }
    }

    fn try_sign(&self, msg: &[u8]) -> Result<[u8; 64]> {
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
        // TPMT_SIGNATURE: ECDSA, SHA-256, TPM2B r, TPM2B s
        let field = |at: usize| -> Result<(&[u8], usize)> {
            let size = u16::from_be_bytes(
                tss.get(at..at + 2)
                    .context("signature")?
                    .try_into()
                    .expect("2 bytes"),
            ) as usize;
            Ok((
                tss.get(at + 2..at + 2 + size).context("signature")?,
                at + 2 + size,
            ))
        };
        if tss.get(..4) != Some(&[0x00, 0x18, 0x00, 0x0b]) {
            bail!("not an ECDSA/SHA-256 signature");
        }
        let (r, next) = field(4)?;
        let (s, _) = field(next)?;
        let pad = |v: &[u8]| -> Result<[u8; 32]> {
            let v = &v[v.iter().take_while(|b| **b == 0).count()..];
            if v.len() > 32 {
                bail!("ECDSA value size");
            }
            let mut out = [0u8; 32];
            out[32 - v.len()..].copy_from_slice(v);
            Ok(out)
        };
        let mut rs = [0u8; 64];
        rs[..32].copy_from_slice(&pad(r)?);
        rs[32..].copy_from_slice(&pad(s)?);
        // (the TPM's s may be high; FPP takes the low twin)
        fpp_crypto::es256_normalize(&rs).context("ECDSA signature")
    }
}

impl fpp_crypto::Signer for TpmSessionKey {
    fn alg(&self) -> i64 {
        self.key.alg()
    }

    fn kid(&self) -> fpp_types::Kid {
        self.kid
    }

    /// A failed signature comes back as zeros, which no verifier accepts.
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        match self.try_sign(msg) {
            Ok(sig) => sig.to_vec(),
            Err(e) => {
                eprintln!("[tpm] signing with the session key: {e:#}");
                vec![0; 64]
            }
        }
    }
}

impl fpp_crypto::SessionSigner for TpmSessionKey {
    fn session_key(&self) -> fpp_types::SessionKey {
        self.key
    }
}

impl Tpm2 {
    /// Make a session key in the TPM (replacing any earlier one).
    pub fn session_key(&self) -> Result<TpmSessionKey> {
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
        // TPM2B_PUBLIC of an ECC key ends with TPM2B x and TPM2B y
        let n = public_area.len();
        if n < 4 + 32 + 2 + 32 {
            bail!("session key public area");
        }
        let mut sec1 = vec![4u8];
        sec1.extend_from_slice(&public_area[n - 66..n - 34]);
        sec1.extend_from_slice(&public_area[n - 32..]);
        let key = fpp_types::SessionKey::from_bytes(&sec1).context("session key")?;
        Ok(TpmSessionKey {
            dir: self.opts.workdir.clone(),
            tcti: self.opts.tcti.clone(),
            kid: fpp_crypto::session_kid(&key),
            key,
            public_area,
        })
    }

    /// `TPM2_Certify` of the session key by the AK: (`TPMS_ATTEST`,
    /// `TPMT_SIGNATURE`).
    pub fn certify(&self, _key: &TpmSessionKey) -> Result<(Vec<u8>, Vec<u8>)> {
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

/// A software TPM (swtpm) with an EK certificate from a CA of its own, as
/// a manufacturer would provision it: for tests and local labs. Stopped
/// and deleted when dropped.
pub mod swtpm {
    use anyhow::{bail, Context, Result};
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

    /// Whether swtpm and tpm2-tools are installed.
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
        pub fn start(dir: PathBuf) -> Result<Swtpm> {
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
                .output()
                .context("swtpm_setup")?;
            if !setup.status.success() {
                bail!("swtpm_setup: {}", String::from_utf8_lossy(&setup.stderr));
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
                .spawn()
                .context("swtpm")?;
            let tpm = Swtpm { dir, port, child };
            for _ in 0..50 {
                if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                    return Ok(tpm);
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            bail!("swtpm did not start")
        }

        pub fn tcti(&self) -> String {
            format!("swtpm:host=127.0.0.1,port={}", self.port)
        }

        /// The manufacturer's root, and the intermediate that issued the
        /// EK certificate (PEM files).
        pub fn root_pem(&self) -> PathBuf {
            self.dir.join("localca/swtpm-localca-rootca-cert.pem")
        }
        pub fn intermediate_pem(&self) -> PathBuf {
            self.dir.join("localca/issuercert.pem")
        }

        /// Extend a PCR, as firmware or the kernel would.
        pub fn extend(&self, pcr: u8, sha256: &[u8]) -> Result<()> {
            let out = Command::new("tpm2_pcrextend")
                .arg(format!("{pcr}:sha256={}", hex::encode(sha256)))
                .env("TPM2TOOLS_TCTI", self.tcti())
                .output()?;
            if !out.status.success() {
                bail!("tpm2_pcrextend: {}", String::from_utf8_lossy(&out.stderr));
            }
            Ok(())
        }
    }
}
