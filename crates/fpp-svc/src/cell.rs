//! A cell's CA and its services' identities.

use anyhow::{bail, Context, Result};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyUsagePurpose,
};
use std::path::Path;

/// Services are named `<service>.fpp-cell` in their certificates.
pub const CELL_DOMAIN: &str = "fpp-cell";

/// A service's TLS identity (certificate and PKCS#8 key, DER) and the cell
/// CA it trusts.
#[derive(Clone)]
pub struct Identity {
    pub name: String,
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    pub ca_der: Vec<u8>,
}

pub fn valid_service_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn dn(common_name: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    dn
}

/// Issue a CA and one identity per service into `dir`: `ca.der`, and
/// `<service>/tls.der`, `<service>/tls.key.der`. Existing files are kept
/// (a cell is initialized once; add services with a new cell or a real CA).
pub fn init(dir: &Path, services: &[&str]) -> Result<Vec<Identity>> {
    if dir.join("ca.der").exists() {
        bail!("{} already holds a cell CA", dir.display());
    }
    for s in services {
        if !valid_service_name(s) {
            bail!("bad service name {s:?}");
        }
    }
    let mut ca_params = CertificateParams::default();
    ca_params.distinguished_name = dn("fpp dev cell CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca = Certificate::from_params(ca_params).context("cell CA")?;
    let ca_der = ca.serialize_der()?;
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join("ca.der"), &ca_der)?;
    let mut out = Vec::new();
    for s in services {
        let host = format!("{s}.{CELL_DOMAIN}");
        let mut params = CertificateParams::new(vec![host.clone()]);
        params.distinguished_name = dn(&host);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let cert = Certificate::from_params(params)?;
        let id = Identity {
            name: s.to_string(),
            cert_der: cert.serialize_der_with_signer(&ca)?,
            key_der: cert.serialize_private_key_der(),
            ca_der: ca_der.clone(),
        };
        let sdir = dir.join(s);
        std::fs::create_dir_all(&sdir)?;
        std::fs::write(sdir.join("tls.der"), &id.cert_der)?;
        std::fs::write(sdir.join("tls.key.der"), &id.key_der)?;
        out.push(id);
    }
    // (the CA key goes out of scope here: nothing more can be issued)
    Ok(out)
}

/// Load service `name`'s identity from a cell directory.
pub fn load(dir: &Path, name: &str) -> Result<Identity> {
    let read = |p: &Path| {
        std::fs::read(p).with_context(|| format!("read {} (run `fpp-cell init`)", p.display()))
    };
    Ok(Identity {
        name: name.to_string(),
        cert_der: read(&dir.join(name).join("tls.der"))?,
        key_der: read(&dir.join(name).join("tls.key.der"))?,
        ca_der: read(&dir.join("ca.der"))?,
    })
}

/// A service's own signing seed (32 bytes) in its directory, made on first
/// use: each service's keys are generated where they are used and never
/// leave it (in production: its HSM).
pub fn signing_seed(dir: &Path, service: &str, which: &str) -> Result<[u8; 32]> {
    let path = dir.join(service).join(format!("{which}.seed"));
    if let Ok(bytes) = std::fs::read(&path) {
        return bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("{} is not 32 bytes", path.display()));
    }
    let seed: [u8; 32] = rand::random();
    std::fs::create_dir_all(dir.join(service))?;
    std::fs::write(&path, seed)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(seed)
}
