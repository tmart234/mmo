//! Certificates and verified TLS configuration for every QUIC link.
//!
//! Every connection in the workspace (client -> Verifier, Broker, GS;
//! GS -> Server Liveness) verifies the server's certificate chain against a
//! pinned CA. There is no "skip verification" path. For local development,
//! `DevPki::generate()` makes a CA plus one certificate per public service
//! (`<service>.dev`, each with its own key) and one for the GS client port
//! (`localhost`), and `gen_keys` writes them under `keys/`. In production
//! the CA is the publisher's (docs/anticheat/04-protocol.md §7.1).
//!
//! These are the public endpoints. Services talk to each other inside their
//! cell over mutual TLS with the cell's own CA (`fpp-svc`).

use anyhow::{anyhow, Context, Result};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::{fs, path::Path, sync::Arc};

/// The trust-plane services with public endpoints: Server Liveness (game
/// servers join it), the Verifier and the Broker (clients).
pub const PUBLIC_SERVICES: [&str; 3] = ["liveness", "verifier", "broker"];

/// TLS server name of a public service (`liveness.dev`, ...).
pub fn server_name(service: &str) -> String {
    format!("{service}.dev")
}

/// TLS server name clients use when dialing a GS client port.
pub const GS_SERVER_NAME: &str = "localhost";

pub const DEFAULT_CA_CERT: &str = "keys/dev_ca.der";
pub const DEFAULT_GS_TLS_CERT: &str = "keys/gs_tls.der";
pub const DEFAULT_GS_TLS_KEY: &str = "keys/gs_tls.key.der";

/// Default certificate and key files of a public service
/// (`keys/<service>_tls.der`, `keys/<service>_tls.key.der`).
pub fn default_tls_files(service: &str) -> (String, String) {
    (
        format!("keys/{service}_tls.der"),
        format!("keys/{service}_tls.key.der"),
    )
}

/// A server certificate (DER) and its PKCS#8 private key (DER).
#[derive(Clone)]
pub struct ServerIdentity {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
}

impl ServerIdentity {
    pub fn load(cert_path: impl AsRef<Path>, key_path: impl AsRef<Path>) -> Result<Self> {
        let (cert_path, key_path) = (cert_path.as_ref(), key_path.as_ref());
        Ok(Self {
            cert_der: fs::read(cert_path).with_context(|| missing_hint(cert_path))?,
            key_der: fs::read(key_path).with_context(|| missing_hint(key_path))?,
        })
    }
}

/// Development PKI: one CA and the server identities it signs.
pub struct DevPki {
    pub ca_cert_der: Vec<u8>,
    /// One per [`PUBLIC_SERVICES`], in that order.
    pub services: Vec<(String, ServerIdentity)>,
    pub gs: ServerIdentity,
}

impl DevPki {
    pub fn generate() -> Result<Self> {
        let mut ca_params = CertificateParams::default();
        ca_params.distinguished_name = distinguished_name("mmo dev CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca = Certificate::from_params(ca_params).context("generate dev CA")?;

        let services = PUBLIC_SERVICES
            .iter()
            .map(|s| Ok((s.to_string(), server_identity(&ca, &server_name(s), false)?)))
            .collect::<Result<_>>()?;
        Ok(Self {
            ca_cert_der: ca.serialize_der().context("serialize dev CA")?,
            services,
            gs: server_identity(&ca, GS_SERVER_NAME, true)?,
        })
    }

    /// The identity of public service `name`.
    pub fn service(&self, name: &str) -> &ServerIdentity {
        &self
            .services
            .iter()
            .find(|(s, _)| s == name)
            .unwrap_or_else(|| panic!("no public service {name}"))
            .1
    }

    /// Write the CA certificate and every server identity into `dir`
    /// using the default file names. The CA private key is not written.
    pub fn write_to(&self, dir: impl AsRef<Path>) -> Result<()> {
        let dir = dir.as_ref();
        fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        let file = |default: &str| dir.join(Path::new(default).file_name().expect("file name"));
        fs::write(file(DEFAULT_CA_CERT), &self.ca_cert_der)?;
        for (name, id) in &self.services {
            let (cert, key) = default_tls_files(name);
            fs::write(file(&cert), &id.cert_der)?;
            fs::write(file(&key), &id.key_der)?;
        }
        fs::write(file(DEFAULT_GS_TLS_CERT), &self.gs.cert_der)?;
        fs::write(file(DEFAULT_GS_TLS_KEY), &self.gs.key_der)?;
        Ok(())
    }
}

/// Generate and write a dev PKI into `dir` unless its files already exist.
/// Returns whether new files were written.
pub fn ensure_dev_pki(dir: impl AsRef<Path>) -> Result<bool> {
    let dir = dir.as_ref();
    let mut files = vec![
        DEFAULT_CA_CERT.to_string(),
        DEFAULT_GS_TLS_CERT.to_string(),
        DEFAULT_GS_TLS_KEY.to_string(),
    ];
    for s in PUBLIC_SERVICES {
        let (cert, key) = default_tls_files(s);
        files.extend([cert, key]);
    }
    let present = files.iter().all(|f| {
        dir.join(Path::new(f).file_name().expect("file name"))
            .exists()
    });
    if present {
        return Ok(false);
    }
    DevPki::generate()?.write_to(dir)?;
    Ok(true)
}

fn distinguished_name(common_name: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    dn
}

fn server_identity(ca: &Certificate, name: &str, loopback_ip: bool) -> Result<ServerIdentity> {
    let mut params = CertificateParams::new(vec![name.to_string()]);
    if loopback_ip {
        params
            .subject_alt_names
            .push(SanType::IpAddress(std::net::Ipv4Addr::LOCALHOST.into()));
    }
    params.distinguished_name = distinguished_name(name);
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let cert = Certificate::from_params(params).with_context(|| format!("generate {name}"))?;
    Ok(ServerIdentity {
        cert_der: cert
            .serialize_der_with_signer(ca)
            .with_context(|| format!("sign {name}"))?,
        key_der: cert.serialize_private_key_der(),
    })
}

fn missing_hint(path: &Path) -> String {
    format!(
        "read {} (generate dev certificates with `cargo run -p tools --bin gen_keys`)",
        path.display()
    )
}

/// Suite FPP-T1 (04 §3): TLS 1.3 over aws-lc-rs with the hybrid
/// post-quantum group `X25519MLKEM768` preferred and `X25519` as fallback,
/// so recorded control-plane traffic (tokens, device evidence, PII) resists
/// later decryption by a quantum computer.
pub fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    use rustls::crypto::aws_lc_rs::{self, kx_group};
    let mut p = aws_lc_rs::default_provider();
    p.kx_groups = vec![kx_group::X25519MLKEM768, kx_group::X25519];
    Arc::new(p)
}

/// Read a CA certificate (DER) to pin as the trust root.
pub fn load_ca(path: impl AsRef<Path>) -> Result<Vec<u8>> {
    let path = path.as_ref();
    fs::read(path).with_context(|| missing_hint(path))
}

/// TLS 1.3 server config presenting `identity` (FPP-T1).
pub fn tls_server_config(identity: &ServerIdentity) -> Result<rustls::ServerConfig> {
    let chain = vec![CertificateDer::from(identity.cert_der.clone())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(identity.key_der.clone()));
    rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("TLS 1.3 server config")?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .context("server certificate")
}

/// TLS 1.3 client config that accepts only servers whose chain ends at `ca_der`.
pub fn tls_client_config(ca_der: &[u8]) -> Result<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca_der.to_vec()))
        .context("add pinned CA to root store")?;
    Ok(rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("TLS 1.3 client config")?
        .with_root_certificates(roots)
        .with_no_client_auth())
}

/// QUIC server config presenting `identity`.
pub fn quic_server_config(identity: &ServerIdentity) -> Result<quinn::ServerConfig> {
    let quic = quinn::crypto::rustls::QuicServerConfig::try_from(tls_server_config(identity)?)
        .map_err(|e| anyhow!("QUIC server config: {e}"))?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(quic)))
}

/// QUIC client config that accepts only servers whose chain ends at `ca_der`.
pub fn quic_client_config(ca_der: &[u8]) -> Result<quinn::ClientConfig> {
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls_client_config(ca_der)?)
        .map_err(|e| anyhow!("QUIC client config: {e}"))?;
    Ok(quinn::ClientConfig::new(Arc::new(quic)))
}
