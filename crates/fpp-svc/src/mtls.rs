//! QUIC with mutual TLS 1.3 inside a cell.

use anyhow::{anyhow, Context, Result};
use quinn::{ClientConfig, Connection, Endpoint, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::cell::{Identity, CELL_DOMAIN};

fn roots(ca: &[u8]) -> Result<rustls::RootCertStore> {
    let mut r = rustls::RootCertStore::empty();
    r.add(CertificateDer::from(ca.to_vec()))
        .context("cell CA")?;
    Ok(r)
}

fn chain_and_key(id: &Identity) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    (
        vec![CertificateDer::from(id.cert_der.clone())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(id.key_der.clone())),
    )
}

/// A server that accepts only callers with a certificate from the cell CA.
pub fn server_config(id: &Identity) -> Result<ServerConfig> {
    let provider = common::pki::provider();
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots(&id.ca_der)?), provider.clone())
            .build()
            .map_err(|e| anyhow!("client verifier: {e}"))?;
    let (chain, key) = chain_and_key(id);
    let tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)?;
    let quic = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|e| anyhow!("QUIC server: {e}"))?;
    Ok(ServerConfig::with_crypto(Arc::new(quic)))
}

/// A client presenting its own cell certificate.
pub fn client_config(id: &Identity) -> Result<ClientConfig> {
    let (chain, key) = chain_and_key(id);
    let tls = rustls::ClientConfig::builder_with_provider(common::pki::provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots(&id.ca_der)?)
        .with_client_auth_cert(chain, key)?;
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|e| anyhow!("QUIC client: {e}"))?;
    Ok(ClientConfig::new(Arc::new(quic)))
}

pub fn server_endpoint(id: &Identity, bind: SocketAddr) -> Result<Endpoint> {
    Endpoint::server(server_config(id)?, bind).with_context(|| format!("bind {bind}"))
}

/// A client endpoint for `id` (on any local port).
pub fn client_endpoint(id: &Identity) -> Result<Endpoint> {
    let mut e = Endpoint::client("0.0.0.0:0".parse().expect("addr")).context("client endpoint")?;
    e.set_default_client_config(client_config(id)?);
    Ok(e)
}

/// Connect to `service` at `addr`; its certificate must name it.
pub async fn connect(endpoint: &Endpoint, addr: SocketAddr, service: &str) -> Result<Connection> {
    endpoint
        .connect(addr, &format!("{service}.{CELL_DOMAIN}"))?
        .await
        .with_context(|| format!("connect to {service} at {addr}"))
}

/// The cell service at the other end of a connection, from its certificate.
pub fn peer_service(conn: &Connection) -> Option<String> {
    let certs = conn
        .peer_identity()?
        .downcast::<Vec<CertificateDer<'static>>>()
        .ok()?;
    let (_, cert) = x509_parser::parse_x509_certificate(certs.first()?.as_ref()).ok()?;
    let san = cert.subject_alternative_name().ok()??;
    san.value.general_names.iter().find_map(|n| match n {
        x509_parser::extensions::GeneralName::DNSName(d) => d
            .strip_suffix(&format!(".{CELL_DOMAIN}"))
            .filter(|s| crate::cell::valid_service_name(s))
            .map(str::to_string),
        _ => None,
    })
}
