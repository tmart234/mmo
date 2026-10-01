//! svc-verifier: the Verifier as its own service.

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use svc_verifier::appraisal::ClientAttestation;

#[derive(Parser, Debug)]
struct Opts {
    /// Cell directory: the Verifier's key is made in `<cell>/verifier/`.
    #[arg(long, default_value = "cell")]
    cell: PathBuf,
    /// Public UDP address for clients (QUIC).
    #[arg(long, default_value = "127.0.0.1:4445")]
    bind: std::net::SocketAddr,
    /// TLS certificate (DER) presented to clients; must chain to the CA they pin.
    #[arg(long, default_value = "keys/verifier_tls.der")]
    tls_cert: String,
    /// PKCS#8 private key (DER) for `--tls-cert`.
    #[arg(long, default_value = "keys/verifier_tls.key.der")]
    tls_key: String,

    /// Android app allowed to attest: `package:sha256hex` of its signing
    /// certificate (repeatable). Without one, Android evidence earns D0.
    #[arg(long = "android-app")]
    android_apps: Vec<String>,
    /// Google's attestation status list (JSON from
    /// https://android.googleapis.com/attestation/status); refresh daily.
    #[arg(long)]
    android_status: Option<PathBuf>,
    /// Apple App ID allowed to attest: `TEAMID.bundle.id` (repeatable).
    /// Without one, App Attest evidence earns D0.
    #[arg(long = "apple-app-id")]
    apple_app_ids: Vec<String>,
    /// Accept App Attest keys from Apple's development environment. Never in
    /// production.
    #[arg(long)]
    apple_allow_development: bool,
    /// TPM manufacturers' root certificates (a PEM bundle): a PC's TPM
    /// evidence counts only if its EK certificate chains to one. Without
    /// it, TPM evidence earns D0.
    #[arg(long)]
    tpm_ek_roots: Option<PathBuf>,
    /// The app's Play Integrity response keys from the Play Console: a file
    /// with the decryption key and the verification key (base64), one per
    /// line. Set: Android D2 needs a MEETS_STRONG_INTEGRITY verdict.
    #[arg(long)]
    play_integrity_keys: Option<PathBuf>,
    /// The client Build Registry: lines `<build id hex> <app id> <version>`
    /// (e.g. `android:com.halo.decomp 42`). Set: an attested build must be
    /// in it, and the AR states the registry's build id.
    #[arg(long)]
    client_builds: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let o = Opts::parse();
    let status = o
        .android_status
        .as_ref()
        .map(std::fs::read_to_string)
        .transpose()
        .context("read --android-status")?;
    let mut attestation = ClientAttestation::from_options(
        &o.android_apps,
        status.as_deref(),
        &o.apple_app_ids,
        o.apple_allow_development,
    )?;
    if let Some(path) = &o.play_integrity_keys {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let mut lines = text.lines().filter(|l| !l.trim().is_empty());
        let (Some(decryption), Some(verification)) = (lines.next(), lines.next()) else {
            anyhow::bail!("--play-integrity-keys: two lines (decryption, verification key)");
        };
        attestation.play_integrity = Some(
            attest_android::integrity::IntegrityKeys::from_console(decryption, verification)
                .map_err(|e| anyhow::anyhow!("--play-integrity-keys: {e}"))?,
        );
    }
    if let Some(path) = &o.client_builds {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        attestation.client_builds = svc_verifier::appraisal::ClientBuilds::parse(&text)
            .with_context(|| format!("--client-builds {}", path.display()))?;
    }
    if let Some(path) = &o.tpm_ek_roots {
        let pem =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        attestation.tpm_ek_roots = attest_core::x509::pem_certificates(&pem)
            .map_err(|e| anyhow::anyhow!("--tpm-ek-roots: {e}"))?;
    }
    let on = |b: bool| if b { "on" } else { "off" };
    println!(
        "[verifier] client evidence: android {} (Play Integrity {}), apple {}, TPM {} manufacturer root(s); client Build Registry: {} build(s)",
        on(attestation.android.is_some()),
        on(attestation.play_integrity.is_some()),
        on(attestation.apple.is_some()),
        attestation.tpm_ek_roots.len(),
        attestation.client_builds.builds.len()
    );
    let identity = common::pki::ServerIdentity::load(&o.tls_cert, &o.tls_key)?;
    let (verifier, endpoint) = svc_verifier::start(&o.cell, &identity, o.bind, attestation)?;
    println!(
        "[verifier] key published in {}; listening on {}",
        o.cell.join("public/verifier").display(),
        o.bind
    );
    verifier.serve(endpoint).await;
    Ok(())
}
