//! Server Liveness (04 §6.3): admits game servers on their TPM 2.0
//! evidence, keeps each one's SAR chain going while it checkpoints, and
//! stops it when it misbehaves or goes quiet. It holds only its own key
//! (Server Liveness role); clients are the Verifier's and the Broker's.
//!
//! - `admission`: the GS's join (challenge, JoinRequest, TPM 2.0)
//! - `tpm2`: TPM 2.0 evidence: EK chain, quote, logs, Build Registry,
//!   credential activation (attest-tpm)
//! - `liveness`: the SAR chain per game server
//! - `checkpoints`: Checkpoint verification and evidence storage
//! - `watchdog`: revoke when Checkpoints stop
//! - `placement`: the cell API the Broker places players with

pub mod admission;
pub mod checkpoints;
pub mod config;
pub mod ctx;
pub mod liveness;
pub mod placement;
pub mod tpm2;
pub mod watchdog;

use anyhow::Result;
use std::net::SocketAddr;
use std::path::Path;

/// Start Server Liveness with the key in `cell`: game servers on `public`
/// (presenting `identity`), the cell API on `rpc` for `callers`.
pub fn start(
    cell: &Path,
    identity: &common::pki::ServerIdentity,
    public: SocketAddr,
    rpc: SocketAddr,
    callers: Vec<String>,
    config: config::LivenessConfig,
) -> Result<ctx::Ctx> {
    let key = fpp_svc::keys::ed25519(cell, "liveness", liveness::LIVENESS_ISS)?;
    let ctx = ctx::Ctx::new(fpp_crypto::Ed25519Signer::new(key), config);
    let cell_endpoint =
        fpp_svc::mtls::server_endpoint(&fpp_svc::cell::load(cell, "liveness")?, rpc)?;
    let public_endpoint = common::admission::server_endpoint(identity, public)?;
    tokio::spawn(placement::serve(cell_endpoint, ctx.clone(), callers));
    let c = ctx.clone();
    tokio::spawn(common::admission::serve(
        public_endpoint,
        "liveness",
        move |incoming| admission::admit_and_run(incoming, c.clone()),
    ));
    Ok(ctx)
}
