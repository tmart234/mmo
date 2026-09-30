//! gen_keys: the development keys of a local cell.
//!
//! - `keys/`: a dev CA and a public TLS certificate for each service
//!   (Server Liveness, the Verifier, the Broker) and the GS client port.
//! - `cell/`: the cell's CA and each service's cell identity (mutual TLS).
//!
//! Each service makes its own signing key in `cell/<service>/` on first
//! start; the key bundle (`keys/fpp_key_bundle.json`) is gathered from what
//! they publish (`fpp-cell bundle cell`, or `tools::cell::Cell::start`).

fn main() -> anyhow::Result<()> {
    tools::cell::ensure_dev_keys()?;
    println!("dev keys ready: keys/ (public TLS), cell/ (cell identities)");
    Ok(())
}
