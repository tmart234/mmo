//! fpp-cell: set up a development cell.
//!
//!     fpp-cell init <dir> [service...]
//!     fpp-cell bundle <dir> [out]
//!
//! `init` issues a CA and a TLS identity for each service (default: all of
//! them) into `<dir>`. The CA's private key is not kept.
//!
//! `bundle` gathers the public keys the Verifier, the Broker, Server
//! Liveness, the Transparency Log and its witness published in `<dir>` (each
//! makes its own key on first start) into the key bundle clients and game
//! servers trust (default `keys/fpp_key_bundle.json`). It fails until the
//! log and a witness have published theirs: players count only cosigned
//! checkpoints.

use anyhow::{ensure, Result};
use std::path::Path;

const SERVICES: &[&str] = &[
    "verifier",
    "broker",
    "liveness",
    "revocation",
    "log",
    "witness",
    "evidence",
    "enforcement",
];

fn usage() -> ! {
    eprintln!("usage: fpp-cell init <dir> [service...]\n       fpp-cell bundle <dir> [out]");
    std::process::exit(2);
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (Some(cmd), Some(dir)) = (args.first().map(String::as_str), args.get(1)) else {
        usage();
    };
    let dir = Path::new(dir);
    match cmd {
        "init" => {
            let chosen: Vec<&str> = if args.len() > 2 {
                args[2..].iter().map(String::as_str).collect()
            } else {
                SERVICES.to_vec()
            };
            for id in fpp_svc::cell::init(dir, &chosen)? {
                println!("{}.{}", id.name, fpp_svc::CELL_DOMAIN);
            }
        }
        "bundle" => {
            let out = args
                .get(2)
                .map(String::as_str)
                .unwrap_or(common::keys::DEFAULT_BUNDLE);
            let bundle = fpp_svc::keys::bundle(dir)?;
            ensure!(
                bundle.log.as_ref().is_some_and(|l| !l.witnesses.is_empty()),
                "the Transparency Log and a witness have not published their keys yet"
            );
            if let Some(parent) = Path::new(out).parent() {
                std::fs::create_dir_all(parent)?;
            }
            bundle.save(out)?;
            println!("key bundle: {out}");
        }
        _ => usage(),
    }
    Ok(())
}
