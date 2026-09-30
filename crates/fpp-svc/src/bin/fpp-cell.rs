//! fpp-cell: set up a development cell.
//!
//!     fpp-cell init <dir> [service...]
//!
//! Issues a CA and a TLS identity for each service (default: all of them)
//! into `<dir>`. The CA's private key is not kept.

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

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (Some("init"), Some(dir)) = (args.first().map(String::as_str), args.get(1)) else {
        eprintln!("usage: fpp-cell init <dir> [service...]");
        std::process::exit(2);
    };
    let chosen: Vec<&str> = if args.len() > 2 {
        args[2..].iter().map(String::as_str).collect()
    } else {
        SERVICES.to_vec()
    };
    let ids = fpp_svc::cell::init(std::path::Path::new(dir), &chosen)?;
    for id in ids {
        println!("{}.{}", id.name, fpp_svc::CELL_DOMAIN);
    }
    Ok(())
}
