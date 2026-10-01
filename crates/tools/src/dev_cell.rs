// A development cell on this machine (Server Liveness, the Verifier, the
// Broker, the Revocation Feed, the Transparency Log and its witness, the
// Evidence Store), held up until interrupted, for games to test against:
// the Halo port's verified-playlist test (tools/p2p_loopback_test.py
// --verified) runs its dedicated host and players on one. Keys and the
// cell's state are under keys/ and cell/ in the working directory; the
// key bundle players and game servers trust is keys/fpp_key_bundle.json.
// Stop it with SIGINT (Ctrl-C), which stops its services with it.

use anyhow::{Context, Result};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use tools::cell::{ensure_dev_keys, Cell, Launch};

fn main() -> Result<()> {
    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        ctrlc::set_handler(move || stop.store(true, Ordering::SeqCst))
            .context("install the interrupt handler")?;
    }
    ensure_dev_keys()?;
    let mut cell = Cell::start(&Launch::from_env("debug"))?;
    println!(
        "[dev-cell] ready; key bundle at {}",
        common::keys::DEFAULT_BUNDLE
    );
    while !stop.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(200));
        cell.check_running()?;
    }
    println!("[dev-cell] stopping");
    Ok(())
}
