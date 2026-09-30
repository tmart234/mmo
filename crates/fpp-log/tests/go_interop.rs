//! The log checked by Go's golang.org/x/mod/sumdb (an independent
//! implementation of the same formats): `interop/go/tlog`. Needs Go;
//! skipped without it unless FPP_REQUIRE_GO is set (CI sets it).

use std::process::Command;

use fpp_crypto::hybrid::HybridSigner;
use fpp_log::{b64, Log};

#[test]
fn go_verifies_checkpoint_tiles_entries_and_proofs() {
    let go = Command::new("go")
        .arg("version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !go {
        assert!(
            std::env::var_os("FPP_REQUIRE_GO").is_none(),
            "FPP_REQUIRE_GO is set and go is missing"
        );
        eprintln!("go missing: skipped");
        return;
    }
    let dir = std::env::temp_dir().join(format!("fpp-log-go-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let key = HybridSigner::from_seeds(&[4; 32], &[5; 32]).unwrap();
    let mut log = Log::open(&dir, "fpp.test/go-interop", key, 60).unwrap();
    // several batches, across level-0 and level-1 tile boundaries
    let mut next = 0usize;
    for n in [1usize, 300, 255, 66_000] {
        let batch: Vec<Vec<u8>> = (next..next + n)
            .map(|i| format!("entry {i}\n").into_bytes())
            .collect();
        log.append_without_receipts(&batch).unwrap();
        next += n;
    }
    let root = env!("CARGO_MANIFEST_DIR");
    let out = Command::new("go")
        .args(["run", "."])
        .arg("-dir")
        .arg(&dir)
        .args([
            "-origin",
            "fpp.test/go-interop",
            "-key",
            &b64::encode(&log.public_key()),
        ])
        .current_dir(format!("{root}/../../interop/go/tlog"))
        .env("GOTOOLCHAIN", "local")
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).starts_with(&format!("ok: {next} entries")));
}
