//! `include/fpp.h` is generated from the Rust source and committed, so C/C++
//! games can vendor it. This test fails if it is stale.
//! Regenerate with `FPP_REGEN_HEADER=1 cargo test -p fpp-ffi --test header`.

use std::path::PathBuf;

#[test]
fn header_is_up_to_date() {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let config = cbindgen::Config::from_file(crate_dir.join("cbindgen.toml")).unwrap();
    let mut generated = Vec::new();
    cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
        .expect("cbindgen")
        .write(&mut generated);
    let generated = String::from_utf8(generated).unwrap();
    let path = crate_dir.join("include/fpp.h");
    if std::env::var_os("FPP_REGEN_HEADER").is_some() {
        std::fs::write(&path, &generated).unwrap();
    }
    let committed = std::fs::read_to_string(&path).expect("include/fpp.h missing; regenerate");
    assert!(
        committed == generated,
        "include/fpp.h is stale; regenerate with FPP_REGEN_HEADER=1"
    );
}
