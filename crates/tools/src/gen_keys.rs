use common::pki::DevPki;
use ed25519_dalek::SigningKey;
use std::fs::{self, File};
use std::io::Write;

fn main() {
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let pk = sk.verifying_key();
    fs::create_dir_all("keys").unwrap();

    File::create("keys/vs_ed25519.pk8")
        .unwrap()
        .write_all(&sk.to_bytes())
        .unwrap();
    File::create("keys/vs_ed25519.pub")
        .unwrap()
        .write_all(&pk.to_bytes())
        .unwrap();

    println!("Generated keys: keys/vs_ed25519.pk8 + .pub");

    // Public role keys (Verifier, Broker, Server Liveness) derived from the VS seed.
    common::keys::ServiceKeys::derive(&sk.to_bytes())
        .bundle()
        .save(common::keys::DEFAULT_BUNDLE)
        .expect("write key bundle");
    println!("Generated key bundle: {}", common::keys::DEFAULT_BUNDLE);

    // Dev CA + VS/GS TLS certificates; every QUIC link verifies against the CA.
    DevPki::generate()
        .and_then(|pki| pki.write_to("keys"))
        .expect("generate dev PKI");
    println!(
        "Generated dev PKI: keys/dev_ca.der, keys/vs_tls.{{der,key.der}}, keys/gs_tls.{{der,key.der}}"
    );
}
