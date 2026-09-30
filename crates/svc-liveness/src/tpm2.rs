//! Game-server admission with a real TPM 2.0 (findings F05, F06, F21), on
//! `attest-tpm`. Pure functions; the network round trip is in
//! `admission.rs`.
//!
//! 1. The EK certificate chains to a TPM manufacturer root Server Liveness pins, and
//!    certifies the EK the GS presents.
//! 2. The quote verifies with the AK, over this connection's challenge and
//!    this exact JoinRequest; the boot log (if any) and the IMA log replay
//!    to the quoted PCRs.
//! 3. The build: the program the kernel measured at `gs_program_path` is in
//!    the Build Registry, and the GS's own `sw_hash` claims the same build.
//! 4. Credential activation: Server Liveness encrypts a fresh secret to the EK, for
//!    the AK's Name; only the TPM holding both can return it. This is what
//!    makes the AK a genuine TPM's, so step 2's quote means something.

use crate::config::LivenessConfig;
use anyhow::{anyhow, bail, Context, Result};
use attest_tpm::{appraise, make_credential, verify_ek, Evidence, Policy, Public, Registry};
use common::proto::{CredentialChallenge, Tpm2Evidence};
use common::tpm::join_quote_nonce;
use rand::{rngs::OsRng, RngCore};

/// What admission established, and the credential the GS must open.
#[derive(Debug)]
pub struct Tpm2Admission {
    /// SHA-256 of the EK public area: the machine's hardware identity.
    pub ek_digest: [u8; 32],
    /// The build the kernel measured, and its registry label, when Server Liveness
    /// has a registry.
    pub build: Option<([u8; 32], String)>,
    pub secure_boot: Option<bool>,
    pub challenge: CredentialChallenge,
    pub secret: Vec<u8>,
}

pub fn registry(cfg: &LivenessConfig) -> Registry {
    Registry {
        builds: cfg
            .build_registry
            .iter()
            .map(|(hash, label)| (hash.to_vec(), label.clone()))
            .collect(),
    }
}

/// Steps 1–3, and the credential for step 4.
pub fn appraise_join(
    cfg: &LivenessConfig,
    challenge: &[u8; 32],
    join_sign_bytes: &[u8],
    claimed_sw_hash: &[u8; 32],
    evidence: &Tpm2Evidence,
    now_unix: i64,
) -> Result<Tpm2Admission> {
    if cfg.tpm_ek_roots.is_empty() {
        bail!("no TPM manufacturer roots configured (--tpm-ek-roots)");
    }
    let ek = Public::from_tpm2b(&evidence.ek_public).map_err(|e| anyhow!("EK public area: {e}"))?;
    let endorsement = verify_ek(&ek, &evidence.ek_chain, &cfg.tpm_ek_roots, Some(now_unix))
        .map_err(|e| anyhow!("EK certificate: {e}"))?;
    let ak = Public::from_tpm2b(&evidence.ak_public).map_err(|e| anyhow!("AK public area: {e}"))?;

    let registry = registry(cfg);
    let policy = Policy {
        registry: &registry,
        program: (!cfg.build_registry.is_empty()).then_some(cfg.gs_program_path.as_str()),
        require_secure_boot: cfg.require_secure_boot,
        allow_ima_violations: false,
    };
    let appraisal = appraise(
        &ak,
        &Evidence {
            attest: evidence.attest.clone(),
            signature: evidence.signature.clone(),
            pcrs: evidence.pcrs.clone(),
            boot_log: evidence.boot_log.clone(),
            ima_log: evidence.ima_log.clone(),
        },
        &join_quote_nonce(challenge, join_sign_bytes),
        &policy,
    )
    .map_err(|e| anyhow!("TPM evidence: {e}"))?;

    let build = match appraisal.program {
        Some((hash, label)) => {
            let hash: [u8; 32] = hash.try_into().map_err(|_| anyhow!("measured hash size"))?;
            // (a GS that says it runs another build than it runs is lying
            // about something)
            if &hash != claimed_sw_hash {
                bail!(
                    "GS reports build {} but the kernel measured {}",
                    hex::encode(claimed_sw_hash),
                    hex::encode(hash)
                );
            }
            Some((hash, label))
        }
        None => None,
    };

    let mut secret = vec![0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let name = ak.name().map_err(|e| anyhow!("AK name: {e}"))?;
    let credential =
        make_credential(&ek, &name, &secret).map_err(|e| anyhow!("credential: {e}"))?;
    Ok(Tpm2Admission {
        ek_digest: endorsement.ek_digest,
        build,
        secure_boot: appraisal.secure_boot,
        challenge: CredentialChallenge {
            id_object: credential.id_object,
            encrypted_secret: credential.encrypted_secret,
        },
        secret,
    })
}

/// Step 4: the GS's answer is the secret (compared in constant time).
pub fn check_activation(admission: &Tpm2Admission, answer: &[u8]) -> Result<()> {
    let same = admission.secret.len() == answer.len()
        && admission
            .secret
            .iter()
            .zip(answer)
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0;
    if !same {
        bail!("credential activation failed: the AK is not in the TPM that holds the certified EK");
    }
    Ok(())
}

/// Load the TPM options: manufacturer roots (PEM bundle) and the Build
/// Registry (`sha256sum` lines).
pub fn load_options(
    cfg: &mut LivenessConfig,
    ek_roots: Option<&std::path::Path>,
    build_registry: Option<&std::path::Path>,
) -> Result<()> {
    if let Some(path) = ek_roots {
        let pem =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        cfg.tpm_ek_roots = attest_core::x509::pem_certificates(&pem)
            .map_err(|e| anyhow!("--tpm-ek-roots: {e}"))?;
    }
    if let Some(path) = build_registry {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let registry = Registry::parse(&text).map_err(|e| anyhow!("--build-registry: {e}"))?;
        cfg.build_registry = registry
            .builds
            .into_iter()
            .map(|(hash, label)| {
                Ok((
                    hash.try_into().map_err(|_| anyhow!("registry hash"))?,
                    label,
                ))
            })
            .collect::<Result<_>>()?;
    }
    Ok(())
}

/// A game server with a real TPM 2.0 (swtpm) joins over QUIC: EK chain,
/// quote, IMA log, Build Registry and credential activation, end to end,
/// with the lies a modified or impersonating server would tell. Needs
/// swtpm and tpm2-tools (skipped without, unless FPP_REQUIRE_SWTPM is set).
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctx::Ctx;
    use attest_tpm::ima::ima_ng_record;
    use common::crypto::{join_request_sign_bytes, now_ms, sign};
    use common::framing::{recv_msg, send_msg, send_msg_continue};
    use common::pki;
    use common::proto::{CredentialResponse, JoinAccept, JoinRequest};
    use ed25519_dalek::SigningKey;
    use gs_sim::tpm2::{swtpm::Swtpm, Tpm2, Tpm2Options};
    use sha2::{Digest, Sha256};

    const PROGRAM: &str = crate::config::DEFAULT_GS_PROGRAM_PATH;

    fn available() -> bool {
        let found = gs_sim::tpm2::swtpm::available();
        assert!(
            found || std::env::var_os("FPP_REQUIRE_SWTPM").is_none(),
            "FPP_REQUIRE_SWTPM is set, and swtpm or tpm2-tools is missing"
        );
        found
    }

    fn sha256(v: &[u8]) -> [u8; 32] {
        Sha256::digest(v).into()
    }

    fn pem(path: &std::path::Path) -> Vec<Vec<u8>> {
        attest_core::x509::pem_certificates(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    /// How the GS side behaves.
    #[derive(Clone, Copy, PartialEq)]
    enum Gs {
        Honest,
        /// claims another build than it runs
        ClaimsOtherBuild,
        /// sends no TPM 2.0 evidence
        NoEvidence,
        /// answers the credential with a guess
        GuessesSecret,
    }

    /// One join against Server Liveness with `config`: its verdict, and the GS's
    /// JoinAccept if admitted.
    async fn join(
        config: LivenessConfig,
        tpm: &Tpm2,
        running: [u8; 32],
        gs: Gs,
    ) -> (Result<()>, Option<JoinAccept>) {
        let dev = pki::DevPki::generate().unwrap();
        let server = quinn::Endpoint::server(
            pki::quic_server_config(dev.service("liveness")).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let addr = server.local_addr().unwrap();
        let ctx = Ctx::new(
            fpp_crypto::Ed25519Signer::new(SigningKey::from_bytes(&[3; 32])),
            config,
        );
        let vs = tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            let verdict = crate::admission::admit_and_run(incoming, ctx).await;
            (verdict, server)
        });

        let accepted = async {
            let o =
                common::admission::request_challenge(&dev.ca_cert_der, addr, "liveness").await?;
            let (mut send, mut recv, challenge) = (o.send, o.recv, o.challenge);
            let gs_key = SigningKey::from_bytes(&[8; 32]);
            let sw_hash = if gs == Gs::ClaimsOtherBuild {
                sha256(b"another build")
            } else {
                running
            };
            let instance = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
            let (now, nonce, noise, game_addr) = (
                now_ms(),
                [1u8; 16],
                [2u8; 32],
                "127.0.0.1:50000".to_string(),
            );
            let to_sign = join_request_sign_bytes(
                "gs-test", &sw_hash, now, &nonce, &instance, &noise, &game_addr,
            );
            let evidence = tpm.evidence(&join_quote_nonce(&challenge, &to_sign))?;
            let jr = JoinRequest {
                gs_id: "gs-test".into(),
                sw_hash,
                t_unix_ms: now,
                nonce,
                ephemeral_pub: instance,
                noise_static: noise,
                game_addr,
                sig_gs: sign(&gs_key, &to_sign).to_vec(),
                gs_pub: gs_key.verifying_key().to_bytes(),
                tpm2: (gs != Gs::NoEvidence).then_some(evidence),
            };
            if gs == Gs::NoEvidence {
                send_msg(&mut send, &jr).await?;
            } else {
                send_msg_continue(&mut send, &jr).await?;
                let credential: CredentialChallenge = recv_msg(&mut recv).await?;
                let secret = if gs == Gs::GuessesSecret {
                    vec![0u8; 32]
                } else {
                    tpm.activate(&credential)?
                };
                send_msg(&mut send, &CredentialResponse { secret }).await?;
            }
            anyhow::Ok(recv_msg::<JoinAccept>(&mut recv).await?)
        }
        .await;
        let (verdict, _server) = vs.await.unwrap();
        (verdict, accepted.ok())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_game_server_is_its_measured_registered_build() {
        if !available() {
            return;
        }
        let dir = std::env::temp_dir().join(format!("vs-tpm2-{}", std::process::id()));
        let swtpm = Swtpm::start(dir.join("swtpm")).unwrap();

        // the kernel measured a shell and the GS build before running them
        let good = sha256(b"gs-sim release 1.0 built by CI");
        let mut ima_log = Vec::new();
        for (file, path) in [(sha256(b"bash"), "/usr/bin/bash"), (good, PROGRAM)] {
            let (record, extend) = ima_ng_record(&file, path);
            swtpm.extend(10, &extend).unwrap();
            ima_log.extend(record);
        }
        std::fs::write(dir.join("ima.log"), &ima_log).unwrap();
        let tpm = Tpm2::open(Tpm2Options {
            tcti: Some(swtpm.tcti()),
            workdir: dir.join("gs"),
            pcrs: vec![0, 7, 10],
            ek_intermediates: pem(&swtpm.intermediate_pem()),
            boot_log: None,
            ima_log: Some(dir.join("ima.log")),
        })
        .unwrap();

        let config = LivenessConfig {
            tpm_ek_roots: pem(&swtpm.root_pem()),
            build_registry: vec![(good, "gs-sim 1.0 (CI build 42)".into())],
            ..LivenessConfig::default()
        };

        // an honest server: admitted
        let (verdict, accepted) = join(config.clone(), &tpm, good, Gs::Honest).await;
        verdict.unwrap();
        assert!(accepted.is_some());

        // one claiming another build than the kernel measured
        let (verdict, accepted) = join(config.clone(), &tpm, good, Gs::ClaimsOtherBuild).await;
        assert!(format!("{:#}", verdict.unwrap_err()).contains("the kernel measured"));
        assert!(accepted.is_none());

        // one that sends only its own word
        let (verdict, _) = join(config.clone(), &tpm, good, Gs::NoEvidence).await;
        assert!(format!("{:#}", verdict.unwrap_err()).contains("TPM 2.0 evidence required"));

        // one that cannot open the credential (its AK is not in the certified TPM)
        let (verdict, accepted) = join(config.clone(), &tpm, good, Gs::GuessesSecret).await;
        assert!(format!("{:#}", verdict.unwrap_err()).contains("credential activation failed"));
        assert!(accepted.is_none());

        // a build that is not registered
        let unregistered = LivenessConfig {
            build_registry: vec![([7; 32], "other".into())],
            ..config.clone()
        };
        let (verdict, _) = join(unregistered, &tpm, good, Gs::Honest).await;
        assert!(format!("{:#}", verdict.unwrap_err()).contains("not a registered build"));

        // a TPM from a manufacturer Server Liveness does not trust
        let other_manufacturer = pki::DevPki::generate().unwrap().ca_cert_der;
        let untrusted = LivenessConfig {
            tpm_ek_roots: vec![other_manufacturer],
            ..config.clone()
        };
        let (verdict, _) = join(untrusted, &tpm, good, Gs::Honest).await;
        assert!(format!("{:#}", verdict.unwrap_err()).contains("EK certificate"));
        let no_roots = LivenessConfig {
            tpm_ek_roots: vec![],
            ..config.clone()
        };
        let (verdict, _) = join(no_roots, &tpm, good, Gs::Honest).await;
        assert!(verdict.is_err());

        // a modified server that really ran: the log replays, the build is unknown
        let modified = sha256(b"gs-sim with a wallhack");
        let (record, extend) = ima_ng_record(&modified, PROGRAM);
        swtpm.extend(10, &extend).unwrap();
        ima_log.extend(record);
        std::fs::write(dir.join("ima.log"), &ima_log).unwrap();
        let (verdict, _) = join(config.clone(), &tpm, good, Gs::Honest).await;
        assert!(format!("{:#}", verdict.unwrap_err()).contains("not a registered build"));

        drop(swtpm);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
