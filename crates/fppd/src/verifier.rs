//! The Verifier role (04 §5.1): appraises client platform evidence
//! (TPM 2.0 via `fpp-attest::tpm::verify`, and optionally Android KeyMint /
//! Play Integrity and Apple App Attest under the `mobile` feature) and signs
//! an Attestation Result bound to the client's session key.
//!
//! Uses ONLY its isolated Verifier signing key (`KeyRole::VerifierAr`).

use anyhow::{anyhow, Result};
use fpp::control::{
    evidence_request_sign_bytes, CredentialChallenge, EvidenceAnswer, EvidenceRequest,
};
use fpp::crypto::{self, now_s, tagged_hash, Ed25519Signer};
use fpp::tokens::{AttestationResult, Features};
use fpp::types::{BuildId, DeviceTier, Did, Reason, SessionKey};
use fpp_attest::tpm::verify::{appraise_pc_client, Activation};
#[cfg(feature = "mobile")]
use fpp_attest::{
    android::{self, integrity::IntegrityKeys, AllowedApp, AndroidPolicy},
    apple::{self, AppKey, ApplePolicy},
    attest_challenge, AttestError,
};
use fpp_attest::{device_tier, Claims, Evidence, KeyStorage};
use rand::{rngs::OsRng, RngCore};
use std::collections::HashMap;
#[cfg(feature = "mobile")]
use std::sync::Mutex;
use std::time::Duration;

pub const VERIFIER_ISS: &str = "ver.dev";
pub const POLICY_VER: u64 = 1;
pub const AR_LIFETIME_S: u64 = 1800;
#[cfg(feature = "mobile")]
pub const INTEGRITY_MAX_AGE_MS: u64 = 10 * 60 * 1000;

/// Client Build Registry: `(app_id, version) -> build_id`.
#[derive(Clone, Debug, Default)]
pub struct ClientBuilds {
    pub builds: HashMap<(String, u64), [u8; 32]>,
}

impl ClientBuilds {
    pub fn parse(text: &str) -> Result<Self> {
        let mut builds = HashMap::new();
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let f: Vec<&str> = line.split_whitespace().collect();
            let [id, app, version] = f.as_slice() else {
                anyhow::bail!("client build line: {line}");
            };
            let id: [u8; 32] = hex::decode(id)?
                .try_into()
                .map_err(|_| anyhow!("build id must be 32 bytes: {line}"))?;
            builds.insert((app.to_string(), version.parse()?), id);
        }
        Ok(Self { builds })
    }
}

/// Attestation policy configured on the Verifier.
#[derive(Default)]
pub struct ClientAttestation {
    pub tpm_ek_roots: Vec<Vec<u8>>,
    pub client_builds: ClientBuilds,
    #[cfg(feature = "mobile")]
    pub android: Option<AndroidPolicy>,
    #[cfg(feature = "mobile")]
    pub apple: Option<ApplePolicy>,
    #[cfg(feature = "mobile")]
    pub apple_keys: Mutex<HashMap<[u8; 32], AppKey>>,
    #[cfg(feature = "mobile")]
    pub play_integrity: Option<IntegrityKeys>,
}

#[cfg(feature = "mobile")]
impl ClientAttestation {
    pub fn from_mobile_options(
        android_apps: &[String],
        android_status: Option<&str>,
        apple_app_ids: &[String],
        apple_allow_development: bool,
    ) -> Result<Self> {
        let android = if android_apps.is_empty() {
            None
        } else {
            let mut apps: Vec<AllowedApp> = Vec::new();
            for spec in android_apps {
                let (package, digest) = spec
                    .split_once(':')
                    .ok_or_else(|| anyhow!("--android-app wants package:sha256hex, got {spec}"))?;
                let digest: [u8; 32] = hex::decode(digest.replace(':', ""))?
                    .try_into()
                    .map_err(|_| anyhow!("--android-app digest must be 32 bytes"))?;
                match apps.iter_mut().find(|a| a.package == package) {
                    Some(a) => a.signer_sha256.push(digest),
                    None => apps.push(AllowedApp {
                        package: package.to_string(),
                        signer_sha256: vec![digest],
                    }),
                }
            }
            let mut policy = AndroidPolicy::production(apps);
            if let Some(json) = android_status {
                policy.revoked = android::parse_status_list(json)?;
            }
            Some(policy)
        };
        let apple = if apple_app_ids.is_empty() {
            None
        } else {
            let mut policy = ApplePolicy::production(apple_app_ids.to_vec());
            policy.allow_development = apple_allow_development;
            Some(policy)
        };
        Ok(Self {
            android,
            apple,
            apple_keys: Mutex::new(HashMap::new()),
            tpm_ek_roots: Vec::new(),
            play_integrity: None,
            client_builds: ClientBuilds::default(),
        })
    }
}

pub struct Appraised {
    pub platform: Option<&'static str>,
    pub tier: DeviceTier,
    pub features: Features,
    pub identity: Option<Vec<u8>>,
    pub client_build: Option<[u8; 32]>,
    pub warnings: Vec<String>,
}

fn unrooted(warning: String) -> Appraised {
    Appraised {
        platform: None,
        tier: DeviceTier::D0Unknown,
        features: Features::default(),
        identity: None,
        client_build: None,
        warnings: vec![warning],
    }
}

fn now_unix_and_yyyymm() -> (i64, u32) {
    let secs = now_s() as i64;
    let z = secs.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (secs, (year * 100 + month) as u32)
}

fn build_features(c: &Claims, strong_integrity: Option<bool>, now_yyyymm: u32) -> Features {
    Features {
        secure_boot: c.verified_boot,
        measured_boot: c.boot.measured_boot,
        vbs: c.boot.vbs,
        hvci: c.boot.hvci,
        iommu: c.boot.iommu,
        key_in_hw: Some(c.session_key_in_hw),
        app_attested: Some(c.app_attested),
        strongbox: (c.key_storage == KeyStorage::StrongBox).then_some(true),
        strong_integrity,
        os_patch_age_days: c
            .os_patch_level
            .map(|p| u64::from(fpp_attest::patch_age_months(p, now_yyyymm)) * 30),
        ..Features::default()
    }
}

struct Assessed {
    claims: Claims,
    max_tier: DeviceTier,
    strong_integrity: Option<bool>,
}

impl Assessed {
    fn of(claims: Claims) -> Self {
        Self {
            claims,
            max_tier: DeviceTier::D3Hardened,
            strong_integrity: None,
        }
    }

    fn cap(&mut self, tier: DeviceTier, warning: String) {
        self.max_tier = self.max_tier.min(tier);
        self.claims.warnings.push(warning);
    }
}

fn finish(
    cfg: &ClientAttestation,
    mut a: Assessed,
    claimed_build: &[u8; 32],
    now_yyyymm: u32,
) -> Appraised {
    let mut client_build = None;
    if !cfg.client_builds.builds.is_empty() {
        match &a.claims.app {
            Some(app) => match cfg.client_builds.builds.get(&(app.id.clone(), app.version)) {
                Some(id) => {
                    if id != claimed_build {
                        a.claims.warnings.push("build-claim-differs".into());
                    }
                    client_build = Some(*id);
                }
                None => a.cap(
                    DeviceTier::D1Software,
                    format!("build-unregistered: {} {}", app.id, app.version),
                ),
            },
            None => a.claims.warnings.push("build-not-attested".into()),
        }
    }
    Appraised {
        platform: Some(a.claims.platform),
        tier: device_tier(&a.claims).min(a.max_tier),
        features: build_features(&a.claims, a.strong_integrity, now_yyyymm),
        identity: a.claims.hardware_identity.clone(),
        client_build,
        warnings: a.claims.warnings,
    }
}

#[cfg(feature = "mobile")]
fn appraise_mobile(
    cfg: &ClientAttestation,
    evidence: Evidence,
    verifier_challenge: &[u8; 32],
    session_pub: &[u8],
    now_unix: i64,
    now_yyyymm: u32,
) -> Result<Assessed, AttestError> {
    let challenge = &attest_challenge(verifier_challenge, session_pub);
    match evidence {
        Evidence::AndroidKey { chain, integrity } => {
            let policy = cfg
                .android
                .as_ref()
                .ok_or(AttestError::Policy("no Android policy on this Verifier"))?;
            let claims = android::appraise(
                &chain,
                verifier_challenge,
                session_pub,
                policy,
                now_unix,
                now_yyyymm,
            )?;
            let mut a = Assessed::of(claims);
            if let Some(keys) = &cfg.play_integrity {
                match integrity.as_deref() {
                    None => a.cap(DeviceTier::D1Software, "no-play-integrity".into()),
                    Some(token) => {
                        let now_ms = (now_unix.max(0) as u64) * 1000;
                        match android::integrity::verify(
                            token,
                            keys,
                            challenge,
                            &policy.apps,
                            now_ms,
                            INTEGRITY_MAX_AGE_MS,
                        ) {
                            Ok(v) => {
                                a.strong_integrity = Some(v.strong);
                                if !v.device {
                                    a.claims.verified_boot = Some(false);
                                    a.claims.warnings.push("device-integrity-failed".into());
                                } else if !v.strong {
                                    a.cap(DeviceTier::D1Software, "integrity-not-strong".into());
                                }
                                if let (Some(app), Some(code)) = (&a.claims.app, v.version_code) {
                                    if app.version != code {
                                        a.cap(
                                            DeviceTier::D0Unknown,
                                            "play-integrity-version-differs".into(),
                                        );
                                    }
                                }
                            }
                            Err(e) => a.cap(
                                DeviceTier::D1Software,
                                format!("play-integrity-rejected: {e}"),
                            ),
                        }
                    }
                }
            }
            Ok(a)
        }
        Evidence::AppleAppAttest { attestation } => {
            let policy = cfg
                .apple
                .as_ref()
                .ok_or(AttestError::Policy("no Apple policy on this Verifier"))?;
            let (claims, key) =
                apple::appraise_attestation(&attestation, challenge, policy, now_unix)?;
            cfg.apple_keys
                .lock()
                .expect("apple_keys")
                .insert(key.key_id, key);
            Ok(Assessed::of(claims))
        }
        Evidence::AppleAppAssert { key_id, assertion } => {
            let policy = cfg
                .apple
                .as_ref()
                .ok_or(AttestError::Policy("no Apple policy on this Verifier"))?;
            let key_id: [u8; 32] = key_id
                .try_into()
                .map_err(|_| AttestError::Envelope("key_id"))?;
            let mut map = cfg.apple_keys.lock().expect("apple_keys");
            let key = map.get_mut(&key_id).ok_or(AttestError::Policy(
                "unknown App Attest key: attest it first",
            ))?;
            apple::appraise_assertion(&assertion, challenge, key, policy).map(Assessed::of)
        }
        Evidence::Tpm(_) => Err(AttestError::Envelope("tpm")),
    }
}

pub enum VerifierStep {
    Answer(EvidenceAnswer),
    Activate(CredentialChallenge, Box<PendingAr>),
}

pub struct PendingAr {
    challenge: [u8; 32],
    req: EvidenceRequest,
    session_key: SessionKey,
    appraised: Appraised,
    activation: Activation,
}

pub struct VerifierRole {
    pub key: Ed25519Signer,
    pub attestation: ClientAttestation,
    pub deadline: Duration,
}

fn refuse(reason: Reason) -> EvidenceAnswer {
    EvidenceAnswer::Refused {
        code: reason as u16,
    }
}

impl VerifierRole {
    pub fn answer(&self, challenge: &[u8; 32], req: &EvidenceRequest) -> VerifierStep {
        let Some(session_key) = SessionKey::from_bytes(&req.session_pub) else {
            return VerifierStep::Answer(refuse(Reason::PopInvalid));
        };
        let msg = evidence_request_sign_bytes(
            challenge,
            &req.session_pub,
            &req.platform,
            &req.client_build,
            &req.evidence,
        );
        if !crypto::verify_session_raw(&session_key, &msg, &req.pop_sig) {
            return VerifierStep::Answer(refuse(Reason::PopInvalid));
        }
        if req.platform.is_empty() || req.platform.len() > 32 {
            return VerifierStep::Answer(refuse(Reason::ArInvalid));
        }

        let evidence = match Evidence::decode(&req.evidence) {
            Ok(Some(e)) => e,
            Ok(None) => {
                return VerifierStep::Answer(self.issue(
                    challenge,
                    req,
                    session_key,
                    unrooted("no-platform-evidence".into()),
                ))
            }
            Err(e) => {
                return VerifierStep::Answer(self.issue(
                    challenge,
                    req,
                    session_key,
                    unrooted(format!("evidence-rejected: {e}")),
                ))
            }
        };

        let (now_unix, now_yyyymm) = now_unix_and_yyyymm();
        let session_pub = session_key.to_bytes();

        if let Evidence::Tpm(t) = &evidence {
            return match appraise_pc_client(
                &self.attestation.tpm_ek_roots,
                t,
                challenge,
                &session_pub,
                now_unix,
            ) {
                Ok((claims, activation)) => {
                    let appraised = finish(
                        &self.attestation,
                        Assessed::of(claims),
                        &req.client_build,
                        now_yyyymm,
                    );
                    let cred = activation.challenge.clone();
                    VerifierStep::Activate(
                        cred,
                        Box::new(PendingAr {
                            challenge: *challenge,
                            req: req.clone(),
                            session_key,
                            appraised,
                            activation,
                        }),
                    )
                }
                Err(e) => VerifierStep::Answer(self.issue(
                    challenge,
                    req,
                    session_key,
                    unrooted(format!("evidence-rejected: {e}")),
                )),
            };
        }

        #[cfg(feature = "mobile")]
        let appraised = match appraise_mobile(
            &self.attestation,
            evidence,
            challenge,
            &session_pub,
            now_unix,
            now_yyyymm,
        ) {
            Ok(a) => finish(&self.attestation, a, &req.client_build, now_yyyymm),
            Err(e) => unrooted(format!("evidence-rejected: {e}")),
        };
        #[cfg(not(feature = "mobile"))]
        let appraised = {
            let _ = (evidence, now_unix, now_yyyymm, session_pub);
            unrooted("evidence-rejected: mobile attestation disabled on this verifier".into())
        };

        VerifierStep::Answer(self.issue(challenge, req, session_key, appraised))
    }

    pub fn activated(&self, pending: PendingAr, secret: &[u8]) -> EvidenceAnswer {
        let appraised = if pending.activation.opened(secret) {
            pending.appraised
        } else {
            unrooted("evidence-rejected: credential activation failed".into())
        };
        self.issue(
            &pending.challenge,
            &pending.req,
            pending.session_key,
            appraised,
        )
    }

    fn issue(
        &self,
        challenge: &[u8; 32],
        req: &EvidenceRequest,
        session_key: SessionKey,
        appraised: Appraised,
    ) -> EvidenceAnswer {
        let did = match &appraised.identity {
            Some(id) => Did(tagged_hash("mmo/dev-did-hw", id)),
            None => Did(tagged_hash("mmo/dev-did", &req.session_pub)),
        };
        let mut cti = [0u8; 16];
        OsRng.fill_bytes(&mut cti);
        let now = now_s();
        let ar = AttestationResult {
            iss: VERIFIER_ISS.into(),
            iat: now,
            exp: now + AR_LIFETIME_S,
            cti,
            cnf: session_key,
            nonce: *challenge,
            did,
            tier: appraised.tier,
            features: appraised.features,
            client_build: BuildId(appraised.client_build.unwrap_or(req.client_build)),
            platform: appraised
                .platform
                .map_or_else(|| req.platform.clone(), str::to_string),
            policy_ver: POLICY_VER,
            warnings: appraised.warnings,
        };
        println!(
            "[verifier] AR for ..{}: tier D{}",
            hex::encode(&crypto::session_key_id(&session_key)[..3]),
            ar.tier as u8
        );
        EvidenceAnswer::Ar(crypto::sign(&self.key, &ar))
    }
}
