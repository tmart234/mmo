//! Verifier appraisal of client platform evidence (roadmap P3, ATT-01..06):
//! `EvidenceRequest.evidence` → Device Trust Tier, feature claims and
//! a hardware-rooted DID where the platform gives one.
//!
//! Formats (attest_core::Evidence): Android key attestation (`attest-android`),
//! Apple App Attest attestations and assertions (`attest-apple`), a PC's
//! TPM 2.0 ([`crate::tpm`], which needs a second round trip: credential
//! activation). All bind to `attest_challenge(verifier_challenge,
//! session_pub)` (an Android key that is itself the session key, to
//! `attest_challenge_hw_key`), so evidence made for another admission or
//! another session key fails. Evidence that fails appraisal is
//! not an error for the client: it is tier D0 with a warning (03 §4.2), and
//! the queue's tier floor decides.

use attest_android::{AllowedApp, AndroidPolicy};
use attest_apple::{AppKey, ApplePolicy};
use attest_core::{attest_challenge, device_tier, AttestError, Claims, Evidence, KeyStorage};
use dashmap::DashMap;
use fpp_tokens::Features;
use fpp_types::{DeviceTier, SessionKey};
use std::time::{SystemTime, UNIX_EPOCH};

/// What the Verifier accepts, set from the command line (`svc-verifier --help`).
#[derive(Default)]
pub struct ClientAttestation {
    pub android: Option<AndroidPolicy>,
    pub apple: Option<ApplePolicy>,
    /// App Attest keys appraised so far, by key id (in memory: a restarted
    /// Verifier asks the app to attest a new key).
    pub apple_keys: DashMap<[u8; 32], AppKey>,
    /// TPM manufacturers' roots (DER): EK certificates must chain to one.
    /// Empty: TPM evidence earns D0.
    pub tpm_ek_roots: Vec<Vec<u8>>,
    /// The app's Play Integrity response keys. Set: Android D2 needs a
    /// `MEETS_STRONG_INTEGRITY` verdict as well as key attestation.
    pub play_integrity: Option<attest_android::integrity::IntegrityKeys>,
    /// The client Build Registry. Empty: builds are self-reported.
    pub client_builds: ClientBuilds,
}

impl ClientAttestation {
    /// `android_apps`: `package:sha256hex` (the signing certificate's digest);
    /// `android_status`: Google's status list JSON, if loaded.
    pub fn from_options(
        android_apps: &[String],
        android_status: Option<&str>,
        apple_app_ids: &[String],
        apple_allow_development: bool,
    ) -> anyhow::Result<Self> {
        let android = if android_apps.is_empty() {
            None
        } else {
            let mut apps: Vec<AllowedApp> = Vec::new();
            for spec in android_apps {
                let (package, digest) = spec.split_once(':').ok_or_else(|| {
                    anyhow::anyhow!("--android-app wants package:sha256hex, got {spec}")
                })?;
                let digest: [u8; 32] = hex::decode(digest.replace(':', ""))?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("--android-app digest must be 32 bytes"))?;
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
                policy.revoked = attest_android::parse_status_list(json)?;
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
        Ok(ClientAttestation {
            android,
            apple,
            apple_keys: DashMap::new(),
            tpm_ek_roots: Vec::new(),
            play_integrity: None,
            client_builds: ClientBuilds::default(),
        })
    }
}

/// The outcome for one admission.
pub struct Appraised {
    /// The platform the evidence proves (`android`, `ios`, `windows`, `pc`),
    /// which the AR states instead of the client's own claim.
    pub platform: Option<&'static str>,
    pub tier: DeviceTier,
    pub features: Features,
    /// Hardware-rooted identity for the DID, when the platform gives one.
    pub identity: Option<Vec<u8>>,
    /// The build the evidence attests (from the client Build Registry),
    /// which the AR states instead of the client's own claim.
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

/// Today as (Unix seconds, `YYYYMM`).
fn now() -> (i64, u32) {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
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

fn features(c: &Claims, strong_integrity: Option<bool>, now_yyyymm: u32) -> Features {
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
            .map(|p| u64::from(attest_core::patch_age_months(p, now_yyyymm)) * 30),
        ..Features::default()
    }
}

/// Claims, and what else bounds the tier.
struct Assessed {
    claims: Claims,
    /// The highest tier the rest of the evidence allows.
    max_tier: DeviceTier,
    /// Play Integrity's `MEETS_STRONG_INTEGRITY`, when a verdict was checked.
    strong_integrity: Option<bool>,
}

impl Assessed {
    fn of(claims: Claims) -> Self {
        Assessed {
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

/// How old a Play Integrity verdict may be.
pub const INTEGRITY_MAX_AGE_MS: u64 = 10 * 60 * 1000;

/// Play Integrity on top of key attestation (03 §4.2: Android D2 is
/// `MEETS_STRONG_INTEGRITY` + key attestation). With response keys
/// configured, a missing or rejected verdict, or one short of strong
/// integrity, caps the device at D1; a device Google does not recognise is
/// D0.
fn play_integrity(
    cfg: &ClientAttestation,
    a: &mut Assessed,
    token: Option<&str>,
    nonce: &[u8; 32],
    now_unix: i64,
) {
    let (Some(keys), Some(policy)) = (&cfg.play_integrity, &cfg.android) else {
        return;
    };
    let Some(token) = token else {
        a.cap(DeviceTier::D1Software, "no-play-integrity".into());
        return;
    };
    let now_ms = (now_unix.max(0) as u64) * 1000;
    match attest_android::integrity::verify(
        token,
        keys,
        nonce,
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
            // (the two attest the same install: the same build)
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

/// The client Build Registry (P3): which attested app versions are builds
/// we made, as `(app id, version) → build id` (`svc-verifier
/// --client-builds`: lines `<build id hex> <app id> <version>`, e.g.
/// `4f…  android:com.halo.decomp 42`).
#[derive(Clone, Debug, Default)]
pub struct ClientBuilds {
    pub builds: std::collections::HashMap<(String, u64), [u8; 32]>,
}

impl ClientBuilds {
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let mut builds = std::collections::HashMap::new();
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
                .map_err(|_| anyhow::anyhow!("build id must be 32 bytes: {line}"))?;
            builds.insert((app.to_string(), version.parse()?), id);
        }
        Ok(ClientBuilds { builds })
    }
}

/// The tier, features, identity and build of assessed evidence. With a
/// client Build Registry, an attested build must be in it (else the device
/// is capped at D1: the binary is not one we built); evidence that attests
/// no build leaves the client's claim, marked as such.
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
        features: features(&a.claims, a.strong_integrity, now_yyyymm),
        identity: a.claims.hardware_identity.clone(),
        client_build,
        warnings: a.claims.warnings,
    }
}

fn appraise_evidence(
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
            let claims = attest_android::appraise(
                &chain,
                verifier_challenge,
                session_pub,
                policy,
                now_unix,
                now_yyyymm,
            )?;
            let mut a = Assessed::of(claims);
            play_integrity(cfg, &mut a, integrity.as_deref(), challenge, now_unix);
            Ok(a)
        }
        Evidence::AppleAppAttest { attestation } => {
            let policy = cfg
                .apple
                .as_ref()
                .ok_or(AttestError::Policy("no Apple policy on this Verifier"))?;
            let (claims, key) =
                attest_apple::appraise_attestation(&attestation, challenge, policy, now_unix)?;
            cfg.apple_keys.insert(key.key_id, key);
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
            let mut key = cfg.apple_keys.get_mut(&key_id).ok_or(AttestError::Policy(
                "unknown App Attest key: attest it first",
            ))?;
            attest_apple::appraise_assertion(&assertion, challenge, &mut key, policy)
                .map(Assessed::of)
        }
        // (appraised in `appraise`: it needs a second round trip)
        Evidence::Tpm(_) => Err(AttestError::Envelope("tpm")),
    }
}

/// What appraisal decided: an AR now, or after credential activation.
pub enum Outcome {
    Done(Appraised),
    /// TPM evidence: `Appraised` holds once the client's TPM opens the
    /// credential; otherwise the client is D0.
    Activate(Appraised, crate::tpm::Activation),
}

/// The outcome when credential activation fails: the AK is not in the TPM
/// that holds the certified EK.
pub fn activation_failed() -> Appraised {
    unrooted("evidence-rejected: credential activation failed".into())
}

/// Appraise an admission's evidence (empty: D0). `claimed_build` is the
/// client's own `client_build`.
pub fn appraise(
    cfg: &ClientAttestation,
    verifier_challenge: &[u8; 32],
    session_key: &SessionKey,
    claimed_build: &[u8; 32],
    evidence: &[u8],
) -> Outcome {
    let evidence = match Evidence::decode(evidence) {
        Ok(Some(e)) => e,
        Ok(None) => return Outcome::Done(unrooted("no-platform-evidence".into())),
        Err(e) => return Outcome::Done(unrooted(format!("evidence-rejected: {e}"))),
    };
    let (now_unix, now_yyyymm) = now();
    let session_pub = session_key.to_bytes();
    if let Evidence::Tpm(t) = &evidence {
        return match crate::tpm::appraise_tpm(
            &cfg.tpm_ek_roots,
            t,
            verifier_challenge,
            &session_pub,
            now_unix,
        ) {
            Ok((claims, activation)) => Outcome::Activate(
                finish(cfg, Assessed::of(claims), claimed_build, now_yyyymm),
                activation,
            ),
            Err(e) => Outcome::Done(unrooted(format!("evidence-rejected: {e}"))),
        };
    }
    Outcome::Done(
        match appraise_evidence(
            cfg,
            evidence,
            verifier_challenge,
            &session_pub,
            now_unix,
            now_yyyymm,
        ) {
            Ok(a) => finish(cfg, a, claimed_build, now_yyyymm),
            Err(e) => unrooted(format!("evidence-rejected: {e}")),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn today_is_plausible() {
        let (secs, ym) = now();
        assert!(secs > 1_700_000_000);
        assert!((202_301..=210_012).contains(&ym) && (1..=12).contains(&(ym % 100)));
    }

    fn done(o: Outcome) -> Appraised {
        match o {
            Outcome::Done(a) => a,
            Outcome::Activate(..) => panic!("no activation expected"),
        }
    }

    #[test]
    fn missing_and_bad_evidence_are_d0() {
        let cfg = ClientAttestation::default();
        let a = done(appraise(
            &cfg,
            &[1; 32],
            &SessionKey::Ed25519([2; 32]),
            &[0; 32],
            &[],
        ));
        assert_eq!(a.tier, DeviceTier::D0Unknown);
        assert_eq!(a.warnings, vec!["no-platform-evidence".to_string()]);
        let a = done(appraise(
            &cfg,
            &[1; 32],
            &SessionKey::Ed25519([2; 32]),
            &[0; 32],
            &[0xff, 0x00],
        ));
        assert_eq!(a.tier, DeviceTier::D0Unknown);
        assert!(a.warnings[0].starts_with("evidence-rejected"));
        // Well-formed, but this Verifier has no Android policy.
        let e = Evidence::AndroidKey {
            chain: vec![vec![1]],
            integrity: None,
        }
        .encode();
        let a = done(appraise(
            &cfg,
            &[1; 32],
            &SessionKey::Ed25519([2; 32]),
            &[0; 32],
            &e,
        ));
        assert_eq!(a.tier, DeviceTier::D0Unknown);
        assert!(a.warnings[0].contains("no Android policy"));
    }

    #[test]
    fn options_parse() {
        let digest = "ab".repeat(32);
        let cfg = ClientAttestation::from_options(
            &[format!("com.halo.decomp:{digest}")],
            Some(r#"{"entries": {"0a1b": {"status": "REVOKED"}}}"#),
            &["ABCDE12345.com.halo.decomp".into()],
            false,
        )
        .unwrap();
        let android = cfg.android.unwrap();
        assert_eq!(android.apps[0].signer_sha256, vec![[0xab; 32]]);
        assert!(android.revoked.contains("a1b"));
        assert!(!cfg.apple.unwrap().allow_development);
        assert!(ClientAttestation::from_options(&["nodigest".into()], None, &[], false).is_err());
    }

    // ---- Play Integrity and the client Build Registry, on claims as key
    // attestation would give them (attest-android's own tests cover that)

    use attest_android::integrity::{b64url, testing::Google};
    use attest_core::AttestedApp;

    const NONCE: [u8; 32] = [0x11; 32];
    const PACKAGE: &str = "com.halo.decomp";
    const SIGNER: [u8; 32] = [0x5a; 32];

    fn android_d2() -> Claims {
        Claims {
            platform: "android",
            key_storage: KeyStorage::StrongBox,
            verified_boot: Some(true),
            app_attested: true,
            session_key_in_hw: true,
            os_patch_level: None,
            hardware_identity: None,
            boot: Default::default(),
            app: Some(AttestedApp {
                id: format!("android:{PACKAGE}"),
                version: 42,
            }),
            warnings: vec![],
        }
    }

    fn cfg_with(google: Option<&Google>, builds: &str) -> ClientAttestation {
        let mut cfg = ClientAttestation::from_options(
            &[format!("{PACKAGE}:{}", hex::encode(SIGNER))],
            None,
            &[],
            false,
        )
        .unwrap();
        cfg.play_integrity = google.map(Google::keys);
        cfg.client_builds = ClientBuilds::parse(builds).unwrap();
        cfg
    }

    fn token(g: &Google, labels: &[&str], version: &str) -> String {
        g.token(&serde_json::json!({
            "requestDetails": {
                "requestPackageName": PACKAGE,
                "nonce": b64url(&NONCE),
                "timestampMillis": (now().0 as u64 * 1000).to_string(),
            },
            "appIntegrity": {
                "appRecognitionVerdict": "PLAY_RECOGNIZED",
                "packageName": PACKAGE,
                "certificateSha256Digest": [b64url(&SIGNER)],
                "versionCode": version,
            },
            "deviceIntegrity": {"deviceRecognitionVerdict": labels},
        }))
    }

    fn assess(cfg: &ClientAttestation, token: Option<String>) -> Appraised {
        let mut a = Assessed::of(android_d2());
        play_integrity(cfg, &mut a, token.as_deref(), &NONCE, now().0);
        finish(cfg, a, &[0; 32], now().1)
    }

    #[test]
    fn android_d2_needs_strong_integrity_when_configured() {
        let g = Google::new();
        // not configured: key attestation alone
        assert_eq!(
            assess(&cfg_with(None, ""), None).tier,
            DeviceTier::D2Hardware
        );
        let cfg = cfg_with(Some(&g), "");
        let strong = &["MEETS_DEVICE_INTEGRITY", "MEETS_STRONG_INTEGRITY"][..];
        let a = assess(&cfg, Some(token(&g, strong, "42")));
        assert_eq!(a.tier, DeviceTier::D2Hardware);
        assert_eq!(a.features.strong_integrity, Some(true));
        let a = assess(&cfg, None);
        assert_eq!(
            (a.tier, a.warnings[0].as_str()),
            (DeviceTier::D1Software, "no-play-integrity")
        );
        let a = assess(&cfg, Some(token(&g, &["MEETS_DEVICE_INTEGRITY"], "42")));
        assert_eq!(a.tier, DeviceTier::D1Software);
        assert_eq!(a.features.strong_integrity, Some(false));
        let a = assess(&cfg, Some(token(&g, &[], "42")));
        assert_eq!(a.tier, DeviceTier::D0Unknown);
        // another install's verdict (another build than the one attested)
        let a = assess(&cfg, Some(token(&g, strong, "41")));
        assert_eq!(a.tier, DeviceTier::D0Unknown);
        // a verdict minted with another app's keys
        let a = assess(&cfg, Some(token(&Google::new(), strong, "42")));
        assert_eq!(a.tier, DeviceTier::D1Software);
        assert!(a.warnings[0].starts_with("play-integrity-rejected"));
    }

    #[test]
    fn the_registry_names_the_attested_build() {
        let id = "ab".repeat(32);
        let cfg = cfg_with(None, &format!("{id} android:{PACKAGE} 42 # release 1.0\n"));
        let a = assess(&cfg, None);
        assert_eq!(a.client_build, Some([0xab; 32]));
        assert_eq!(a.tier, DeviceTier::D2Hardware);
        assert!(a.warnings.contains(&"build-claim-differs".to_string()));
        // a version we did not build
        let cfg = cfg_with(None, &format!("{id} android:{PACKAGE} 41\n"));
        let a = assess(&cfg, None);
        assert_eq!((a.tier, a.client_build), (DeviceTier::D1Software, None));
        assert!(a.warnings[0].starts_with("build-unregistered"));
        // evidence that attests no build: the claim stands, marked
        let cfg = cfg_with(None, &format!("{id} android:{PACKAGE} 42\n"));
        let mut claims = android_d2();
        claims.app = None;
        let a = finish(&cfg, Assessed::of(claims), &[0; 32], now().1);
        assert_eq!(a.client_build, None);
        assert_eq!(a.warnings, vec!["build-not-attested".to_string()]);
        assert!(ClientBuilds::parse("zz android:x 1").is_err());
    }
}
