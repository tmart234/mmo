//! Verifier appraisal of client platform evidence (roadmap P3, ATT-01..06):
//! `EvidenceRequest.evidence` → Device Trust Tier, feature claims and
//! a hardware-rooted DID where the platform gives one.
//!
//! Formats (attest_core::Evidence): Android key attestation (`attest-android`),
//! Apple App Attest attestations and assertions (`attest-apple`). All bind to
//! `attest_challenge(verifier_challenge, session_pub)`, so evidence made for another
//! admission or another session key fails. Evidence that fails appraisal is
//! not an error for the client: it is tier D0 with a warning (03 §4.2), and
//! the queue's tier floor decides.

use attest_android::{AllowedApp, AndroidPolicy};
use attest_apple::{AppKey, ApplePolicy};
use attest_core::{attest_challenge, device_tier, AttestError, Claims, Evidence, KeyStorage};
use dashmap::DashMap;
use fpp_tokens::Features;
use fpp_types::DeviceTier;
use std::time::{SystemTime, UNIX_EPOCH};

/// What the Verifier accepts, set from the command line (`svc-verifier --help`).
#[derive(Default)]
pub struct ClientAttestation {
    pub android: Option<AndroidPolicy>,
    pub apple: Option<ApplePolicy>,
    /// App Attest keys appraised so far, by key id (in memory: a restarted
    /// Verifier asks the app to attest a new key).
    pub apple_keys: DashMap<[u8; 32], AppKey>,
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
        })
    }
}

/// The outcome for one admission.
pub struct Appraised {
    pub tier: DeviceTier,
    pub features: Features,
    /// Hardware-rooted identity for the DID, when the platform gives one.
    pub identity: Option<Vec<u8>>,
    pub warnings: Vec<String>,
}

fn unrooted(warning: String) -> Appraised {
    Appraised {
        tier: DeviceTier::D0Unknown,
        features: Features::default(),
        identity: None,
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

fn features(c: &Claims, now_yyyymm: u32) -> Features {
    Features {
        secure_boot: c.verified_boot,
        key_in_hw: Some(c.session_key_in_hw),
        app_attested: Some(c.app_attested),
        strongbox: (c.key_storage == KeyStorage::StrongBox).then_some(true),
        os_patch_age_days: c
            .os_patch_level
            .map(|p| u64::from(attest_core::patch_age_months(p, now_yyyymm)) * 30),
        ..Features::default()
    }
}

fn appraise_evidence(
    cfg: &ClientAttestation,
    evidence: Evidence,
    challenge: &[u8; 32],
    session_pub: &[u8; 32],
    now_unix: i64,
    now_yyyymm: u32,
) -> Result<Claims, AttestError> {
    match evidence {
        Evidence::AndroidKey { chain } => {
            let policy = cfg
                .android
                .as_ref()
                .ok_or(AttestError::Policy("no Android policy on this Verifier"))?;
            attest_android::appraise(&chain, challenge, session_pub, policy, now_unix, now_yyyymm)
        }
        Evidence::AppleAppAttest { attestation } => {
            let policy = cfg
                .apple
                .as_ref()
                .ok_or(AttestError::Policy("no Apple policy on this Verifier"))?;
            let (claims, key) =
                attest_apple::appraise_attestation(&attestation, challenge, policy, now_unix)?;
            cfg.apple_keys.insert(key.key_id, key);
            Ok(claims)
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
        }
    }
}

/// Appraise an admission's evidence (empty: D0).
pub fn appraise(
    cfg: &ClientAttestation,
    verifier_challenge: &[u8; 32],
    session_pub: &[u8; 32],
    evidence: &[u8],
) -> Appraised {
    let evidence = match Evidence::decode(evidence) {
        Ok(Some(e)) => e,
        Ok(None) => return unrooted("no-platform-evidence".into()),
        Err(e) => return unrooted(format!("evidence-rejected: {e}")),
    };
    let (now_unix, now_yyyymm) = now();
    let challenge = attest_challenge(verifier_challenge, session_pub);
    match appraise_evidence(cfg, evidence, &challenge, session_pub, now_unix, now_yyyymm) {
        Ok(claims) => Appraised {
            tier: device_tier(&claims),
            features: features(&claims, now_yyyymm),
            identity: claims.hardware_identity.clone(),
            warnings: claims.warnings.clone(),
        },
        Err(e) => unrooted(format!("evidence-rejected: {e}")),
    }
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

    #[test]
    fn missing_and_bad_evidence_are_d0() {
        let cfg = ClientAttestation::default();
        let a = appraise(&cfg, &[1; 32], &[2; 32], &[]);
        assert_eq!(a.tier, DeviceTier::D0Unknown);
        assert_eq!(a.warnings, vec!["no-platform-evidence".to_string()]);
        let a = appraise(&cfg, &[1; 32], &[2; 32], &[0xff, 0x00]);
        assert_eq!(a.tier, DeviceTier::D0Unknown);
        assert!(a.warnings[0].starts_with("evidence-rejected"));
        // Well-formed, but this Verifier has no Android policy.
        let e = Evidence::AndroidKey {
            chain: vec![vec![1]],
        }
        .encode();
        let a = appraise(&cfg, &[1; 32], &[2; 32], &e);
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
}
