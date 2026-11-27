//! Title- and region-scoped authority policy for `fppd`.
//!
//! Keeps the Fair-Play Protocol v1 trust plane 100% game-agnostic: any MMO,
//! shooter, or multiplayer title configures its own publisher domain, region,
//! queue/playlist tier floors, per-server/shard slot capacity, token lifetimes,
//! and measured game-server executable path without touching protocol code.

use anyhow::{anyhow, bail, Result};
use fpp::types::DeviceTier;
use std::collections::BTreeMap;

/// Default domain used when no `--domain` / policy file is provided.
pub const DEFAULT_DOMAIN: &str = "fpp.dev";
/// Default deployment region.
pub const DEFAULT_REGION: &str = "dev";
/// Default IMA-measured server binary path.
pub const DEFAULT_GS_PROGRAM_PATH: &str = "/usr/local/bin/game-server";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityPolicy {
    /// Publisher or title domain (e.g. `mygame.example`). Derives issuer IDs
    /// (`verifier.<domain>`, `broker.<domain>`, `liveness.<domain>`), the
    /// Transparency Log origin (`<domain>/log`), and witness name
    /// (`<domain>/witness`).
    pub domain: String,
    /// Region name stamped into SARs and matched by Enforcement scope.
    pub region: String,
    /// Monotonic policy version stamped into ARs and SATs.
    pub policy_ver: u64,
    /// Allowed queue/playlist/shard names and their minimum `DeviceTier`.
    pub queues: BTreeMap<String, DeviceTier>,
    /// Maximum active slots per game server / shard before Broker spills to
    /// another live server.
    pub max_slots: u16,
    /// Seconds between SAR re-issues.
    pub sar_interval_s: u64,
    /// Lifetime (TTL) of each issued SAR in seconds.
    pub sar_ttl_s: u64,
    /// Lifetime (TTL) of each issued Attestation Result in seconds.
    pub ar_ttl_s: u64,
    /// Lifetime (TTL) of each issued Session Admission Token in seconds.
    pub sat_ttl_s: u64,
    /// Measured executable path checked in IMA logs for TPM-attested game servers.
    pub gs_program_path: String,
}

impl Default for AuthorityPolicy {
    fn default() -> Self {
        let mut queues = BTreeMap::new();
        queues.insert("open".into(), DeviceTier::D0Unknown);
        queues.insert("verified".into(), DeviceTier::D2Hardware);
        queues.insert("hardened".into(), DeviceTier::D3Hardened);
        Self {
            domain: DEFAULT_DOMAIN.into(),
            region: DEFAULT_REGION.into(),
            policy_ver: 1,
            queues,
            max_slots: 128,
            sar_interval_s: 2,
            sar_ttl_s: 10,
            ar_ttl_s: 1800,
            sat_ttl_s: 3600,
            gs_program_path: DEFAULT_GS_PROGRAM_PATH.into(),
        }
    }
}

impl AuthorityPolicy {
    pub fn verifier_iss(&self) -> String {
        format!("verifier.{}", self.domain)
    }

    pub fn broker_iss(&self) -> String {
        format!("broker.{}", self.domain)
    }

    pub fn liveness_iss(&self) -> String {
        format!("liveness.{}", self.domain)
    }

    pub fn log_origin(&self) -> String {
        format!("{}/log", self.domain)
    }

    pub fn witness_name(&self) -> String {
        format!("{}/witness", self.domain)
    }

    pub fn queue_min_tier(&self, queue: &str) -> Option<DeviceTier> {
        self.queues.get(queue).copied()
    }

    /// Parse a single `<name>:<tier>` CLI flag (e.g. `ranked:2` or `raid:D2`).
    pub fn parse_queue_spec(spec: &str) -> Result<(String, DeviceTier)> {
        let (name, raw_tier) = spec
            .split_once(':')
            .ok_or_else(|| anyhow!("queue spec must be <name>:<0..3>, got {spec:?}"))?;
        let name = name.trim();
        if name.is_empty() {
            bail!("empty queue name in {spec:?}");
        }
        Ok((name.to_string(), parse_tier(raw_tier.trim())?))
    }

    /// Parse a simple `#`-commented `key = value` policy file (zero external parser deps).
    ///
    /// Example:
    /// ```text
    /// domain = my-mmo.example
    /// region = us-east
    /// policy_ver = 2
    /// max_slots = 500
    /// gs_program = /opt/my-mmo/shard-server
    /// queues.clear = true
    /// queue.world = D0
    /// queue.ranked-arena = D2
    /// queue.tournament = D3
    /// ```
    pub fn parse(text: &str) -> Result<Self> {
        let mut policy = Self::default();
        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let (k, v) = line
                .split_once('=')
                .ok_or_else(|| anyhow!("policy line {}: expected `key = value`", lineno + 1))?;
            let k = k.trim();
            let v = v.trim();
            if let Some(qname) = k.strip_prefix("queue.") {
                if qname.is_empty() {
                    bail!("policy line {}: empty queue name", lineno + 1);
                }
                policy.queues.insert(qname.to_string(), parse_tier(v)?);
                continue;
            }
            match k {
                "domain" => {
                    if v.is_empty() || v.chars().any(char::is_whitespace) {
                        bail!("policy line {}: invalid domain {v:?}", lineno + 1);
                    }
                    policy.domain = v.to_string();
                }
                "region" => {
                    if v.is_empty() || v.chars().any(char::is_whitespace) {
                        bail!("policy line {}: invalid region {v:?}", lineno + 1);
                    }
                    policy.region = v.to_string();
                }
                "policy_ver" => policy.policy_ver = v.parse()?,
                "max_slots" => {
                    let n: u16 = v.parse()?;
                    if n == 0 {
                        bail!("policy line {}: max_slots must be > 0", lineno + 1);
                    }
                    policy.max_slots = n;
                }
                "sar_interval_s" => policy.sar_interval_s = v.parse::<u64>()?.max(1),
                "sar_ttl_s" => policy.sar_ttl_s = v.parse::<u64>()?.max(2),
                "ar_ttl_s" => policy.ar_ttl_s = v.parse::<u64>()?.max(60),
                "sat_ttl_s" => policy.sat_ttl_s = v.parse::<u64>()?.max(60),
                "gs_program" => policy.gs_program_path = v.to_string(),
                "queues.clear" => {
                    if v == "true" || v == "1" {
                        policy.queues.clear();
                    }
                }
                other => bail!("policy line {}: unknown key {other:?}", lineno + 1),
            }
        }
        policy.validate()?;
        Ok(policy)
    }

    /// Enforce policy invariants consistently for both policy files and CLI overrides.
    pub fn validate(&self) -> Result<()> {
        if self.domain.is_empty() || self.domain.chars().any(char::is_whitespace) {
            bail!("invalid domain {:?}", self.domain);
        }
        if self.region.is_empty() || self.region.chars().any(char::is_whitespace) {
            bail!("invalid region {:?}", self.region);
        }
        if self.max_slots == 0 {
            bail!("max_slots must be > 0");
        }
        if self.sar_interval_s == 0 {
            bail!("sar_interval_s must be > 0");
        }
        if self.sar_ttl_s <= self.sar_interval_s {
            bail!(
                "sar_ttl_s ({}) must be > sar_interval_s ({})",
                self.sar_ttl_s,
                self.sar_interval_s
            );
        }
        if self.queues.is_empty() {
            bail!("policy must configure at least one queue");
        }
        Ok(())
    }
}

pub fn parse_tier(s: &str) -> Result<DeviceTier> {
    match s {
        "0" | "d0" | "D0" => Ok(DeviceTier::D0Unknown),
        "1" | "d1" | "D1" => Ok(DeviceTier::D1Software),
        "2" | "d2" | "D2" => Ok(DeviceTier::D2Hardware),
        "3" | "d3" | "D3" => Ok(DeviceTier::D3Hardened),
        _ => bail!("invalid device tier {s:?} (expected 0..3 or D0..D3)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_custom_mmo_policy() {
        let p = AuthorityPolicy::parse(
            r#"
            # Example RPG/MMO authority cell
            domain = realm.example
            region = eu-central
            policy_ver = 7
            max_slots = 500
            sar_interval_s = 3
            sar_ttl_s = 15
            gs_program = /opt/realm/zone-server
            queues.clear = true
            queue.world-shard = D0
            queue.ranked-arena = D2
            queue.tournament = 3
            "#,
        )
        .unwrap();
        assert_eq!(p.domain, "realm.example");
        assert_eq!(p.region, "eu-central");
        assert_eq!(p.policy_ver, 7);
        assert_eq!(p.max_slots, 500);
        assert_eq!(p.verifier_iss(), "verifier.realm.example");
        assert_eq!(p.broker_iss(), "broker.realm.example");
        assert_eq!(p.liveness_iss(), "liveness.realm.example");
        assert_eq!(p.log_origin(), "realm.example/log");
        assert_eq!(p.witness_name(), "realm.example/witness");
        assert_eq!(p.queue_min_tier("open"), None);
        assert_eq!(p.queue_min_tier("world-shard"), Some(DeviceTier::D0Unknown));
        assert_eq!(
            p.queue_min_tier("ranked-arena"),
            Some(DeviceTier::D2Hardware)
        );
        assert_eq!(p.queue_min_tier("tournament"), Some(DeviceTier::D3Hardened));
    }
}
