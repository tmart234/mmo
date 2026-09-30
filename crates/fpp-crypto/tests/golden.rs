//! Golden interop vectors (P1 exit criterion, 07-gap-analysis-and-roadmap.md).
//!
//! Builds a deterministic vector set, checks every vector with this crate,
//! and compares the result with `interop/vectors/fpp1.json`, which an
//! independent implementation (`interop/python/fpp_interop.py`) also checks.
//! Regenerate after an intentional change with `FPP_REGEN_VECTORS=1`.

use ed25519_dalek::{Signer as _, SigningKey};
use fpp_crypto::*;
use fpp_merkle::{leaf_hash, root, root_from_leaf_hashes};
use fpp_tokens::{
    instance_id, sar_link, AttestationResult, Features, ServerAttestationResult,
    SessionAdmissionToken,
};
use fpp_types::{ctx, BuildId, Digest, GsInstanceId, MatchId, FPP_VERSION};
use fpp_types::{DeviceTier, Did, ServerClass};
use fpp_wire::cbor::{self, Value};
use fpp_wire::cose::{alg, ProtectedHeader, Sign1};
use fpp_wire::msg::frame_leaf_data;
use fpp_wire::{
    Action, AdmitPop, Checkpoint, InputCommit, InputLeaf, Payload, RevocationEvent, Scope,
    SubjectKind,
};
use serde_json::{json, Value as Json};
use sha2::{Digest as _, Sha256};
use std::path::PathBuf;

const MATCH: MatchId = MatchId(*b"fpp1-golden-mtch");
const TICKS_PER_EPOCH: u32 = 64;

struct Key {
    name: &'static str,
    role: KeyRole,
    role_name: &'static str,
    signer: Ed25519Signer,
    known: bool,
}

fn key(name: &'static str, seed: u8, role: KeyRole, role_name: &'static str, known: bool) -> Key {
    Key {
        name,
        role,
        role_name,
        signer: Ed25519Signer::new(SigningKey::from_bytes(&[seed; 32])),
        known,
    }
}

fn h(b: impl AsRef<[u8]>) -> String {
    hex::encode(b)
}

fn frames(epoch: u32, skip: &[u32]) -> Vec<(u32, Vec<u8>)> {
    let first = epoch * TICKS_PER_EPOCH;
    (first..first + TICKS_PER_EPOCH)
        .filter(|t| !skip.contains(&(t - first)))
        .map(|t| (t, vec![(t & 0xff) as u8, 0xA5, (epoch & 0xff) as u8]))
        .collect()
}

fn frames_root(f: &[(u32, Vec<u8>)]) -> Digest {
    let data: Vec<Vec<u8>> = f.iter().map(|(t, p)| frame_leaf_data(*t, p)).collect();
    root(&data)
}

fn commit_for(slot: u16, epoch: u32, f: &[(u32, Vec<u8>)], prev: Digest) -> InputCommit {
    InputCommit {
        match_id: MATCH,
        slot,
        epoch,
        first_tick: epoch * TICKS_PER_EPOCH,
        last_tick: epoch * TICKS_PER_EPOCH + TICKS_PER_EPOCH - 1,
        n: f.len() as u32,
        frames_root: frames_root(f),
        prev,
    }
}

fn applied_bits(skip: &[u32]) -> Vec<u8> {
    let mut bits = vec![0xffu8; (TICKS_PER_EPOCH / 8) as usize];
    for s in skip {
        bits[(*s / 8) as usize] &= !(1 << (s % 8));
    }
    bits
}

fn commit_json(c: &InputCommit) -> Json {
    json!({
        "match_id": h(c.match_id.0), "slot": c.slot, "epoch": c.epoch,
        "first_tick": c.first_tick, "last_tick": c.last_tick, "n": c.n,
        "frames_root": h(c.frames_root.0), "prev": h(c.prev.0),
    })
}

fn admit_pop_json(p: &AdmitPop) -> Json {
    json!({"channel": p.channel, "binding": h(&p.binding)})
}

fn ar_json(a: &AttestationResult) -> Json {
    let f = &a.features;
    let mut feats = serde_json::Map::new();
    for (k, v) in [
        ("secure_boot", f.secure_boot),
        ("measured_boot", f.measured_boot),
        ("hvci", f.hvci),
        ("vbs", f.vbs),
        ("iommu", f.iommu),
        ("runtime_report", f.runtime_report),
        ("key_in_hw", f.key_in_hw),
        ("strong_integrity", f.strong_integrity),
        ("app_attested", f.app_attested),
    ] {
        if let Some(v) = v {
            feats.insert(k.into(), json!(v));
        }
    }
    if let Some(d) = f.os_patch_age_days {
        feats.insert("os_patch_age_days".into(), json!(d));
    }
    json!({
        "iss": a.iss, "iat": a.iat, "exp": a.exp, "cti": h(a.cti), "cnf": h(a.cnf),
        "nonce": h(a.nonce), "did": h(a.did.0), "tier": a.tier as u8, "features": feats,
        "client_build": h(a.client_build.0), "platform": a.platform,
        "policy_ver": a.policy_ver, "warnings": a.warnings,
    })
}

fn sat_json(s: &SessionAdmissionToken) -> Json {
    json!({
        "iss": s.iss, "sub": h(s.sub), "aud": h(s.aud.0), "iat": s.iat, "exp": s.exp,
        "cti": h(s.cti), "cnf": h(s.cnf), "did": h(s.did.0), "tier": s.tier as u8,
        "match_id": h(s.match_id.0), "slot": s.slot, "queue": s.queue,
        "policy_ver": s.policy_ver, "ar_cti": h(s.ar_cti),
    })
}

fn revocation_json(r: &RevocationEvent) -> Json {
    let mut scope = serde_json::Map::new();
    for (k, v) in [
        ("titles", &r.scope.titles),
        ("queues", &r.scope.queues),
        ("regions", &r.scope.regions),
    ] {
        if !v.is_empty() {
            scope.insert(k.into(), json!(v));
        }
    }
    json!({
        "id": h(r.id), "subject_kind": r.subject_kind as u8, "subject_id": h(&r.subject_id),
        "action": r.action as u8, "scope": scope, "effective_at": r.effective_at,
        "expires_at": r.expires_at, "reason": r.reason, "record": h(r.record.0),
    })
}

fn sar_json(s: &ServerAttestationResult) -> Json {
    json!({
        "iss": s.iss, "sub": h(s.sub.0), "iat": s.iat, "exp": s.exp, "cnf": h(s.cnf),
        "tls_spki_sha256": s.tls_spki_sha256.map(h), "noise_static": s.noise_static.map(h),
        "server_class": s.server_class as u8, "build_id": h(s.build_id.0), "region": s.region,
        "seq": s.seq, "prev": h(s.prev.0), "vrf_pub": s.vrf_pub.map(h),
    })
}

fn checkpoint_json(c: &Checkpoint) -> Json {
    json!({
        "match_id": h(c.match_id.0), "gs_instance_id": h(c.gs_instance_id.0),
        "build_id": h(c.build_id.0), "policy_ver": c.policy_ver, "epoch": c.epoch,
        "ticks": [c.ticks.0, c.ticks.1], "prev": h(c.prev.0),
        "inputs_root": h(c.inputs_root.0), "inputs_n": c.inputs_n,
        "events_root": h(c.events_root.0), "events_n": c.events_n,
        "state_root": h(c.state_root.0),
        "rng_root": h(c.rng_root.0), "rng_n": c.rng_n,
        "roster_root": h(c.roster_root.0), "roster_n": c.roster_n,
    })
}

/// Build a COSE_Sign1 by hand, for vectors that break one rule on purpose.
fn assemble(signer: &Ed25519Signer, header: ProtectedHeader, payload: Vec<u8>) -> Sign1 {
    let mut s = Sign1::new(header, payload).unwrap();
    s.signature = signer.sign(&s.to_be_signed());
    s
}

fn header_for(signer: &Ed25519Signer, context: &str, content_type: &str) -> ProtectedHeader {
    ProtectedHeader {
        alg: alg::EDDSA,
        content_type: content_type.into(),
        kid: signer.kid(),
        ctx: context.into(),
        version: FPP_VERSION,
    }
}

/// Re-encode a COSE_Sign1 with an arbitrary protected header map, signed validly.
fn with_protected_map(
    signer: &Ed25519Signer,
    protected: Value,
    unprotected: Value,
    payload: Vec<u8>,
) -> Vec<u8> {
    let protected_raw = cbor::encode(&protected).unwrap();
    let tbs = cbor::encode(&Value::Array(vec![
        Value::text("Signature1"),
        Value::bytes(protected_raw.clone()),
        Value::bytes(vec![]),
        Value::bytes(payload.clone()),
    ]))
    .unwrap();
    let sig = signer.sign(&tbs);
    cbor::encode(&Value::Array(vec![
        Value::bytes(protected_raw),
        unprotected,
        Value::bytes(payload),
        Value::bytes(sig),
    ]))
    .unwrap()
}

fn build() -> Json {
    let keys = [
        key("session-slot0", 0x51, KeyRole::Session, "session", true),
        key("session-slot1", 0x52, KeyRole::Session, "session", true),
        key(
            "gs-instance",
            0x61,
            KeyRole::GsInstance,
            "gs_instance",
            true,
        ),
        key("log", 0x71, KeyRole::Log, "log", true),
        key(
            "verifier-ar",
            0x11,
            KeyRole::VerifierAr,
            "verifier_ar",
            true,
        ),
        key("broker-sat", 0x12, KeyRole::BrokerSat, "broker_sat", true),
        key(
            "server-liveness",
            0x13,
            KeyRole::ServerLiveness,
            "server_liveness",
            true,
        ),
        key(
            "enforcement",
            0x14,
            KeyRole::Enforcement,
            "enforcement",
            true,
        ),
        key("unregistered", 0x7f, KeyRole::Session, "session", false),
    ];
    let k = |name: &str| keys.iter().find(|k| k.name == name).unwrap();
    let mut keyset = KeySet::default();
    for key in keys.iter().filter(|k| k.known) {
        keyset.insert_ed25519(key.role, key.signer.verifying_key());
    }

    let mut objects: Vec<Json> = Vec::new();
    let mut valid = |name: &str, kind: &str, cose: &[u8], payload: Json, derive: Json| {
        objects.push(json!({
            "name": name, "type": kind, "expect": "valid", "cose": h(cose),
            "digest": h(object_digest(cose).0), "payload": payload, "derive": derive,
        }));
    };

    // ---- InputCommits: slot 0 epochs 0 and 1 (chained), slot 1 epoch 1 with 4 lost frames.
    let f00 = frames(0, &[]);
    let c00 = commit_for(0, 0, &f00, Digest::default());
    let c00_cose = sign(&k("session-slot0").signer, &c00);
    let f01 = frames(1, &[]);
    let c01 = commit_for(0, 1, &f01, object_digest(&c00_cose));
    let c01_cose = sign(&k("session-slot0").signer, &c01);
    let skip = [5, 6, 17, 63];
    let f11 = frames(1, &skip);
    let c11 = commit_for(1, 1, &f11, Digest::default());
    let c11_cose = sign(&k("session-slot1").signer, &c11);
    let frames_json =
        |f: &[(u32, Vec<u8>)]| Json::Array(f.iter().map(|(t, p)| json!([t, h(p)])).collect());
    valid(
        "input-commit/slot0-epoch0",
        "input-commit",
        &c00_cose,
        commit_json(&c00),
        json!({"signer": "session-slot0", "frames": frames_json(&f00), "prev_object": null}),
    );
    valid(
        "input-commit/slot0-epoch1",
        "input-commit",
        &c01_cose,
        commit_json(&c01),
        json!({"signer": "session-slot0", "frames": frames_json(&f01), "prev_object": "input-commit/slot0-epoch0"}),
    );
    valid(
        "input-commit/slot1-epoch1-lossy",
        "input-commit",
        &c11_cose,
        commit_json(&c11),
        json!({"signer": "session-slot1", "frames": frames_json(&f11), "prev_object": null}),
    );

    // ---- Checkpoints for epochs 0 and 1 (chained).
    let gs = &k("gs-instance").signer;
    let gs_id = GsInstanceId(key_digest(&gs.verifying_key()).0);
    let roster: Vec<Vec<u8>> = vec![
        b"slot0|sat-cti-00|did-aaaa".to_vec(),
        b"slot1|sat-cti-01|did-bbbb".to_vec(),
        b"slot2|sat-cti-02|did-cccc".to_vec(),
    ];
    let make_cp = |epoch: u32,
                   leaves: Vec<InputLeaf>,
                   events: Vec<Vec<u8>>,
                   rng: Vec<Vec<u8>>,
                   prev: Digest| {
        let leaf_data: Vec<Vec<u8>> = leaves.iter().map(InputLeaf::leaf_data).collect();
        let state = format!("state@epoch{epoch}").into_bytes();
        let cp = Checkpoint {
            match_id: MATCH,
            gs_instance_id: gs_id,
            build_id: BuildId(Sha256::digest(b"gs-build-1.0.0").into()),
            policy_ver: 42,
            epoch,
            ticks: (
                epoch * TICKS_PER_EPOCH,
                epoch * TICKS_PER_EPOCH + TICKS_PER_EPOCH - 1,
            ),
            prev,
            inputs_root: root(&leaf_data),
            inputs_n: leaf_data.len() as u32,
            events_root: root(&events),
            events_n: events.len() as u32,
            state_root: Digest(Sha256::digest(&state).into()),
            rng_root: root(&rng),
            rng_n: rng.len() as u32,
            roster_root: root(&roster),
            roster_n: roster.len() as u32,
        };
        let derive = json!({
            "signer": "gs-instance",
            "input_leaves": leaves.iter().map(|l| json!({
                "slot": l.slot, "commit": l.commit.map(|d| h(d.0)), "applied": h(&l.applied),
            })).collect::<Vec<_>>(),
            "events": events.iter().map(h).collect::<Vec<_>>(),
            "rng": rng.iter().map(h).collect::<Vec<_>>(),
            "roster": roster.iter().map(h).collect::<Vec<_>>(),
            "state": h(&state),
        });
        (cp, derive)
    };
    let (cp0, d0) = make_cp(
        0,
        vec![
            InputLeaf {
                slot: 0,
                commit: Some(object_digest(&c00_cose)),
                applied: applied_bits(&[]),
            },
            InputLeaf {
                slot: 1,
                commit: None,
                applied: vec![0; 8],
            },
            InputLeaf {
                slot: 2,
                commit: None,
                applied: vec![0; 8],
            },
        ],
        vec![b"spawn|slot0".to_vec()],
        vec![],
        Digest::default(),
    );
    let cp0_cose = sign(gs, &cp0);
    let (cp1, d1) = make_cp(
        1,
        vec![
            InputLeaf {
                slot: 0,
                commit: Some(object_digest(&c01_cose)),
                applied: applied_bits(&[]),
            },
            InputLeaf {
                slot: 1,
                commit: Some(object_digest(&c11_cose)),
                applied: applied_bits(&skip),
            },
            InputLeaf {
                slot: 2,
                commit: None,
                applied: vec![0; 8],
            },
        ],
        vec![
            b"move|slot0".to_vec(),
            b"move|slot1".to_vec(),
            b"hit|slot0->slot1|dmg=20".to_vec(),
        ],
        vec![b"vrf-proof-loot-roll-0".to_vec()],
        object_digest(&cp0_cose),
    );
    let cp1_cose = sign(gs, &cp1);
    let mut d0 = d0;
    d0["prev_object"] = Json::Null;
    let mut d1 = d1;
    d1["prev_object"] = json!("checkpoint/epoch0");
    valid(
        "checkpoint/epoch0",
        "checkpoint",
        &cp0_cose,
        checkpoint_json(&cp0),
        d0,
    );
    valid(
        "checkpoint/epoch1",
        "checkpoint",
        &cp1_cose,
        checkpoint_json(&cp1),
        d1,
    );

    // ---- AdmitPop: slot 0's session key bound to a player-hosted Noise IK channel.
    let (host_static, joiner_static) = ([0x81u8; 32], [0x82u8; 32]);
    let pop = AdmitPop {
        channel: AdmitPop::NOISE_IK.into(),
        binding: [host_static, joiner_static].concat(),
    };
    let pop_cose = sign(&k("session-slot0").signer, &pop);
    valid(
        "admit-pop/slot0-noise-ik",
        "admit-pop",
        &pop_cose,
        admit_pop_json(&pop),
        json!({"signer": "session-slot0", "host_static": h(host_static), "joiner_static": h(joiner_static)}),
    );

    // ---- Tokens (§6): an AR, the SAT it backs, and a two-link SAR chain.
    const T0: u64 = 1_790_000_000;
    let session_pub = k("session-slot0").signer.verifying_key().to_bytes();
    let instance_pub = gs.verifying_key().to_bytes();
    let ar = AttestationResult {
        iss: "ver.golden".into(),
        iat: T0,
        exp: T0 + 1800,
        cti: *b"ar-cti-golden-01",
        cnf: session_pub,
        nonce: Sha256::digest(b"verifier challenge").into(),
        did: Did(Sha256::digest(b"device").into()),
        tier: DeviceTier::D2Hardware,
        features: Features {
            secure_boot: Some(true),
            measured_boot: Some(true),
            hvci: Some(false),
            key_in_hw: Some(true),
            os_patch_age_days: Some(12),
            ..Features::default()
        },
        client_build: BuildId(Sha256::digest(b"client-build-1").into()),
        platform: "windows".into(),
        policy_ver: 42,
        warnings: vec!["os-patch-stale".into()],
    };
    let ar_cose = sign(&k("verifier-ar").signer, &ar);
    valid(
        "attestation-result/d2",
        "attestation-result",
        &ar_cose,
        ar_json(&ar),
        json!({"signer": "verifier-ar"}),
    );
    let sat = SessionAdmissionToken {
        iss: "broker.golden".into(),
        sub: Sha256::digest(b"account").into(),
        aud: instance_id(&instance_pub),
        iat: T0,
        exp: T0 + 3600,
        cti: *b"sat-cti-golden01",
        cnf: session_pub,
        did: ar.did,
        tier: ar.tier,
        match_id: MATCH,
        slot: 0,
        queue: "verified-slayer".into(),
        policy_ver: 42,
        ar_cti: ar.cti,
    };
    let sat_cose = sign(&k("broker-sat").signer, &sat);
    valid(
        "sat/slot0",
        "sat",
        &sat_cose,
        sat_json(&sat),
        json!({"signer": "broker-sat", "ar_object": "attestation-result/d2"}),
    );
    let sar_at = |seq: u64, prev: Digest| ServerAttestationResult {
        iss: "live.golden".into(),
        sub: instance_id(&instance_pub),
        iat: T0 + 2 * seq,
        exp: T0 + 2 * seq + 10,
        cnf: instance_pub,
        tls_spki_sha256: None,
        noise_static: Some(Sha256::digest(b"noise static").into()),
        server_class: ServerClass::FirstParty,
        build_id: BuildId(Sha256::digest(b"gs-build-1.0.0").into()),
        region: "eu-west".into(),
        seq,
        prev,
        vrf_pub: None,
    };
    let sar0 = sar_at(0, Digest::default());
    let sar0_cose = sign(&k("server-liveness").signer, &sar0);
    let sar1 = sar_at(1, sar_link(&sar0_cose).unwrap());
    let sar1_cose = sign(&k("server-liveness").signer, &sar1);
    valid(
        "sar/seq0",
        "sar",
        &sar0_cose,
        sar_json(&sar0),
        json!({"signer": "server-liveness", "prev_object": null}),
    );
    valid(
        "sar/seq1",
        "sar",
        &sar1_cose,
        sar_json(&sar1),
        json!({"signer": "server-liveness", "prev_object": "sar/seq0"}),
    );

    // ---- Enforcement (§9): a kick of one account, in one region, for a day.
    let revocation = RevocationEvent {
        id: *b"revocation-gold1",
        subject_kind: SubjectKind::Account,
        subject_id: sat.sub.to_vec(),
        action: Action::Kick,
        scope: Scope {
            regions: vec!["eu-west".into()],
            ..Scope::default()
        },
        effective_at: T0 + 100,
        expires_at: Some(T0 + 100 + 86_400),
        reason: fpp_types::Reason::PolicyKick as u16,
        record: Digest(Sha256::digest(b"enforcement record").into()),
    };
    let revocation_cose = sign(&k("enforcement").signer, &revocation);
    valid(
        "revocation/kick-account",
        "revocation",
        &revocation_cose,
        revocation_json(&revocation),
        json!({"signer": "enforcement"}),
    );

    // ---- Negative vectors: each must be rejected with this category.
    let mut reject = |name: &str, kind: &str, cose: Vec<u8>, category: &str| {
        objects.push(json!({"name": name, "type": kind, "expect": "reject", "category": category, "cose": h(cose)}));
    };
    let s0 = &k("session-slot0").signer;
    reject(
        "reject/revocation-signed-by-broker-key",
        "revocation",
        sign(&k("broker-sat").signer, &revocation),
        "role",
    );
    reject(
        "reject/checkpoint-signed-by-session-key",
        "checkpoint",
        sign(s0, &cp1),
        "role",
    );
    reject(
        "reject/input-commit-presented-as-checkpoint",
        "checkpoint",
        c01_cose.clone(),
        "ctx",
    );
    reject(
        "reject/checkpoint-under-sat-context",
        "checkpoint",
        assemble(
            gs,
            header_for(gs, ctx::SAT, Checkpoint::CONTENT_TYPE),
            cp1.to_cbor(),
        )
        .encode(),
        "ctx",
    );
    reject(
        "reject/log-key-single-signature",
        "checkpoint",
        sign(&k("log").signer, &cp1),
        "role",
    );
    reject(
        "reject/unknown-kid",
        "input-commit",
        sign(&k("unregistered").signer, &c01),
        "kid",
    );
    let mut bad_alg = header_for(gs, ctx::CHECKPOINT, Checkpoint::CONTENT_TYPE);
    bad_alg.alg = -7;
    reject(
        "reject/alg-mismatch",
        "checkpoint",
        assemble(gs, bad_alg, cp1.to_cbor()).encode(),
        "alg",
    );
    let mut v2 = header_for(s0, ctx::INPUT_COMMIT, InputCommit::CONTENT_TYPE);
    v2.version = 2;
    reject(
        "reject/version-2",
        "input-commit",
        assemble(s0, v2, c01.to_cbor()).encode(),
        "version",
    );

    let mut tampered_sig = Sign1::decode(&cp1_cose).unwrap();
    tampered_sig.signature[10] ^= 0x01;
    reject(
        "reject/tampered-signature",
        "checkpoint",
        tampered_sig.encode(),
        "signature",
    );
    let mut tampered_payload = Sign1::decode(&cp1_cose).unwrap();
    let last = tampered_payload.payload.len() - 1;
    tampered_payload.payload[last] ^= 0x01; // inside roster_n or a digest: still canonical
    reject(
        "reject/tampered-payload",
        "checkpoint",
        tampered_payload.encode(),
        "signature",
    );

    // Validly signed but not deterministic CBOR inside the payload.
    let mut noncanon = c01.to_cbor();
    let slot_key = [0x64, b's', b'l', b'o', b't', 0x00];
    let pos = noncanon.windows(6).position(|w| w == slot_key).unwrap() + 5;
    noncanon.splice(pos..pos + 1, [0x18, 0x00]); // slot 0 as 0x18 0x00
    reject(
        "reject/non-canonical-integer-in-payload",
        "input-commit",
        assemble(
            s0,
            header_for(s0, ctx::INPUT_COMMIT, InputCommit::CONTENT_TYPE),
            noncanon,
        )
        .encode(),
        "encoding",
    );
    let unsorted = {
        let mut entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        if let Value::Map(m) = c01.to_value() {
            for (kk, vv) in m {
                entries.push((cbor::encode(&kk).unwrap(), cbor::encode(&vv).unwrap()));
            }
        }
        entries.sort();
        entries.swap(0, 1);
        let mut out = vec![0xa0 | entries.len() as u8];
        for (kk, vv) in entries {
            out.extend(kk);
            out.extend(vv);
        }
        out
    };
    reject(
        "reject/unsorted-payload-keys",
        "input-commit",
        assemble(
            s0,
            header_for(s0, ctx::INPUT_COMMIT, InputCommit::CONTENT_TYPE),
            unsorted,
        )
        .encode(),
        "encoding",
    );
    let mut bad_ticks = c01.clone();
    bad_ticks.first_tick = bad_ticks.last_tick + 1;
    reject(
        "reject/schema-first-tick-after-last",
        "input-commit",
        sign(s0, &bad_ticks),
        "schema",
    );

    reject(
        "reject/admit-pop-signed-by-gs-key",
        "admit-pop",
        sign(gs, &pop),
        "role",
    );
    let short = AdmitPop {
        channel: AdmitPop::NOISE_IK.into(),
        binding: vec![0x81; 16],
    };
    reject(
        "reject/admit-pop-short-binding",
        "admit-pop",
        sign(s0, &short),
        "schema",
    );

    reject(
        "reject/sat-signed-by-verifier-key",
        "sat",
        sign(&k("verifier-ar").signer, &sat),
        "role",
    );
    reject(
        "reject/sar-presented-as-sat",
        "sat",
        sar1_cose.clone(),
        "ctx",
    );
    let mut long_ar = ar.clone();
    long_ar.exp = long_ar.iat + 1801;
    reject(
        "reject/ar-lifetime-over-1800s",
        "attestation-result",
        sign(&k("verifier-ar").signer, &long_ar),
        "schema",
    );
    let mut stray = sar_at(1, sar_link(&sar0_cose).unwrap());
    stray.sub = instance_id(&session_pub);
    reject(
        "reject/sar-sub-not-its-instance-key",
        "sar",
        sign(&k("server-liveness").signer, &stray),
        "schema",
    );
    let mut unbound = sar_at(1, sar_link(&sar0_cose).unwrap());
    unbound.noise_static = None;
    reject(
        "reject/sar-without-transport-binding",
        "sar",
        sign(&k("server-liveness").signer, &unbound),
        "schema",
    );

    let protected = header_for(gs, ctx::CHECKPOINT, Checkpoint::CONTENT_TYPE).to_value();
    let unprot = Value::Map(vec![(Value::int(4), Value::bytes(vec![0; 16]))]);
    reject(
        "reject/unprotected-header-not-empty",
        "checkpoint",
        with_protected_map(gs, protected.clone(), unprot, cp1.to_cbor()),
        "header",
    );
    let mut crit = protected.clone();
    if let Value::Map(m) = &mut crit {
        m.push((Value::int(2), Value::Array(vec![Value::int(-65537)])));
    }
    reject(
        "reject/crit-header",
        "checkpoint",
        with_protected_map(gs, crit, Value::Map(vec![]), cp1.to_cbor()),
        "header",
    );
    let mut trailing = cp1_cose.clone();
    trailing.push(0x00);
    reject("reject/trailing-byte", "checkpoint", trailing, "encoding");
    let mut indefinite = cp1_cose.clone();
    assert_eq!(indefinite[0], 0x84);
    indefinite[0] = 0x9f;
    indefinite.push(0xff);
    reject(
        "reject/indefinite-length-array",
        "checkpoint",
        indefinite,
        "encoding",
    );

    let ct_leaves = [
        "",
        "00",
        "10",
        "2021",
        "3031",
        "40414243",
        "5051525354555657",
        "606162636465666768696a6b6c6d6e6f",
    ];
    let ct_data: Vec<Vec<u8>> = ct_leaves.iter().map(|x| hex::decode(x).unwrap()).collect();
    let ct_roots: Vec<String> = (1..=8).map(|n| h(root(&ct_data[..n]).0)).collect();

    // RFC 8032 §7.1 TEST 1 (empty message), for Ed25519 cross-checks.
    let rfc_sk = SigningKey::from_bytes(
        &hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let rfc_sig = rfc_sk.sign(b"");
    assert_eq!(
        h(rfc_sig.to_bytes()),
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        "RFC 8032 TEST 1"
    );

    json!({
        "fpp_version": FPP_VERSION,
        "about": "FPP v1 interop vectors. Generated by crates/fpp-crypto/tests/golden.rs; checked by that test and by interop/python/fpp_interop.py. Verification order and categories: docs/anticheat/04-protocol.md §2.1.",
        "ticks_per_epoch": TICKS_PER_EPOCH,
        "keys": keys.iter().map(|k| json!({
            "name": k.name, "role": k.role_name, "alg": alg::EDDSA, "known": k.known,
            "public": h(k.signer.verifying_key().to_bytes()),
            "kid": h(k.signer.kid().0),
            "key_digest": h(key_digest(&k.signer.verifying_key()).0),
        })).collect::<Vec<_>>(),
        "ed25519_rfc8032": [{
            "public": h(rfc_sk.verifying_key().to_bytes()), "message": "", "signature": h(rfc_sig.to_bytes()),
        }],
        "merkle_ct": {"leaves": ct_leaves, "roots": ct_roots, "empty_root": h(root_from_leaf_hashes(&[]).0),
                      "leaf_hash_of_empty": h(leaf_hash(b"").0)},
        "objects": objects,
    })
}

fn check_with_rust(v: &Json) {
    let mut keyset = KeySet::default();
    for k in v["keys"].as_array().unwrap() {
        if !k["known"].as_bool().unwrap() {
            continue;
        }
        let role = match k["role"].as_str().unwrap() {
            "session" => KeyRole::Session,
            "gs_instance" => KeyRole::GsInstance,
            "log" => KeyRole::Log,
            "verifier_ar" => KeyRole::VerifierAr,
            "broker_sat" => KeyRole::BrokerSat,
            "server_liveness" => KeyRole::ServerLiveness,
            "enforcement" => KeyRole::Enforcement,
            other => panic!("role {other}"),
        };
        let pk: [u8; 32] = hex::decode(k["public"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        keyset.insert_ed25519(role, ed25519_dalek::VerifyingKey::from_bytes(&pk).unwrap());
    }
    for o in v["objects"].as_array().unwrap() {
        let name = o["name"].as_str().unwrap();
        let cose = hex::decode(o["cose"].as_str().unwrap()).unwrap();
        let result =
            match o["type"].as_str().unwrap() {
                "input-commit" => verify::<InputCommit>(&cose, &keyset)
                    .map(|x| (commit_json(&x.payload), x.digest)),
                "checkpoint" => verify::<Checkpoint>(&cose, &keyset)
                    .map(|x| (checkpoint_json(&x.payload), x.digest)),
                "admit-pop" => verify::<AdmitPop>(&cose, &keyset)
                    .map(|x| (admit_pop_json(&x.payload), x.digest)),
                "attestation-result" => verify::<AttestationResult>(&cose, &keyset)
                    .map(|x| (ar_json(&x.payload), x.digest)),
                "sat" => verify::<SessionAdmissionToken>(&cose, &keyset)
                    .map(|x| (sat_json(&x.payload), x.digest)),
                "sar" => verify::<ServerAttestationResult>(&cose, &keyset)
                    .map(|x| (sar_json(&x.payload), x.digest)),
                "revocation" => verify::<RevocationEvent>(&cose, &keyset)
                    .map(|x| (revocation_json(&x.payload), x.digest)),
                other => panic!("type {other}"),
            };
        match o["expect"].as_str().unwrap() {
            "valid" => {
                let (payload, digest) = result.unwrap_or_else(|e| panic!("{name}: {e}"));
                assert_eq!(payload, o["payload"], "{name}");
                assert_eq!(h(digest.0), o["digest"].as_str().unwrap(), "{name}");
            }
            _ => {
                let err = result
                    .err()
                    .unwrap_or_else(|| panic!("{name} verified but must be rejected"));
                assert_eq!(
                    err.category(),
                    o["category"].as_str().unwrap(),
                    "{name}: {err}"
                );
            }
        }
    }
}

#[test]
fn golden_vectors_match_committed_file() {
    let vectors = build();
    check_with_rust(&vectors);
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../interop/vectors/fpp1.json");
    let rendered = serde_json::to_string_pretty(&vectors).unwrap() + "\n";
    if std::env::var_os("FPP_REGEN_VECTORS").is_some() {
        std::fs::write(&path, &rendered).unwrap();
    }
    let committed = std::fs::read_to_string(&path)
        .expect("interop/vectors/fpp1.json missing; run with FPP_REGEN_VECTORS=1");
    assert!(
        committed == rendered,
        "interop/vectors/fpp1.json is stale; if the change is intended, regenerate with FPP_REGEN_VECTORS=1 and re-run the Python verifier"
    );
}
