#![cfg(all(feature = "std", feature = "client"))]
//! The shared B1 UC seal vectors (`tests/fixtures/b1-seals/v1`, derived from bft-core's `b1ref`
//! any-age corpus; identical in the JS and Rust SDKs). The verdict of every case must equal
//! B1's: `valid` verifies; `invalid` (a well-formed certificate B1 judges false) and `malformed`
//! (B1 refuses the input before evaluation) are both errors here.

use serde_json::Value;
use unicity_token::api::bft::{
    TrustBaseEntry, TrustBaseHistory, TrustBaseMember, UnicityCertificate,
};
use unicity_token::api::NetworkId;
use unicity_token::crypto::hash::sha256;
use unicity_token::crypto::signature::PublicKey;
use unicity_token::verify::{verify_certificate_of_partition, SealSession};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/b1-seals/v1");

fn load() -> Value {
    let raw = std::fs::read(format!("{DIR}/b1-seal-vectors-v1.json")).unwrap();
    let manifest = std::fs::read_to_string(format!("{DIR}/manifest.sha256")).unwrap();
    let want = manifest
        .lines()
        .find(|l| l.ends_with("  b1-seal-vectors-v1.json"))
        .and_then(|l| l.split_whitespace().next())
        .unwrap();
    assert_eq!(hex::encode(sha256(&raw).data()), want, "vector file digest");
    serde_json::from_slice(&raw).unwrap()
}

fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

/// The committees as a trusted history: the entries are the corpus' epochs, chained by identity
/// (the corpus has no predecessor signatures; the seal rule is what is under test).
fn history(case: &Value) -> TrustBaseHistory {
    let network = NetworkId::new(case["network"].as_u64().unwrap() as u16).unwrap();
    let mut entries: Vec<TrustBaseEntry> = Vec::new();
    for e in case["epochs"].as_array().unwrap() {
        let members = e["members"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| {
                TrustBaseMember::new(
                    m["nodeId"].as_str().unwrap(),
                    PublicKey::from_bytes(&bytes(&m["key"])).unwrap(),
                    m["weight"].as_u64().unwrap(),
                )
            })
            .collect();
        let mut entry = TrustBaseEntry::genesis(
            network,
            e["epoch"].as_u64().unwrap(),
            e["start"].as_u64().unwrap(),
            members,
        );
        assert_eq!(entry.quorum_threshold, e["threshold"].as_u64().unwrap());
        if let Some(prev) = entries.last() {
            entry.previous_entry_id = prev.entry_id();
            // a placeholder witness: the chain is trusted, not re-verified
            entry.add_signature("x", vec![0; 65]);
        }
        if let (Some(prev), end) = (entries.last(), e["start"].as_u64().unwrap()) {
            let declared = prev_end(case, prev.epoch);
            assert_eq!(
                declared,
                Some(end),
                "the corpus' interval end is the next start"
            );
        }
        entries.push(entry);
    }
    TrustBaseHistory::from_trusted_chain(entries).unwrap()
}

fn prev_end(case: &Value, epoch: u64) -> Option<u64> {
    case["epochs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["epoch"].as_u64() == Some(epoch))
        .and_then(|e| e["end"].as_u64())
}

#[test]
fn every_case_has_the_b1_verdict() {
    let v = load();
    let mut failures = Vec::new();
    let mut count = [0usize; 3];
    for c in v["cases"].as_array().unwrap() {
        let id = c["id"].as_str().unwrap();
        let verdict = c["verdict"].as_str().unwrap();
        // B1 re-encodes byte-exactly: a decoded `null` path collection stays `null`
        // (two of the valid certificates carry one), whatever else is encoded
        if verdict == "valid" {
            let uc =
                UnicityCertificate::from_cbor(unicity_token::cbor::Decoder::new(&bytes(&c["uc"])))
                    .unwrap();
            assert_eq!(
                uc.to_cbor(),
                bytes(&c["uc"]),
                "{id}: re-encoding is byte-exact"
            );
        }
        let history = history(c);
        let partition = c["expectedPartition"].as_u64().unwrap() as u32;
        let got =
            UnicityCertificate::from_cbor(unicity_token::cbor::Decoder::new(&bytes(&c["uc"])))
                .map_err(|e| format!("decode: {e:?}"))
                .and_then(|uc| {
                    verify_certificate_of_partition(
                        &mut SealSession::new(&history),
                        &uc,
                        partition,
                        &[0; 32],
                    )
                    .map_err(|e| format!("verify: {e}"))
                });
        match (verdict, &got) {
            ("valid", Ok(())) => count[0] += 1,
            ("invalid", Err(_)) => count[1] += 1,
            ("malformed", Err(_)) => count[2] += 1,
            _ => failures.push(format!(
                "{id}: B1 says {verdict} ({}), Rust says {got:?}",
                c["b1Sentinel"].as_str().unwrap_or("-")
            )),
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} cases differ ({:?} ok):\n{}",
        failures.len(),
        v["cases"].as_array().unwrap().len(),
        count,
        failures.join("\n")
    );
}
