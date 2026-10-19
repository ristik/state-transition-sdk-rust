#![cfg(all(feature = "std", feature = "client"))]
//! The shared UTB V2 history vectors (`tests/fixtures/utb/v1`, generated from Go by
//! `generator/`, identical in the JS and Rust SDKs). Every expectation is the Go reference's
//! (`utbstore.Open/Append`, `gettrustbase` bundle functions).

use serde_json::Value;
use unicity_token::api::bft::{Appended, HistoryError, TrustBaseEntry, TrustBaseHistory};
use unicity_token::crypto::hash::sha256;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/utb/v1");

fn load() -> Value {
    let raw = std::fs::read(format!("{DIR}/utb-vectors-v1.json")).unwrap();
    // the file is byte-identical in both SDKs: pinned by the manifest
    let manifest = std::fs::read_to_string(format!("{DIR}/manifest.sha256")).unwrap();
    let want = manifest
        .lines()
        .find(|l| l.ends_with("  utb-vectors-v1.json"))
        .and_then(|l| l.split_whitespace().next())
        .unwrap();
    assert_eq!(hex::encode(sha256(&raw).data()), want, "vector file digest");
    serde_json::from_slice(&raw).unwrap()
}

fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn id32(v: &Value) -> [u8; 32] {
    bytes(v).try_into().unwrap()
}

/// The history of the first `held` epochs of the vector chain.
fn held(chain: &[Value], held: u64) -> TrustBaseHistory {
    let mut h = TrustBaseHistory::from_genesis(
        TrustBaseEntry::from_cbor(&bytes(&chain[0]["hex"])).unwrap(),
        None,
    )
    .unwrap();
    for c in &chain[1..held as usize] {
        assert_eq!(
            h.append(TrustBaseEntry::from_cbor(&bytes(&c["hex"])).unwrap())
                .unwrap(),
            Appended::Added
        );
    }
    h
}

#[test]
fn chain_identities_match_go() {
    let v = load();
    for c in v["chain"].as_array().unwrap() {
        let e = TrustBaseEntry::from_cbor(&bytes(&c["hex"])).unwrap();
        assert_eq!(e.to_cbor(), bytes(&c["hex"]), "epoch {}", e.epoch);
        assert_eq!(e.sig_bytes(), bytes(&c["sigBytes"]), "epoch {}", e.epoch);
        assert_eq!(e.entry_id(), id32(&c["entryId"]), "epoch {}", e.epoch);
    }
    assert_eq!(
        TrustBaseEntry::from_cbor(&bytes(&v["chain"][0]["hex"]))
            .unwrap()
            .entry_id(),
        id32(&v["pin"])
    );
}

#[test]
fn genesis_cases() {
    let v = load();
    for c in v["genesisCases"].as_array().unwrap() {
        let id = c["id"].as_str().unwrap();
        let got = TrustBaseEntry::from_cbor(&bytes(&c["input"]))
            .map_err(HistoryError::from)
            .and_then(|e| TrustBaseHistory::from_genesis(e, Some(id32(&c["pin"]))));
        assert_eq!(got.is_ok(), c["valid"].as_bool().unwrap(), "{id}: {got:?}");
    }
}

#[test]
fn entry_cases() {
    let v = load();
    let chain = v["chain"].as_array().unwrap();
    for c in v["entryCases"].as_array().unwrap() {
        let id = c["id"].as_str().unwrap();
        let mut h = held(chain, c["held"].as_u64().unwrap());
        let input = bytes(&c["input"]);
        let (result, epoch) = match TrustBaseEntry::from_cbor(&input) {
            Err(_) => ("refused", None),
            Ok(e) => {
                let epoch = e.epoch;
                let r = match h.append(e) {
                    Ok(Appended::Added) => "appended",
                    Ok(Appended::AlreadyHeld) => "noop",
                    Err(HistoryError::Gap { .. }) => "gap",
                    Err(HistoryError::Conflict { .. }) => "conflict",
                    Err(_) => "refused",
                };
                (r, Some(epoch))
            }
        };
        let want = &c["expected"];
        assert_eq!(result, want["result"].as_str().unwrap(), "{id}");
        assert_eq!(
            h.latest().epoch,
            want["tipAfter"].as_u64().unwrap(),
            "{id}: tip"
        );
        if let (Some(b), Some(epoch)) = (c.get("heldBytesAfter"), epoch) {
            assert_eq!(
                h.get(epoch).unwrap().to_cbor(),
                bytes(b),
                "{id}: held bytes"
            );
        }
    }
}

#[test]
fn bundle_cases() {
    let v = load();
    let chain = v["chain"].as_array().unwrap();
    for c in v["bundleCases"].as_array().unwrap() {
        let id = c["id"].as_str().unwrap();
        let input = bytes(&c["input"]);
        let standalone = TrustBaseHistory::from_bundle(&input, None);
        let ok = c["decodes"].as_bool().unwrap() && c["verifies"].as_bool().unwrap();
        assert_eq!(standalone.is_ok(), ok, "{id}: {standalone:?}");
        if let Some(n) = c.get("held").and_then(Value::as_u64) {
            let mut h = held(chain, n);
            let got = match h.install_bundle(&input) {
                Ok(Appended::Added) => "appended",
                Ok(Appended::AlreadyHeld) => "noop",
                Err(_) => "refused",
            };
            assert_eq!(got, c["install"].as_str().unwrap(), "{id}");
            assert_eq!(
                h.latest().epoch,
                c["tipAfter"].as_u64().unwrap(),
                "{id}: tip"
            );
        }
    }
}
