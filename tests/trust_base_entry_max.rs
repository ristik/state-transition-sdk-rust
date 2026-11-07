//! The shared maximum-size entry (bft-go-base 81ee667, `tests/vectors/trust-base-v2-max`): 256 members with 128-byte node ids and the signatures of
//! all 256 predecessors, 95,365 bytes under the 128 KiB cap.
#![cfg(feature = "std")]

use serde_json::Value;
use sha2::{Digest, Sha256};
use unicity_token::api::bft::trust_base_entry::MAX_ENTRY_BYTES;
use unicity_token::api::bft::{TrustBaseEntry, TrustBaseError};

const FILE: &[u8] = include_bytes!("vectors/trust-base-v2-max/max-entry.json");

fn fixture() -> Value {
    serde_json::from_slice(FILE).unwrap()
}

fn hx(v: &Value, key: &str) -> Vec<u8> {
    hex::decode(v[key].as_str().unwrap()).unwrap()
}

#[test]
fn the_vendored_file_is_the_pinned_one() {
    assert_eq!(
        hex::encode(Sha256::digest(FILE)),
        "c4c5970307c1780fa08108529e3ef9e37803726b6df1843d61c8421f97a795b6"
    );
}

#[test]
fn the_largest_valid_entry_round_trips_and_verifies_from_its_genesis() {
    let v = fixture();
    let genesis = TrustBaseEntry::from_cbor(&hx(&v, "genesis")).unwrap();
    let entry_bytes = hx(&v, "entry");
    assert_eq!(entry_bytes.len() as u64, v["entryBytes"].as_u64().unwrap());
    assert!(entry_bytes.len() < MAX_ENTRY_BYTES && entry_bytes.len() > 64 * 1024);
    let entry = TrustBaseEntry::from_cbor(&entry_bytes).unwrap();
    assert_eq!(entry.members.len(), 256);
    assert!(entry.members.iter().all(|m| m.node_id.len() == 128));
    assert_eq!(entry.signatures.as_ref().unwrap().len(), 256);
    // identities
    assert_eq!(
        hex::encode(genesis.entry_id()),
        v["genesisId"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(entry.entry_id()),
        v["entryId"].as_str().unwrap()
    );
    // re-encoding is the same bytes
    assert_eq!(entry.to_cbor(), entry_bytes);
    assert_eq!(genesis.to_cbor(), hx(&v, "genesis"));
    // 256 strict signatures verify from the genesis
    genesis.verify_genesis().unwrap();
    entry.verify_successor(&genesis).unwrap();
}

#[test]
fn an_entry_over_128_kib_is_refused_by_size() {
    let v = fixture();
    let mut padded = hx(&v, "entry");
    padded.resize(MAX_ENTRY_BYTES, 0);
    // exactly the cap is not a size refusal (the trailing bytes are another one)
    let at_cap = TrustBaseEntry::from_cbor(&padded).unwrap_err();
    assert!(!format!("{at_cap}").contains("size bound"), "{at_cap}");
    padded.push(0);
    let over = TrustBaseEntry::from_cbor(&padded).unwrap_err();
    assert!(
        matches!(over, TrustBaseError::Encoding(m) if m.contains("size bound")),
        "{over}"
    );
}
