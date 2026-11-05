//! The shared GetTrustBase response vectors (bft-core 5d9a8eaa, `tests/vectors/gettrustbase`) against the page decoder.
#![cfg(feature = "std")]

use serde_json::Value;
use unicity_token::api::bft::trust_base_range::{RangeError, TrustBaseRange, PAGE_LIMITS};
use unicity_token::api::NetworkId;

fn vectors() -> Value {
    serde_json::from_str(include_str!("vectors/gettrustbase/vectors.json")).unwrap()
}

fn hx(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

#[test]
fn the_vendored_file_is_the_pinned_one() {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(include_bytes!("vectors/gettrustbase/vectors.json"));
    assert_eq!(
        hex::encode(digest),
        "3f9732fa5d5bed202d326f452f732d625040dbfac81857e19574df25bde3734c"
    );
}

#[test]
fn every_case_decodes_or_is_refused_as_the_vectors_say() {
    let v = vectors();
    let network = NetworkId::new(v["network"].as_u64().unwrap() as u16).unwrap();
    let cases = v["cases"].as_array().unwrap();
    let (mut accepted, mut encoding, mut response) = (0, 0, 0);
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let bytes = hx(&c["hex"]);
        let got = TrustBaseRange::decode(&bytes, &PAGE_LIMITS, network);
        match c.get("error").and_then(Value::as_str) {
            None => {
                let r = got.unwrap_or_else(|e| panic!("{name}: {e}"));
                accepted += 1;
                assert_eq!(r.status.wire(), c["status"].as_u64().unwrap(), "{name}");
                assert_eq!(r.from_epoch, c["fromEpoch"].as_u64().unwrap(), "{name}");
                assert_eq!(
                    r.effective_end,
                    c["effectiveEnd"].as_u64().unwrap(),
                    "{name}"
                );
                assert_eq!(
                    r.end_entry_id.map(hex::encode),
                    c.get("endEntryId")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    "{name}"
                );
                let epochs: Vec<u64> = c
                    .get("entryEpochs")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().map(|e| e.as_u64().unwrap()).collect())
                    .unwrap_or_default();
                assert_eq!(
                    r.entries.iter().map(|e| e.epoch).collect::<Vec<_>>(),
                    epochs,
                    "{name}"
                );
                assert_eq!(
                    r.next_epoch,
                    c.get("nextEpoch").and_then(Value::as_u64),
                    "{name}"
                );
            }
            Some(class) => {
                let e = got.expect_err(name);
                // Go labels a junk embedded entry a response failure (the entry's decode error is wrapped); here it is the entry's own encoding error.
                let want_encoding = class == "encoding" || name.contains("not a version 2 entry");
                match (&e, want_encoding) {
                    (RangeError::Encoding(_), true) => encoding += 1,
                    (RangeError::Response(_), false) => response += 1,
                    _ => panic!("{name}: class {class}, got {e:?}"),
                }
            }
        }
    }
    assert_eq!(accepted + encoding + response, cases.len());
    assert!(accepted > 0 && encoding > 0 && response > 0);
}

#[test]
fn a_response_for_another_network_is_refused() {
    let v = vectors();
    let c = &v["cases"][0];
    let other = NetworkId::new(6).unwrap();
    assert!(matches!(
        TrustBaseRange::decode(&hx(&c["hex"]), &PAGE_LIMITS, other),
        Err(RangeError::Response(_))
    ));
}
