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

#[test]
fn the_budgets_are_exact() {
    use unicity_token::api::bft::trust_base_range::RangeLimits;
    let v = vectors();
    let network = NetworkId::new(v["network"].as_u64().unwrap() as u16).unwrap();
    let bytes = hx(&v["cases"][0]["hex"]); // the complete history: three entries
    let at = |max_bytes, max_entries| RangeLimits {
        max_bytes,
        max_entries,
    };
    assert!(TrustBaseRange::decode(&bytes, &at(bytes.len(), 3), network).is_ok());
    assert!(matches!(
        TrustBaseRange::decode(&bytes, &at(bytes.len() - 1, 3), network),
        Err(RangeError::Encoding(_))
    ));
    assert!(matches!(
        TrustBaseRange::decode(&bytes, &at(bytes.len(), 2), network),
        Err(RangeError::Response(_))
    ));
}

fn raw_page(network: u16, from: u64, end: u64, end_id: &[u8; 32], items: &[Vec<u8>]) -> Vec<u8> {
    use unicity_token::cbor::{
        encode_array, encode_byte_string, encode_null, encode_tag, encode_uint,
    };
    let refs: Vec<&[u8]> = items.iter().map(Vec::as_slice).collect();
    encode_tag(
        39015,
        &encode_array(&[
            &encode_uint(1),
            &encode_uint(u64::from(network)),
            &encode_uint(0),
            &encode_uint(from),
            &encode_uint(end),
            &encode_byte_string(end_id),
            &encode_array(&refs),
            &encode_null(),
        ]),
    )
}

/// The shared maximum-size entry (bft-go-base 81ee667, `tests/vectors/trust-base-v2-max`) is one page entry well inside the 1 MiB page; an item
/// over the 128 KiB per-entry cap is refused.
#[test]
fn the_largest_entry_is_a_valid_page_and_one_over_the_cap_is_not() {
    use unicity_token::api::bft::trust_base_entry::MAX_ENTRY_BYTES;
    let v: Value =
        serde_json::from_slice(include_bytes!("vectors/trust-base-v2-max/max-entry.json")).unwrap();
    let entry = hex::decode(v["entry"].as_str().unwrap()).unwrap();
    let id: [u8; 32] = hex::decode(v["entryId"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let network = v["network"].as_u64().unwrap() as u16;
    let page = raw_page(network, 2, 2, &id, std::slice::from_ref(&entry));
    assert!(page.len() > 90_000 && page.len() < PAGE_LIMITS.max_bytes);
    let r = TrustBaseRange::decode(&page, &PAGE_LIMITS, NetworkId::new(network).unwrap()).unwrap();
    assert_eq!(
        (r.entries.len(), r.entries[0].epoch, r.next_epoch),
        (1, 2, None)
    );

    // an item above the per-entry cap, whatever it holds, is refused by size
    let big = unicity_token::cbor::encode_byte_string(&vec![0u8; MAX_ENTRY_BYTES]);
    assert!(big.len() > MAX_ENTRY_BYTES);
    let page = raw_page(network, 2, 2, &id, &[big]);
    assert!(matches!(
        TrustBaseRange::decode(&page, &PAGE_LIMITS, NetworkId::new(network).unwrap()),
        Err(RangeError::Response(m)) if m.contains("size bound")
    ));
}
