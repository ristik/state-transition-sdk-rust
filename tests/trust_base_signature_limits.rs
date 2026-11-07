#![cfg(feature = "std")]
//! The native signature ceiling of an entry (owner §49): at most 256 signatures however small the entry is.

use unicity_token::api::bft::trust_base_entry::MAX_ENTRY_SIGNATURES;
use unicity_token::api::bft::{TrustBaseEntry, TrustBaseError, TrustBaseMember};
use unicity_token::api::NetworkId;
use unicity_token::crypto::signer::{Secp256k1Signer, Signer};

fn entry_with(signatures: usize) -> TrustBaseEntry {
    let key = Secp256k1Signer::from_bytes(&[1; 32]).unwrap().public_key();
    let mut e = TrustBaseEntry::new(
        NetworkId::new(5).unwrap(),
        2,
        10,
        vec![TrustBaseMember::new("a", key, 1)],
        1,
        None,
        None,
        [7; 32],
    );
    for i in 0..signatures {
        e.add_signature(&format!("s{i:04}"), vec![0; 65]);
    }
    e
}

#[test]
fn an_entry_carries_at_most_256_signatures_however_small_it_is() {
    assert_eq!(MAX_ENTRY_SIGNATURES, 256);
    // 256 signatures (not verified here) decode: a one-member entry handed over by a 256-member committee
    let at_cap = entry_with(256);
    assert_eq!(
        TrustBaseEntry::from_cbor(&at_cap.to_cbor()).unwrap(),
        at_cap
    );
    // a 257th is refused by the decoder before it is copied, whatever the entry's size
    let over = entry_with(257);
    let bytes = over.to_cbor();
    assert!(
        bytes.len() < 128 << 10,
        "well inside the byte cap: the count is what refuses it"
    );
    assert!(
        matches!(TrustBaseEntry::from_cbor(&bytes), Err(TrustBaseError::Encoding(m)) if m == "too many signatures")
    );
}

#[test]
fn a_supplied_witness_over_256_signatures_is_refused_before_any_check() {
    let prev = entry_with(0);
    let sigs = |n: usize| -> Vec<(String, Vec<u8>)> {
        (0..n).map(|_| ("a".into(), vec![0u8; 65])).collect()
    };
    // 257 junk signatures: refused for their number, not for the first thing wrong with one of them
    let over = prev
        .verify_quorum_signatures(b"data", &sigs(257))
        .unwrap_err();
    assert!(
        matches!(&over, TrustBaseError::Signature(m) if m == "too many signatures"),
        "{over}"
    );
    // 256 get as far as the per-signature rules (the first junk signature does not verify)
    let at_cap = prev
        .verify_quorum_signatures(b"data", &sigs(256))
        .unwrap_err();
    assert!(
        matches!(&at_cap, TrustBaseError::Signature(m) if m != "too many signatures"),
        "{at_cap}"
    );
}
