//! Signer ids of different lengths: the wire order of the signature map is canonical CBOR
//! (shorter key first) while the in-memory order is raw byte order. Go and JS accept these
//! bytes; so must the decoder, and the entry must round-trip.
#![cfg(all(feature = "std", feature = "client"))]

use unicity_token::api::bft::{TrustBaseEntry, TrustBaseMember};
use unicity_token::api::NetworkId;
use unicity_token::crypto::signer::{Secp256k1Signer, Signer};

fn signer(i: u8) -> Secp256k1Signer {
    Secp256k1Signer::from_bytes(&[i; 32]).unwrap()
}

fn pair() -> (TrustBaseEntry, TrustBaseEntry) {
    // raw byte order: node1 < node10 < node2; canonical CBOR order: node1, node2, node10
    let ids = [("node1", 1u8), ("node10", 2), ("node2", 3)];
    let ms = || -> Vec<TrustBaseMember> {
        ids.iter()
            .map(|(id, k)| TrustBaseMember::new(*id, signer(*k).public_key(), 1))
            .collect()
    };
    let g = TrustBaseEntry::genesis(NetworkId::new(7).unwrap(), 1, 1, ms());
    let mut e = TrustBaseEntry::new(
        g.network_id,
        2,
        2,
        ms(),
        TrustBaseEntry::threshold_for(3).unwrap(),
        Some(vec![9; 32]),
        None,
        g.entry_id(),
    );
    for (id, k) in ids {
        e.sign(id, &signer(k));
    }
    (g, e)
}

#[test]
fn signer_ids_of_different_lengths_round_trip_and_verify() {
    let (g, e) = pair();
    let ids: Vec<&str> = e
        .signatures
        .as_ref()
        .unwrap()
        .iter()
        .map(|(i, _)| i.as_str())
        .collect();
    assert_eq!(
        ids,
        ["node1", "node10", "node2"],
        "in-memory raw byte order"
    );
    e.verify_successor(&g).unwrap();
    let bytes = e.to_cbor();
    let back = TrustBaseEntry::from_cbor(&bytes).unwrap();
    assert_eq!(back, e);
    assert_eq!(back.to_cbor(), bytes);
    assert_eq!(back.entry_id(), e.entry_id());
    back.verify_successor(&g).unwrap();
}

#[test]
fn a_non_canonical_wire_order_of_the_signatures_is_still_refused() {
    let (_, e) = pair();
    let bytes = e.to_cbor();
    // exchange the keys node1 and node2 on the wire: the map is then out of canonical order
    let k1 = bytes.windows(6).rposition(|w| w == b"\x65node1").unwrap();
    let k2 = bytes.windows(6).rposition(|w| w == b"\x65node2").unwrap();
    // the last occurrences are the signature map's; the first are the member list's
    let first = bytes.windows(6).position(|w| w == b"\x65node1").unwrap();
    assert!(k1 > first);
    let mut swapped = bytes.clone();
    swapped[k1..k1 + 6].copy_from_slice(b"\x65node2");
    swapped[k2..k2 + 6].copy_from_slice(b"\x65node1");
    let err = TrustBaseEntry::from_cbor(&swapped).unwrap_err();
    assert!(matches!(
        err,
        unicity_token::api::bft::TrustBaseError::Encoding(_)
    ));
}

#[test]
fn mixed_length_signer_ids_through_append_and_the_bundle_round_trip() {
    use unicity_token::api::bft::TrustBaseHistory;
    let (g, e) = pair();
    let mut h = TrustBaseHistory::from_genesis(g.clone(), Some(g.entry_id())).unwrap();
    h.append(e.clone()).unwrap();
    let bundle = h.to_bundle();
    let back = TrustBaseHistory::from_bundle(&bundle, Some(g.entry_id())).unwrap();
    assert_eq!(back.latest().entry_id(), e.entry_id());
    assert_eq!(back.to_bundle(), bundle);
    let mut fresh = TrustBaseHistory::from_genesis(g.clone(), Some(g.entry_id())).unwrap();
    fresh.install_bundle(&bundle).unwrap();
    assert_eq!(fresh.latest().entry_id(), e.entry_id());
}
