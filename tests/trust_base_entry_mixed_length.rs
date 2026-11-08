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

/// 256 members with 128-byte ids and 256 predecessor signatures: the largest entry the bounds allow (about 95,400 bytes) round-trips, the
/// 128 KiB cap is exact.
#[test]
fn the_largest_entry_round_trips_under_the_128_kib_cap() {
    use unicity_token::api::bft::trust_base_entry::{
        MAX_ENTRY_BYTES, MAX_MEMBERS, MAX_NODE_ID_LEN,
    };
    assert_eq!(MAX_ENTRY_BYTES, 128 * 1024);
    let ids: Vec<String> = (0..MAX_MEMBERS)
        .map(|i| format!("{:0>width$}", i, width = MAX_NODE_ID_LEN))
        .collect();
    // 256 distinct compressed keys
    let keys: Vec<_> = (0..MAX_MEMBERS)
        .map(|i| {
            let mut k = [0u8; 32];
            k[30] = (i / 255) as u8 + 1;
            k[31] = (i % 255) as u8 + 1;
            Secp256k1Signer::from_bytes(&k).unwrap().public_key()
        })
        .collect();
    let members = || -> Vec<TrustBaseMember> {
        ids.iter()
            .zip(&keys)
            .map(|(id, k)| TrustBaseMember::new(id.clone(), k.clone(), 1))
            .collect()
    };
    let g = TrustBaseEntry::genesis(NetworkId::new(7).unwrap(), 1, 1, members());
    let mut e = TrustBaseEntry::new(
        g.network_id,
        2,
        2,
        members(),
        TrustBaseEntry::threshold_for(MAX_MEMBERS as u64).unwrap(),
        Some(vec![9; 32]),
        Some(vec![8; 32]),
        g.entry_id(),
    );
    for id in &ids {
        e.add_signature(id, vec![0x42; 65]);
    }
    let bytes = e.to_cbor();
    assert!(
        (90_000..=100_000).contains(&bytes.len()),
        "{} bytes",
        bytes.len()
    );
    let back = TrustBaseEntry::from_cbor(&bytes).unwrap();
    assert_eq!(back, e);
    assert_eq!(back.to_cbor(), bytes);
    // the cap is exact: this entry is far below it; a buffer one byte over it is refused before anything is read
    assert!(TrustBaseEntry::from_cbor(&vec![0u8; MAX_ENTRY_BYTES + 1]).is_err());
    let mut padded = bytes.clone();
    padded.resize(MAX_ENTRY_BYTES, 0);
    // trailing bytes are a different refusal, but not the size one
    let e1 = TrustBaseEntry::from_cbor(&padded).unwrap_err();
    assert!(!format!("{e1}").contains("size bound"), "{e1}");
    padded.push(0);
    let e2 = TrustBaseEntry::from_cbor(&padded).unwrap_err();
    assert!(format!("{e2}").contains("size bound"), "{e2}");
}
