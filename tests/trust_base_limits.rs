#![cfg(all(feature = "std", feature = "client"))]
//! The native limits (owner §49): 256 members per entry, 256 predecessor signatures however small the successor, 128 operating validators.

use unicity_token::api::bft::trust_base_entry::MAX_MEMBERS;
use unicity_token::api::bft::{Appended, TrustBaseEntry, TrustBaseHistory, TrustBaseMember};
use unicity_token::api::NetworkId;
use unicity_token::crypto::signer::{Secp256k1Signer, Signer};

fn signer(i: usize) -> Secp256k1Signer {
    let mut k = [0u8; 32];
    k[30] = ((i + 1) >> 8) as u8;
    k[31] = ((i + 1) & 0xff) as u8;
    Secp256k1Signer::from_bytes(&k).unwrap()
}

fn id(i: usize) -> String {
    format!("n{i:03}")
}

fn members(n: usize) -> Vec<TrustBaseMember> {
    (0..n)
        .map(|i| TrustBaseMember::new(id(i), signer(i).public_key(), 1))
        .collect()
}

fn genesis(n: usize) -> TrustBaseEntry {
    TrustBaseEntry::genesis(NetworkId::new(5).unwrap(), 1, 1, members(n))
}

/// Epoch 2 with `m` members, signed by the first `signers` members of `prev`.
fn successor(prev: &TrustBaseEntry, m: usize, signers: usize) -> TrustBaseEntry {
    let mut e = TrustBaseEntry::new(
        NetworkId::new(5).unwrap(),
        prev.epoch + 1,
        prev.epoch_start + 10,
        members(m),
        TrustBaseEntry::threshold_for(m as u64).unwrap(),
        None,
        None,
        prev.entry_id(),
    );
    for i in 0..signers {
        e.sign(&id(i), &signer(i));
    }
    e
}

#[test]
fn committees_of_128_and_256_members_round_trip_and_chain() {
    for n in [128usize, 256] {
        let g = genesis(n);
        assert_eq!(
            TrustBaseEntry::from_cbor(&g.to_cbor()).unwrap(),
            g,
            "{n} members"
        );
        let all_sign = successor(&g, n, n); // every member of the predecessor signs
        let bytes = all_sign.to_cbor();
        assert_eq!(TrustBaseEntry::from_cbor(&bytes).unwrap(), all_sign);
        let mut h = TrustBaseHistory::from_genesis(g, None).unwrap();
        assert_eq!(
            h.append(all_sign),
            Ok(Appended::Added),
            "{n} members, all signatures"
        );
    }
}

#[test]
fn more_than_256_members_are_refused() {
    assert_eq!(MAX_MEMBERS, 256);
    let too_many = TrustBaseEntry::genesis(NetworkId::new(5).unwrap(), 1, 1, members(257));
    assert!(too_many.verify_genesis().is_err(), "257 members");
    assert!(
        TrustBaseEntry::from_cbor(&too_many.to_cbor()).is_err(),
        "257 members do not decode"
    );
}

#[test]
fn a_256_member_predecessor_signs_a_four_member_successor() {
    let g = genesis(256);
    // the successor is small, its witness is the old committee's: all 256 signatures count against the predecessor, not the successor
    let small = successor(&g, 4, 256);
    assert_eq!(small.signatures.as_ref().unwrap().len(), 256);
    small.verify_successor(&g).unwrap();
    let mut h = TrustBaseHistory::from_genesis(g.clone(), None).unwrap();
    assert_eq!(h.append(small.clone()), Ok(Appended::Added));
    assert_eq!(TrustBaseEntry::from_cbor(&small.to_cbor()).unwrap(), small);
    // the other direction: 4 members sign a 256-member successor
    let g4 = genesis(4);
    let big = successor(&g4, 256, 4);
    big.verify_successor(&g4).unwrap();
}
