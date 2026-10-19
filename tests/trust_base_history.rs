#![cfg(all(feature = "std", feature = "client"))]
//! Trust base V2 entries and the append-only history (bft-go-base `RootTrustBaseV2`).

use unicity_token::api::bft::trust_base_entry::TRUST_BASE_TAG;
use unicity_token::api::bft::{
    Appended, HistoryError, TrustBaseEntry, TrustBaseError, TrustBaseHistory, TrustBaseMember,
};
use unicity_token::api::NetworkId;
use unicity_token::crypto::signer::{Secp256k1Signer, Signer};

const NET: u16 = 5;

fn signer(i: u8) -> Secp256k1Signer {
    Secp256k1Signer::from_bytes(&[i; 32]).unwrap()
}

fn members(ids: &[(&str, u8, u64)]) -> Vec<TrustBaseMember> {
    ids.iter()
        .map(|(id, k, w)| TrustBaseMember {
            node_id: (*id).into(),
            signing_key: signer(*k).public_key(),
            weight: *w,
        })
        .collect()
}

fn entry(epoch: u64, start: u64, m: &[(&str, u8, u64)], prev: [u8; 32]) -> TrustBaseEntry {
    let members = members(m);
    let total: u64 = members.iter().map(|x| x.weight).sum();
    TrustBaseEntry::new(
        NetworkId::new(NET).unwrap(),
        epoch,
        start,
        members,
        TrustBaseEntry::threshold_for(total).unwrap(),
        None,
        None,
        prev,
    )
}

const FOUR: [(&str, u8, u64); 4] = [("a", 1, 1), ("b", 2, 1), ("c", 3, 1), ("d", 4, 1)];

fn genesis() -> TrustBaseEntry {
    entry(1, 1, &FOUR, [0; 32])
}

/// A successor of `prev` (members `m`) signed by the predecessor's keys of `by` (key seeds = 1..).
fn successor(prev: &TrustBaseEntry, m: &[(&str, u8, u64)], by: &[(&str, u8)]) -> TrustBaseEntry {
    let mut e = entry(prev.epoch + 1, prev.epoch_start + 10, m, prev.entry_id());
    for (id, k) in by {
        e.sign(id, &signer(*k));
    }
    e
}

const ABC: [(&str, u8); 3] = [("a", 1), ("b", 2), ("c", 3)];

#[test]
fn genesis_roundtrips_and_has_a_stable_identity() {
    let g = genesis();
    let bytes = g.to_cbor();
    assert_eq!(&bytes[..3], &[0xd9, 0x98, 0x58], "tag 39000");
    assert_eq!(TrustBaseEntry::from_cbor(&bytes).unwrap(), g);
    let mut signed = successor(&g, &FOUR, &ABC);
    let id = signed.entry_id();
    signed.add_signature("d", vec![0; 65]);
    assert_eq!(signed.entry_id(), id, "the identity ignores the signatures");
    assert_eq!(
        g.sig_bytes(),
        bytes,
        "a genesis entry's signature field is already null"
    );
}

#[test]
fn go_encoding_of_a_genesis_decodes_and_reencodes_identically() {
    // bft-go-base RootTrustBaseV2 genesis, nil hashes (null), produced by MarshalCBOR
    let hex = "d998588a02050101848361615821031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f018361625821024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d076601836163582102531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe33701836164582103462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b0103f6f658200000000000000000000000000000000000000000000000000000000000000000f6";
    let bytes = hex::decode(hex).unwrap();
    let e = TrustBaseEntry::from_cbor(&bytes).unwrap();
    assert!(e.is_genesis());
    assert_eq!(e.state_hash, None);
    assert_eq!(e.to_cbor(), bytes);
    // the empty byte string is not a wire form: the canonical absent hash is null only
    let empty = hex.replace("0103f6f658", "0103404058");
    assert_ne!(empty, hex);
    assert_eq!(
        TrustBaseEntry::from_cbor(&hex::decode(empty).unwrap()),
        Err(TrustBaseError::Encoding(
            "an absent hash is null, not an empty byte string"
        ))
    );
    // an in-memory empty value is the same entry as null: same bytes, same identity
    let mut mem = e.clone();
    mem.state_hash = Some(vec![]);
    assert_eq!(mem.to_cbor(), bytes);
    assert_eq!(mem.entry_id(), e.entry_id());
    // a present hash is exactly 32 bytes
    let mut short = e.clone();
    short.state_hash = Some(vec![7; 31]);
    assert!(short.validate().is_err());
    let mut full = e.clone();
    full.state_hash = Some(vec![7; 32]);
    assert_eq!(TrustBaseEntry::from_cbor(&full.to_cbor()).unwrap(), full);
}

#[test]
fn decoding_is_strict() {
    let g = genesis();
    let good = g.to_cbor();
    let mut tag = good.clone();
    tag[2] = 0x59; // tag 39001
    assert!(matches!(
        TrustBaseEntry::from_cbor(&tag),
        Err(TrustBaseError::Encoding(_))
    ));
    let mut version = good.clone();
    version[4] = 0x01; // record version 1
    assert!(matches!(
        TrustBaseEntry::from_cbor(&version),
        Err(TrustBaseError::Encoding(_))
    ));
    let mut trailing = good.clone();
    trailing.push(0);
    assert!(TrustBaseEntry::from_cbor(&trailing).is_err());
    assert!(TrustBaseEntry::from_cbor(&good[..good.len() - 1]).is_err());
    // non-minimal integer: epoch 1 as 0x1801
    let mut long = good.clone();
    long.splice(6..7, [0x18, 0x01]);
    assert!(
        TrustBaseEntry::from_cbor(&long).is_err(),
        "non-minimal integer"
    );
    assert_eq!(TRUST_BASE_TAG, 39000);
}

#[test]
fn structure_is_validated() {
    let bad = |m: &[(&str, u8, u64)]| {
        let mut e = entry(1, 1, m, [0; 32]);
        e.quorum_threshold =
            TrustBaseEntry::threshold_for(e.total_weight().unwrap_or(0)).unwrap_or(0);
        e.validate()
    };
    assert!(bad(&[("a", 1, 1), ("b", 2, 1)]).is_ok());
    assert!(bad(&[("b", 1, 1), ("a", 2, 1)]).is_err(), "unsorted");
    assert!(bad(&[("a", 1, 1), ("a", 2, 1)]).is_err(), "duplicate id");
    assert!(bad(&[("a", 1, 1), ("b", 1, 1)]).is_err(), "shared key");
    assert!(bad(&[("a", 1, 0)]).is_err(), "zero weight");
    assert!(bad(&[("a", 1, (1 << 40) + 1)]).is_err(), "weight bound");
    assert!(bad(&[]).is_err(), "no members");
    let mut e = genesis();
    e.quorum_threshold += 1;
    assert!(e.validate().is_err(), "threshold must be floor(2W/3)+1");
    let mut e = genesis();
    e.add_signature("a", vec![0; 65]);
    assert!(e.validate().is_err(), "genesis with signatures");
    let mut e = genesis();
    e.epoch = 0;
    assert!(e.validate().is_err());
}

#[test]
fn successor_needs_the_predecessors_strict_quorum() {
    let g = genesis();
    let ok = successor(&g, &FOUR, &ABC);
    ok.verify_successor(&g).unwrap();
    // the encoding round trip keeps the signatures
    assert_eq!(TrustBaseEntry::from_cbor(&ok.to_cbor()).unwrap(), ok);

    // below quorum
    assert!(successor(&g, &FOUR, &ABC[..2])
        .verify_successor(&g)
        .is_err());
    // unsigned
    let mut none = successor(&g, &FOUR, &ABC);
    none.signatures = None;
    assert!(none.verify_successor(&g).is_err());
    // an invalid extra fails although the others reach the quorum
    let mut extra = successor(&g, &FOUR, &ABC);
    let mut sig = extra.signatures.as_ref().unwrap()[0].1.clone();
    sig[3] ^= 1;
    extra.add_signature("d", sig);
    assert!(matches!(
        extra.verify_successor(&g),
        Err(TrustBaseError::Signature(_))
    ));
    // an unknown signer
    let mut unknown = successor(&g, &FOUR, &ABC);
    unknown.add_signature("z", unknown.signatures.as_ref().unwrap()[0].1.clone());
    assert!(unknown.verify_successor(&g).is_err());
    // a signature bound to another member
    let mut moved = successor(&g, &FOUR, &ABC[..2]);
    moved.add_signature("c", moved.signatures.as_ref().unwrap()[0].1.clone());
    assert!(moved.verify_successor(&g).is_err());
    // the current members' keys do not count, only the predecessor's
    let other = successor(
        &g,
        &[("a", 5, 1), ("b", 6, 1), ("c", 7, 1)],
        &[("a", 5), ("b", 6), ("c", 7)],
    );
    assert!(other.verify_successor(&g).is_err());
}

#[test]
fn signature_forms_are_65_byte_recoverable_only() {
    let g = genesis();
    let ok = successor(&g, &FOUR, &ABC);
    let sigs = ok.signatures.clone().unwrap();
    let with = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut e = ok.clone();
        let mut s = sigs[0].1.clone();
        f(&mut s);
        e.add_signature("a", s);
        e.verify_successor(&g)
    };
    assert!(with(&|_| {}).is_ok());
    assert!(
        with(&|s| s.truncate(64)).is_err(),
        "the 64-byte compact form"
    );
    assert!(with(&|s| s.truncate(63)).is_err());
    assert!(with(&|s| s.push(0)).is_err(), "66 bytes");
    assert!(
        with(&|s| s[64] ^= 1).is_err(),
        "the other recovery id recovers another key"
    );
    assert!(with(&|s| s[64] = 2).is_err());
    assert!(with(&|s| s.clear()).is_err());
}

#[test]
fn weights_decide_the_quorum() {
    // weights 98, 1, 1: threshold floor(200/3)+1 = 67, the first member alone is a quorum
    let w: [(&str, u8, u64); 3] = [("a", 1, 98), ("b", 2, 1), ("c", 3, 1)];
    let g = entry(1, 1, &w, [0; 32]);
    assert_eq!(g.quorum_threshold, 67);
    successor(&g, &w, &[("a", 1)]).verify_successor(&g).unwrap();
    assert!(successor(&g, &w, &[("b", 2), ("c", 3)])
        .verify_successor(&g)
        .is_err());
}

#[test]
fn chain_rules() {
    let g = genesis();
    let ok = |e: TrustBaseEntry| e.verify_successor(&g);
    let base = successor(&g, &FOUR, &ABC);
    // re-sign after each mutation so only the chain rule can fail
    let resign = |mut e: TrustBaseEntry| {
        e.signatures = None;
        for (id, k) in ABC {
            e.sign(id, &signer(k));
        }
        e
    };
    ok(base.clone()).unwrap();
    let mut e = base.clone();
    e.network_id = NetworkId::new(6).unwrap();
    assert!(matches!(ok(resign(e)), Err(TrustBaseError::Chain(_))));
    let mut e = base.clone();
    e.epoch = 3;
    assert!(matches!(ok(resign(e)), Err(TrustBaseError::Chain(_))));
    let mut e = base.clone();
    e.epoch_start = g.epoch_start;
    assert!(matches!(ok(resign(e)), Err(TrustBaseError::Chain(_))));
    let mut e = base.clone();
    e.previous_entry_id = [9; 32];
    assert!(matches!(ok(resign(e)), Err(TrustBaseError::Chain(_))));
    assert!(
        g.verify_successor(&g).is_err(),
        "genesis is not a successor"
    );
}

#[test]
fn history_is_append_only() {
    let g = genesis();
    let mut h = TrustBaseHistory::from_genesis(g.clone(), Some(g.entry_id())).unwrap();
    assert_eq!(
        TrustBaseHistory::from_genesis(g.clone(), Some([1; 32])),
        Err(HistoryError::PinMismatch)
    );

    let e2 = successor(&g, &FOUR, &ABC);
    assert_eq!(h.append(e2.clone()).unwrap(), Appended::Added);
    assert_eq!(h.latest().epoch, 2);

    // the same entry with another valid witness is a no-op and keeps the first witness
    let other_witness = successor(&g, &FOUR, &[("b", 2), ("c", 3), ("d", 4)]);
    assert_eq!(other_witness.entry_id(), e2.entry_id());
    assert_eq!(h.append(other_witness).unwrap(), Appended::AlreadyHeld);
    assert_eq!(h.get(2).unwrap().signatures, e2.signatures);

    // a different entry of a held epoch is a conflict and nothing changes
    let mut conflicting = successor(&g, &FOUR, &ABC);
    conflicting.epoch_start += 1;
    conflicting.signatures = None;
    for (id, k) in ABC {
        conflicting.sign(id, &signer(k));
    }
    let before = h.clone();
    assert_eq!(
        h.append(conflicting),
        Err(HistoryError::Conflict { epoch: 2 })
    );
    assert_eq!(h, before);

    // a gap is refused
    let e3 = successor(&e2, &FOUR, &ABC);
    let e4 = successor(&e3, &FOUR, &ABC);
    assert_eq!(
        h.append(e4.clone()),
        Err(HistoryError::Gap {
            held: 2,
            offered: 4
        })
    );

    // a bad successor is refused; a good one added; extend stops at the first refusal
    let mut forged = e3.clone();
    forged.signatures = None;
    forged.sign("a", &signer(9));
    assert!(h.append(forged).is_err());
    assert_eq!(h.extend([e3, e4]).unwrap(), 2);
    assert_eq!(h.latest().epoch, 4);
    assert!(h.get(1).is_some() && h.get(5).is_none() && h.get(0).is_none());

    // another network
    let mut foreign = successor(h.latest(), &FOUR, &ABC);
    foreign.network_id = NetworkId::new(6).unwrap();
    assert_eq!(h.append(foreign), Err(HistoryError::WrongNetwork));
}

#[test]
fn the_release_bundle_roundtrips_and_is_checked() {
    let g = genesis();
    let e2 = successor(&g, &FOUR, &ABC);
    let e3 = successor(&e2, &FOUR, &ABC);
    let mut h = TrustBaseHistory::from_genesis(g.clone(), None).unwrap();
    h.extend([e2, e3]).unwrap();
    let bundle = h.to_bundle();
    assert_eq!(&bundle[..3], &[0xd9, 0x98, 0x67], "tag 39015");
    let back = TrustBaseHistory::from_bundle(&bundle, Some(g.entry_id())).unwrap();
    assert_eq!(back, h);
    assert_eq!(back.to_bundle(), bundle);
    assert_eq!(
        TrustBaseHistory::from_bundle(&bundle, Some([7; 32])),
        Err(HistoryError::PinMismatch)
    );

    // a tampered entry (broken link) is refused; a truncated or wrong-tag bundle too
    let mut broken = h.clone();
    let e4_bad = {
        let mut e = successor(h.latest(), &FOUR, &ABC);
        e.previous_entry_id = [3; 32];
        e
    };
    assert!(broken.append(e4_bad).is_err());
    assert!(TrustBaseHistory::from_bundle(&bundle[..bundle.len() - 2], None).is_err());
    let mut wrong_tag = bundle.clone();
    wrong_tag[2] = 0x06;
    assert!(TrustBaseHistory::from_bundle(&wrong_tag, None).is_err());
}

#[test]
fn a_genesis_json_loads_to_the_pinned_identity() {
    let g = genesis();
    let nodes: Vec<String> = g
        .members
        .iter()
        .map(|m| {
            format!(
                r#"{{"nodeId":"{}","sigKey":"{}","stake":{}}}"#,
                m.node_id,
                hex::encode(m.signing_key.as_bytes()),
                m.weight
            )
        })
        .collect();
    let json = format!(
        r#"{{"version":2,"networkId":{NET},"epoch":1,"epochStartRound":1,"rootNodes":[{}],"quorumThreshold":{},"stateHash":"","changeRecordHash":null,"previousEntryId":"{}","signatures":null}}"#,
        nodes.join(","),
        g.quorum_threshold,
        "00".repeat(32)
    );
    let loaded = TrustBaseEntry::from_json(&json).unwrap();
    assert_eq!(loaded, g);
    assert!(TrustBaseHistory::from_genesis(loaded.clone(), Some(g.entry_id())).is_ok());
    assert_eq!(
        TrustBaseHistory::from_genesis(loaded, Some([5; 32])),
        Err(HistoryError::PinMismatch)
    );
    assert!(TrustBaseEntry::from_json(&json.replace("\"version\":2", "\"version\":1")).is_err());
    assert!(TrustBaseEntry::from_json("{}").is_err());
}

// `from_trusted_chain` verifies no signature, so each structural check of the chain is the
// only thing between a gap or a misordered list and a wrong committee judging a seal
// (`TrustBaseHistory::get` finds an entry by its position). One violation per test.

fn chain_entry(epoch: u64, start: u64, prev: [u8; 32], net: u16) -> TrustBaseEntry {
    let mut e = TrustBaseEntry::genesis(NetworkId::new(net).unwrap(), epoch, start, members(&FOUR));
    e.previous_entry_id = prev;
    if prev != [0; 32] {
        e.add_signature("a", vec![0; 65]); // a placeholder witness: the chain is trusted
    }
    e
}

#[test]
fn a_trusted_chain_with_every_link_in_order_is_accepted() {
    let e1 = chain_entry(1, 1, [0; 32], NET);
    let e2 = chain_entry(2, 5, e1.entry_id(), NET);
    let e3 = chain_entry(3, 9, e2.entry_id(), NET);
    let h = TrustBaseHistory::from_trusted_chain(vec![e1, e2, e3]).unwrap();
    assert_eq!((h.genesis().epoch, h.latest().epoch), (1, 3));
    assert_eq!(h.get(2).unwrap().epoch, 2);
}

#[test]
fn a_trusted_chain_refuses_another_predecessor() {
    let e1 = chain_entry(1, 1, [0; 32], NET);
    let e2 = chain_entry(2, 5, [9; 32], NET); // not e1's identity
    assert!(matches!(
        TrustBaseHistory::from_trusted_chain(vec![e1, e2]),
        Err(HistoryError::Entry(TrustBaseError::Chain(m))) if m.contains("previous entry id")
    ));
}

#[test]
fn a_trusted_chain_refuses_a_gap_in_the_epochs() {
    let e1 = chain_entry(1, 1, [0; 32], NET);
    let e3 = chain_entry(3, 5, e1.entry_id(), NET); // epoch 2 is missing
    assert_eq!(
        TrustBaseHistory::from_trusted_chain(vec![e1, e3]),
        Err(HistoryError::Gap {
            held: 1,
            offered: 3
        })
    );
}

#[test]
fn a_trusted_chain_refuses_a_start_round_that_does_not_rise() {
    let e1 = chain_entry(1, 5, [0; 32], NET);
    let e2 = chain_entry(2, 5, e1.entry_id(), NET); // same start as its predecessor
    assert!(matches!(
        TrustBaseHistory::from_trusted_chain(vec![e1, e2]),
        Err(HistoryError::Entry(TrustBaseError::Chain(m))) if m.contains("start")
    ));
}

#[test]
fn a_trusted_chain_refuses_another_network() {
    let e1 = chain_entry(1, 1, [0; 32], NET);
    let e2 = chain_entry(2, 5, e1.entry_id(), NET + 1);
    assert_eq!(
        TrustBaseHistory::from_trusted_chain(vec![e1, e2]),
        Err(HistoryError::WrongNetwork)
    );
}

// ---- the GetTrustBase page decoder: bounds and strictness that only one check can catch ----

use unicity_token::api::bft::TrustBasePage;
use unicity_token::cbor::{encode_array, encode_byte_string, encode_null, encode_tag, encode_uint};

fn page_bytes(network: u16, from: u64, end: u64, entries: &[Vec<u8>]) -> Vec<u8> {
    let refs: Vec<&[u8]> = entries.iter().map(Vec::as_slice).collect();
    encode_tag(
        39015,
        &encode_array(&[
            &encode_uint(1),
            &encode_uint(u64::from(network)),
            &encode_uint(0),
            &encode_uint(from),
            &encode_uint(end),
            &encode_byte_string(&[7; 32]),
            &encode_array(&refs),
            &encode_null(),
        ]),
    )
}

/// `n` contiguous, valid, signed entries from epoch 2 (successors of the test genesis).
fn successors(n: usize) -> Vec<Vec<u8>> {
    let mut prev = genesis();
    let mut out = Vec::new();
    for _ in 0..n {
        let next = successor(&prev, &FOUR, &ABC);
        out.push(next.to_cbor());
        prev = next;
    }
    out
}

#[test]
fn a_page_holds_at_most_64_entries() {
    let entries = successors(65);
    let ok = TrustBasePage::from_cbor(&page_bytes(NET, 2, 66, &entries[..64])).unwrap();
    assert_eq!(ok.entries.len(), 64);
    // 65 valid contiguous entries: only the entry cap refuses them
    assert!(TrustBasePage::from_cbor(&page_bytes(NET, 2, 66, &entries)).is_err());
}

#[test]
fn a_page_is_one_item_without_trailing_bytes() {
    let entries = successors(2);
    let mut bytes = page_bytes(NET, 2, 3, &entries);
    assert!(TrustBasePage::from_cbor(&bytes).is_ok());
    bytes.push(0);
    assert!(TrustBasePage::from_cbor(&bytes).is_err());
}

#[test]
fn the_entries_of_a_page_are_of_the_pages_network() {
    let entries = successors(1);
    // the entries are of network NET, the header says another one
    assert!(TrustBasePage::from_cbor(&page_bytes(NET, 2, 2, &entries)).is_ok());
    assert!(TrustBasePage::from_cbor(&page_bytes(NET + 1, 2, 2, &entries)).is_err());
}
