//! The shared Unicity Trust Base v2 vectors (tests/vectors/trust-base-v2, from bft-go-base) against the history:
//! release bundles (tag 39015, GetTrustBase response layout), the append rule and its outcomes.
#![cfg(feature = "std")]

use serde_json::Value;
use unicity_token::api::bft::{
    Appended, HistoryError, TrustBaseEntry, TrustBaseError, TrustBaseHistory,
};

fn vectors() -> Value {
    serde_json::from_str(include_str!("vectors/trust-base-v2/vectors.json")).expect("vectors.json")
}

fn unhex(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string")).expect("hex")
}

fn bundle(v: &Value, name: &str) -> Vec<u8> {
    let b = v["bundles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["name"].as_str().unwrap().starts_with(name))
        .unwrap();
    unhex(&b["hex"])
}

fn class(e: &HistoryError) -> &'static str {
    match e {
        HistoryError::Entry(TrustBaseError::Signature(_)) => "error:signature",
        HistoryError::Entry(TrustBaseError::Chain(_)) => "error:chain",
        HistoryError::Entry(TrustBaseError::Invalid(_)) => "error:invalid",
        HistoryError::Entry(_) => "error:encoding",
        HistoryError::Conflict { .. } => "conflict",
        HistoryError::Gap { .. } => "gap",
        _ => "other",
    }
}

#[test]
fn bundles_load_and_re_encode_byte_for_byte() {
    let v = vectors();
    for b in v["bundles"].as_array().unwrap() {
        let name = b["name"].as_str().unwrap();
        let bytes = unhex(&b["hex"]);
        let h =
            TrustBaseHistory::from_bundle(&bytes, None).unwrap_or_else(|e| panic!("{name}: {e}"));
        let ids: Vec<Vec<u8>> = h.entries().iter().map(|e| e.entry_id().to_vec()).collect();
        let want: Vec<Vec<u8>> = b["entryIds"]
            .as_array()
            .unwrap()
            .iter()
            .map(unhex)
            .collect();
        assert_eq!(ids, want, "{name}: entry ids");
        assert_eq!(h.to_bundle(), bytes, "{name}: re-encoding");
    }
}

#[test]
fn the_genesis_pin_is_checked() {
    let v = vectors();
    let one = bundle(&v, "one-entry");
    let id: [u8; 32] = TrustBaseHistory::from_bundle(&one, None)
        .unwrap()
        .genesis_id();
    TrustBaseHistory::from_bundle(&one, Some(id)).unwrap();
    let mut wrong = id;
    wrong[0] ^= 1;
    assert_eq!(
        TrustBaseHistory::from_bundle(&one, Some(wrong)),
        Err(HistoryError::PinMismatch)
    );
    assert_eq!(
        TrustBaseHistory::from_genesis(
            TrustBaseHistory::from_bundle(&one, None)
                .unwrap()
                .genesis()
                .clone(),
            Some(wrong)
        ),
        Err(HistoryError::PinMismatch)
    );
}

#[test]
fn malformed_bundles_are_refused() {
    let v = vectors();
    let three = bundle(&v, "three entries");
    // layout: tag(3 bytes) array(8) version network status from end endEntryId entries cursor
    let at = |i: usize, b: u8| {
        let mut x = three.clone();
        x[i] = b;
        x
    };
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("status not OK", at(6, 1)),
        ("version 2", at(4, 2)),
        ("declared start is not the first entry", at(7, 2)),
        ("declared end is not the last entry", at(8, 2)),
        ("another network than the entries", at(5, 6)),
        (
            "declared end identity is not the last entry's",
            at(12, three[12] ^ 1),
        ),
        ("a cursor", {
            let mut x = three.clone();
            let n = x.len();
            x[n - 1] = 0x00;
            x
        }),
        ("trailing byte", {
            let mut x = three.clone();
            x.push(0);
            x
        }),
        ("truncated", three[..three.len() - 1].to_vec()),
        ("empty", Vec::new()),
        ("untagged", three[3..].to_vec()),
    ];
    for (name, bytes) in cases {
        assert!(
            TrustBaseHistory::from_bundle(&bytes, None).is_err(),
            "{name}"
        );
    }
}

#[test]
fn append_outcomes_match_the_reference() {
    let v = vectors();
    let cases = v["history"].as_array().unwrap();
    assert!(cases.len() >= 11);
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let mut held: Option<TrustBaseHistory> = None;
        for (i, step) in c["steps"].as_array().unwrap().iter().enumerate() {
            let want = step["outcome"].as_str().unwrap();
            let entry = TrustBaseEntry::from_cbor(&unhex(&step["entry"]))
                .unwrap_or_else(|e| panic!("{name}[{i}]: {e}"));
            let got: String = match held.as_mut() {
                None => match TrustBaseHistory::from_genesis(entry, None) {
                    Ok(h) => {
                        held = Some(h);
                        "appended".into()
                    }
                    Err(e) => class(&e).into(),
                },
                Some(h) => match h.append(entry) {
                    Ok(Appended::Added) => "appended".into(),
                    Ok(Appended::AlreadyHeld) => "noop".into(),
                    Err(e) => class(&e).into(),
                },
            };
            assert_eq!(got, want, "{name}[{i}]");
        }
        let ids: Vec<Vec<u8>> = held
            .map(|h| h.entries().iter().map(|e| e.entry_id().to_vec()).collect())
            .unwrap_or_default();
        let want: Vec<Vec<u8>> = c["finalEntryIds"]
            .as_array()
            .unwrap_or(&Vec::new())
            .iter()
            .map(unhex)
            .collect();
        assert_eq!(ids, want, "{name}: held chain");
    }
}

#[test]
fn a_refused_entry_changes_nothing() {
    let v = vectors();
    let mut h = TrustBaseHistory::from_bundle(&bundle(&v, "one-entry"), None).unwrap();
    let before = h.clone();
    let e3 = TrustBaseHistory::from_bundle(&bundle(&v, "three entries"), None)
        .unwrap()
        .get(3)
        .unwrap()
        .clone();
    assert!(matches!(
        h.append(e3),
        Err(HistoryError::Gap {
            held: 1,
            offered: 3
        })
    ));
    assert_eq!(h, before);
}

#[test]
fn an_entry_of_another_network_or_before_the_genesis_is_refused() {
    let v = vectors();
    let three = TrustBaseHistory::from_bundle(&bundle(&v, "three entries"), None).unwrap();
    let mut h = TrustBaseHistory::from_bundle(&bundle(&v, "one-entry"), None).unwrap();
    let mut other = three.get(2).unwrap().clone();
    other.network_id = unicity_token::api::NetworkId::new(6).unwrap();
    assert_eq!(h.append(other), Err(HistoryError::WrongNetwork));
    let mut early = three.get(2).unwrap().clone();
    early.epoch = 0;
    assert_eq!(h.append(early), Err(HistoryError::BeforeGenesis));
}
