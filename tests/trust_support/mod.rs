//! Trust base history fixtures shared by the verification tests (usable without `std`).
#![allow(dead_code)]

use unicity_token::api::bft::{TrustBaseEntry, TrustBaseHistory, TrustBaseMember};
use unicity_token::api::NetworkId;
use unicity_token::crypto::signature::PublicKey;

/// A one-entry history for a fixture environment: `members` are `(node id, key, weight)`. Epoch 0
/// is allowed for fixtures (`from_trusted_chain`); a real network's epochs start at 1.
pub fn history(
    network: NetworkId,
    epoch: u64,
    start: u64,
    members: Vec<(&str, PublicKey, u64)>,
) -> TrustBaseHistory {
    let members = members
        .into_iter()
        .map(|(id, key, w)| TrustBaseMember::new(id, key, w))
        .collect();
    TrustBaseHistory::from_trusted_chain(vec![TrustBaseEntry::genesis(
        network, epoch, start, members,
    )])
    .unwrap()
}

/// The single-validator history of a fixture whose seals are signed by `key`.
pub fn single_node_history(key: PublicKey) -> TrustBaseHistory {
    history(NetworkId::LOCAL, 0, 0, vec![("NODE", key, 1)])
}

/// The history of a Go corpus' `trust-base.cbor` (tag 39000, a version-1 record
/// `[version, network, epoch, epochStart, [[nodeId, sigKey, stake]..], threshold, ..]`): one entry
/// with the same validators, weights, epoch and start round. The corpus threshold has to be the
/// V2 one, `floor(2W/3)+1`.
pub fn history_from_corpus_trust_base(bytes: &[u8]) -> TrustBaseHistory {
    use unicity_token::cbor::Decoder;
    let items = Decoder::new(bytes)
        .expect_tag(39000)
        .unwrap()
        .array(Some(10))
        .unwrap();
    let members: Vec<TrustBaseMember> = items[4]
        .array(None)
        .unwrap()
        .into_iter()
        .map(|n| {
            let f = n.array(Some(3)).unwrap();
            TrustBaseMember::new(
                f[0].text().unwrap(),
                PublicKey::from_bytes(f[1].bytes_value().unwrap()).unwrap(),
                f[2].uint().unwrap(),
            )
        })
        .collect();
    let entry = TrustBaseEntry::genesis(
        NetworkId::new(items[1].uint().unwrap() as u16).unwrap(),
        items[2].uint().unwrap(),
        items[3].uint().unwrap(),
        members,
    );
    assert_eq!(
        entry.quorum_threshold,
        items[5].uint().unwrap(),
        "the corpus threshold is the V2 one"
    );
    TrustBaseHistory::from_trusted_chain(vec![entry]).unwrap()
}

#[cfg(feature = "std")]
/// The history of a V1-shaped trust base JSON (`epoch`, `epochStartRound`, `networkId`,
/// `rootNodes[{nodeId, sigKey, stake}]`, `quorumThreshold`), optionally followed by a synthetic
/// successor epoch starting at `next_epoch_start` (so the end of the first epoch is known).
/// Fixtures only (`from_trusted_chain`).
pub fn history_from_corpus_json(json: &str, next_epoch_start: Option<u64>) -> TrustBaseHistory {
    let v: serde_json::Value = serde_json::from_str(json).unwrap();
    let num = |x: &serde_json::Value| match x {
        serde_json::Value::String(s) => s.parse::<u64>().unwrap(),
        other => other.as_u64().unwrap(),
    };
    let members: Vec<TrustBaseMember> = v["rootNodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| {
            TrustBaseMember::new(
                n["nodeId"].as_str().unwrap(),
                PublicKey::from_bytes(
                    &hex::decode(n["sigKey"].as_str().unwrap().trim_start_matches("0x")).unwrap(),
                )
                .unwrap(),
                num(&n["stake"]),
            )
        })
        .collect();
    let first = TrustBaseEntry::genesis(
        NetworkId::new(num(&v["networkId"]) as u16).unwrap(),
        num(&v["epoch"]),
        num(&v["epochStartRound"]),
        members.clone(),
    );
    assert_eq!(
        first.quorum_threshold,
        num(&v["quorumThreshold"]),
        "the corpus threshold is the V2 one"
    );
    let mut chain = vec![first.clone()];
    if let Some(start) = next_epoch_start {
        let mut next = TrustBaseEntry::genesis(first.network_id, first.epoch + 1, start, members);
        next.previous_entry_id = first.entry_id();
        next.add_signature("x", vec![0; 65]);
        chain.push(next);
    }
    TrustBaseHistory::from_trusted_chain(chain).unwrap()
}
