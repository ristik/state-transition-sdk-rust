//! Trust base history fixtures of the tests that verify against a history (usable without `std`).
#![allow(dead_code)]

use unicity_token::api::bft::{TrustBaseEntry, TrustBaseHistory, TrustBaseMember};
use unicity_token::api::NetworkId;
use unicity_token::crypto::signature::PublicKey;

/// A one-entry history for a fixture environment: `members` are `(node id, key, weight)`. Epoch 0 is allowed for fixtures (`from_trusted_chain`);
/// a real network's epochs start at 1.
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
