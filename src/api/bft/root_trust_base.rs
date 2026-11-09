//! Root trust base: the validator set and quorum threshold that anchor all
//! verification. This is the SDK's root of trust; it must be supplied by the
//! caller out-of-band (e.g. embedded in a zkVM guest, or loaded from a vetted
//! `trust-base.json`).

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

use crate::api::network_id::NetworkId;
use crate::crypto::signature::PublicKey;
#[cfg(feature = "std")]
use crate::error::Error;

#[cfg(feature = "std")]
const MAX_TRUST_BASE_JSON_BYTES: usize = 1024 * 1024;
const MAX_ROOT_NODES: usize = 4096;
const MAX_NODE_ID_BYTES: usize = 256;

/// Information about one root (validator) node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootTrustBaseNodeInfo {
    /// Node id (the key used in seal signature maps).
    pub node_id: String,
    /// The node's secp256k1 signing (public) key.
    pub signing_key: PublicKey,
    /// Staked amount.
    pub stake: u64,
}

/// The validator set and quorum threshold anchoring verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootTrustBase {
    /// Trust base version.
    pub version: u64,
    /// Network this trust base is for.
    pub network_id: NetworkId,
    /// Current epoch.
    pub epoch: u64,
    /// Round the epoch started at.
    pub epoch_start_round: u64,
    /// The root nodes (validators).
    pub root_nodes: Vec<RootTrustBaseNodeInfo>,
    /// Minimum number of valid signatures for a quorum.
    pub quorum_threshold: u64,
}

impl RootTrustBase {
    /// Construct directly (the no_std / embedded path).
    ///
    /// This preserves the original infallible API. Prefer [`Self::try_new`]
    /// for new code. [`Self::validate`] and token verification reject an unsafe
    /// value, including one made unsafe through later mutation of public fields.
    pub fn new(
        version: u64,
        network_id: NetworkId,
        epoch: u64,
        epoch_start_round: u64,
        root_nodes: Vec<RootTrustBaseNodeInfo>,
        quorum_threshold: u64,
    ) -> Self {
        RootTrustBase {
            version,
            network_id,
            epoch,
            epoch_start_round,
            root_nodes,
            quorum_threshold,
        }
    }

    /// Construct a trust base and reject configurations that cannot safely
    /// anchor quorum verification.
    pub fn try_new(
        version: u64,
        network_id: NetworkId,
        epoch: u64,
        epoch_start_round: u64,
        root_nodes: Vec<RootTrustBaseNodeInfo>,
        quorum_threshold: u64,
    ) -> Result<Self, crate::Error> {
        let trust_base = Self::new(
            version,
            network_id,
            epoch,
            epoch_start_round,
            root_nodes,
            quorum_threshold,
        );
        trust_base.validate()?;
        Ok(trust_base)
    }

    /// Validate the structural invariants required for secure quorum counting.
    ///
    /// Authentication of the trust base itself remains the caller's external
    /// policy decision. This method establishes that an authenticated document
    /// cannot silently disable or weaken validator authentication.
    pub fn validate(&self) -> Result<(), crate::Error> {
        // Version 0 is used by the reference SDK fixture format; testnet trust
        // bases currently use version 1. Reject unknown future semantics.
        if !matches!(self.version, 0 | 1) {
            return Err(crate::Error::InvalidTrustBase(
                "unsupported trust base version",
            ));
        }
        if self.root_nodes.is_empty() {
            return Err(crate::Error::InvalidTrustBase(
                "validator set must not be empty",
            ));
        }
        if self.root_nodes.len() > MAX_ROOT_NODES {
            return Err(crate::Error::InvalidTrustBase(
                "validator count exceeds safety limit",
            ));
        }
        if self.quorum_threshold == 0 {
            return Err(crate::Error::InvalidTrustBase(
                "quorum threshold must be positive",
            ));
        }
        if self.quorum_threshold > self.root_nodes.len() as u64 {
            return Err(crate::Error::InvalidTrustBase(
                "quorum threshold exceeds validator count",
            ));
        }

        let mut node_ids = BTreeSet::new();
        let mut signing_keys = BTreeSet::new();
        for node in &self.root_nodes {
            if node.node_id.is_empty() || node.node_id.len() > MAX_NODE_ID_BYTES {
                return Err(crate::Error::InvalidTrustBase(
                    "validator node id length is invalid",
                ));
            }
            if !node_ids.insert(node.node_id.as_str()) {
                return Err(crate::Error::InvalidTrustBase(
                    "validator node ids must be unique",
                ));
            }
            if !signing_keys.insert(node.signing_key.as_bytes().as_slice()) {
                return Err(crate::Error::InvalidTrustBase(
                    "validator signing keys must be unique",
                ));
            }
            // The protocol's quorumThreshold is a validator count, not a
            // stake weight. A zero-stake entry must not count as a validator.
            if node.stake == 0 {
                return Err(crate::Error::InvalidTrustBase(
                    "validator stake must be positive",
                ));
            }
        }
        Ok(())
    }

    /// Look up a root node's signing key by node id.
    pub fn signing_key(&self, node_id: &str) -> Option<&PublicKey> {
        self.root_nodes
            .iter()
            .find(|n| n.node_id == node_id)
            .map(|n| &n.signing_key)
    }

    /// Parse a `trust-base.json` document (host only).
    #[cfg(feature = "std")]
    pub fn from_json(input: &str) -> Result<Self, Error> {
        use serde_json::Value;

        if input.len() > MAX_TRUST_BASE_JSON_BYTES {
            return Err(Error::InvalidTrustBase(
                "trust base JSON exceeds safety limit",
            ));
        }

        fn as_u64(v: &Value) -> Result<u64, Error> {
            match v {
                Value::Number(n) => n.as_u64().ok_or(Error::OutOfRange("trust base integer")),
                Value::String(s) => s
                    .parse()
                    .map_err(|_| Error::OutOfRange("trust base integer")),
                _ => Err(Error::UnexpectedValue("trust base integer")),
            }
        }
        fn decode_hex(s: &str) -> Result<Vec<u8>, Error> {
            let s = s.strip_prefix("0x").unwrap_or(s);
            hex::decode(s).map_err(|_| Error::UnexpectedValue("trust base hex"))
        }

        let root: Value = serde_json::from_str(input)
            .map_err(|_| Error::UnexpectedValue("invalid trust base JSON"))?;

        let network_id = NetworkId::new(
            u16::try_from(as_u64(&root["networkId"])?)
                .map_err(|_| Error::OutOfRange("network id"))?,
        )?;

        let nodes_json = root["rootNodes"]
            .as_array()
            .ok_or(Error::UnexpectedValue("rootNodes must be an array"))?;
        if nodes_json.len() > MAX_ROOT_NODES {
            return Err(Error::InvalidTrustBase(
                "validator count exceeds safety limit",
            ));
        }
        let mut root_nodes = Vec::with_capacity(nodes_json.len());
        for node in nodes_json {
            let node_id = node["nodeId"]
                .as_str()
                .ok_or(Error::UnexpectedValue("nodeId must be a string"))?
                .into();
            let signing_key = PublicKey::from_bytes(&decode_hex(
                node["sigKey"]
                    .as_str()
                    .ok_or(Error::UnexpectedValue("sigKey must be a string"))?,
            )?)?;
            root_nodes.push(RootTrustBaseNodeInfo {
                node_id,
                signing_key,
                stake: as_u64(&node["stake"])?,
            });
        }

        RootTrustBase::try_new(
            as_u64(&root["version"])?,
            network_id,
            as_u64(&root["epoch"])?,
            as_u64(&root["epochStartRound"])?,
            root_nodes,
            as_u64(&root["quorumThreshold"])?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(hex_key: &str) -> PublicKey {
        PublicKey::from_bytes(&hex::decode(hex_key).unwrap()).unwrap()
    }

    fn node(id: &str, key_hex: &str) -> RootTrustBaseNodeInfo {
        RootTrustBaseNodeInfo {
            node_id: id.into(),
            signing_key: key(key_hex),
            stake: 1,
        }
    }

    const KEY_A: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const KEY_B: &str = "02c6047f9441ed7d6d3045406e95c07cd85a869ffd0987c3efd81f5a7b5f6f9d5b";

    fn trust_base(nodes: Vec<RootTrustBaseNodeInfo>, threshold: u64) -> RootTrustBase {
        RootTrustBase::new(1, NetworkId::LOCAL, 1, 1, nodes, threshold)
    }

    #[test]
    fn rejects_degenerate_quorums() {
        assert!(trust_base(Vec::new(), 0).validate().is_err());
        assert!(trust_base(alloc::vec![node("A", KEY_A)], 0)
            .validate()
            .is_err());
        assert!(trust_base(alloc::vec![node("A", KEY_A)], 2)
            .validate()
            .is_err());
        let mut unsupported = trust_base(alloc::vec![node("A", KEY_A)], 1);
        unsupported.version = 2;
        assert!(unsupported.validate().is_err());
        let mut zero_stake = trust_base(alloc::vec![node("A", KEY_A)], 1);
        zero_stake.root_nodes[0].stake = 0;
        assert!(zero_stake.validate().is_err());
    }

    #[test]
    fn rejects_duplicate_validator_identities() {
        assert!(
            trust_base(alloc::vec![node("A", KEY_A), node("A", KEY_B)], 2,)
                .validate()
                .is_err()
        );
        assert!(
            trust_base(alloc::vec![node("A", KEY_A), node("B", KEY_A)], 2,)
                .validate()
                .is_err()
        );
        assert!(trust_base(alloc::vec![node("", KEY_A)], 1)
            .validate()
            .is_err());
    }

    #[test]
    fn accepts_unique_attainable_quorum() {
        trust_base(alloc::vec![node("A", KEY_A), node("B", KEY_B)], 2)
            .validate()
            .unwrap();
    }
}
