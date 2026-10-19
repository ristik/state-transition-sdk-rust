//! The signed Unicity Trust Base entry (record version 2), the canonical form of a
//! root-validator epoch. Byte-compatible with bft-go-base `types.RootTrustBaseV2`.
//!
//! * Wire form: `tag(39000) [2, network, epoch, epochStart, [[nodeId, key, weight]..],
//!   threshold, stateHash, changeRecordHash, previousEntryId, signatures]` in the
//!   deterministic encoding. The decoder accepts that encoding only: the input must be
//!   exactly the re-encoding of the decoded value.
//! * The identity of an entry is [`TrustBaseEntry::entry_id`] = SHA-256 of the entry with
//!   the signature field encoded as `null` ([`TrustBaseEntry::sig_bytes`]); two valid
//!   signature sets of the same entry have the same identity. A successor links to the
//!   predecessor's identity.
//! * Weights are positive and bounded; the threshold is exactly `floor(2W/3)+1`.
//! * Signatures are the predecessor members' recoverable 65-byte signatures over
//!   `SHA-256(sig_bytes)`. Verification is strict: an unknown member, a malformed or an
//!   invalid signature fails the whole check even when the others reach the quorum.
//!
//! The genesis entry has a zero previous identity and `null` signatures; its authority is
//! an out-of-band pin on its identity, never signatures.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::api::NetworkId;
use crate::cbor::{
    encode_array, encode_byte_string, encode_map, encode_null, encode_tag, encode_text_string,
    encode_uint, Decoder,
};
use crate::crypto::hash::sha256;
#[cfg(feature = "client")]
use crate::crypto::hash::DataHash;
use crate::crypto::signature::{PublicKey, Signature};
#[cfg(feature = "client")]
use crate::crypto::signer::Signer;

/// CBOR tag of the trust base record.
pub const TRUST_BASE_TAG: u64 = 39000;
/// Record version of [`TrustBaseEntry`].
pub const TRUST_BASE_V2_VERSION: u64 = 2;
/// Bound on the member list while decoding.
pub const MAX_MEMBERS: usize = 256;
/// Bound on a node identifier in bytes.
pub const MAX_NODE_ID_LEN: usize = 128;
/// Bound on one member's weight, so that the sum over [`MAX_MEMBERS`] cannot overflow.
pub const MAX_WEIGHT: u64 = 1 << 40;
/// Length of an entry identity and of a present state/change hash.
pub const ID_LEN: usize = 32;
/// Bound on the encoded size of one entry.
pub const MAX_ENTRY_BYTES: usize = 64 << 10;

/// Why an entry was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TrustBaseError {
    /// Not a canonical tagged version-2 entry: wrong tag or version, wrong shape,
    /// non-deterministic bytes, trailing bytes, or a size bound exceeded.
    Encoding(&'static str),
    /// The entry's own structure is invalid (members, weights, threshold, hashes).
    Invalid(&'static str),
    /// The entry does not extend the given predecessor.
    Chain(&'static str),
    /// The signature check failed (strict).
    Signature(String),
}

impl fmt::Display for TrustBaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrustBaseError::Encoding(m) => write!(f, "trust base v2: invalid encoding: {m}"),
            TrustBaseError::Invalid(m) => write!(f, "trust base v2: invalid entry: {m}"),
            TrustBaseError::Chain(m) => {
                write!(f, "trust base v2: does not extend the predecessor: {m}")
            }
            TrustBaseError::Signature(m) => write!(f, "trust base v2: signature check failed: {m}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TrustBaseError {}

impl From<crate::error::CborError> for TrustBaseError {
    fn from(_: crate::error::CborError) -> Self {
        TrustBaseError::Encoding("malformed CBOR")
    }
}

impl From<crate::Error> for TrustBaseError {
    fn from(_: crate::Error) -> Self {
        TrustBaseError::Encoding("malformed field")
    }
}

/// One root validator of an epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustBaseMember {
    /// Node identifier (UTF-8, 1..=[`MAX_NODE_ID_LEN`] bytes).
    pub node_id: String,
    /// Compressed secp256k1 signing key.
    pub signing_key: PublicKey,
    /// Voting weight, `1..=`[`MAX_WEIGHT`].
    pub weight: u64,
}

/// An optional 32-byte hash in the entry. The canonical absent form is `None`, CBOR `null`;
/// a present hash is exactly 32 bytes. The empty byte string is not a wire form: the decoder
/// refuses it, and an in-memory `Some(empty)` is treated as `None` (it encodes as `null`),
/// so an entry has one byte form and one identity.
pub type OptionalHash = Option<Vec<u8>>;

/// A signed trust base entry, record version 2.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TrustBaseEntry {
    /// Network this entry belongs to.
    pub network_id: NetworkId,
    /// Epoch number, at least 1.
    pub epoch: u64,
    /// Root chain round at which the epoch begins.
    pub epoch_start: u64,
    /// Members sorted strictly by raw node id bytes.
    pub members: Vec<TrustBaseMember>,
    /// Exactly `floor(2W/3)+1` of the total weight `W`.
    pub quorum_threshold: u64,
    /// State hash: absent, empty or 32 bytes.
    pub state_hash: OptionalHash,
    /// Change record hash: absent, empty or 32 bytes.
    pub change_record_hash: OptionalHash,
    /// Identity of the predecessor; 32 zero bytes for the genesis entry.
    pub previous_entry_id: [u8; ID_LEN],
    /// Predecessor members' signatures over `SHA-256(sig_bytes)`, sorted by node id;
    /// `None` for the genesis entry.
    pub signatures: Option<Vec<(String, Vec<u8>)>>,
}

impl TrustBaseEntry {
    /// An unsigned entry. The caller supplies a consistent member list and threshold;
    /// [`validate`](Self::validate) checks them.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        network_id: NetworkId,
        epoch: u64,
        epoch_start: u64,
        members: Vec<TrustBaseMember>,
        quorum_threshold: u64,
        state_hash: OptionalHash,
        change_record_hash: OptionalHash,
        previous_entry_id: [u8; ID_LEN],
    ) -> Self {
        let norm = |h: OptionalHash| h.filter(|b| !b.is_empty());
        TrustBaseEntry {
            network_id,
            epoch,
            epoch_start,
            members,
            quorum_threshold,
            state_hash: norm(state_hash),
            change_record_hash: norm(change_record_hash),
            previous_entry_id,
            signatures: None,
        }
    }

    /// The threshold of a total weight: `floor(2W/3)+1`. `None` on overflow.
    pub fn threshold_for(total_weight: u64) -> Option<u64> {
        total_weight.checked_mul(2).map(|w| w / 3 + 1)
    }

    /// Total weight of the members (checked).
    pub fn total_weight(&self) -> Option<u64> {
        self.members
            .iter()
            .try_fold(0u64, |acc, m| acc.checked_add(m.weight))
    }

    /// Whether this is a genesis entry (zero previous identity).
    pub fn is_genesis(&self) -> bool {
        self.previous_entry_id == [0u8; ID_LEN]
    }

    /// The member with this node id.
    pub fn member(&self, node_id: &str) -> Option<&TrustBaseMember> {
        self.members
            .binary_search_by(|m| m.node_id.as_bytes().cmp(node_id.as_bytes()))
            .ok()
            .map(|i| &self.members[i])
    }

    fn encode_inner(&self, with_signatures: bool) -> Vec<u8> {
        let members: Vec<Vec<u8>> = self
            .members
            .iter()
            .map(|m| {
                encode_array(&[
                    &encode_text_string(&m.node_id),
                    &encode_byte_string(m.signing_key.as_bytes()),
                    &encode_uint(m.weight),
                ])
            })
            .collect();
        let member_refs: Vec<&[u8]> = members.iter().map(Vec::as_slice).collect();
        // the canonical absent hash is null, also for an in-memory empty value
        let hash = |h: &OptionalHash| match h {
            Some(b) if !b.is_empty() => encode_byte_string(b),
            _ => encode_null(),
        };
        let signatures = match (&self.signatures, with_signatures) {
            (Some(sigs), true) => {
                let mut entries: Vec<(Vec<u8>, Vec<u8>)> = sigs
                    .iter()
                    .map(|(id, s)| (encode_text_string(id), encode_byte_string(s)))
                    .collect();
                encode_map(&mut entries)
            }
            _ => encode_null(),
        };
        let inner = encode_array(&[
            &encode_uint(TRUST_BASE_V2_VERSION),
            &encode_uint(u64::from(self.network_id.id())),
            &encode_uint(self.epoch),
            &encode_uint(self.epoch_start),
            &encode_array(&member_refs),
            &encode_uint(self.quorum_threshold),
            &hash(&self.state_hash),
            &hash(&self.change_record_hash),
            &encode_byte_string(&self.previous_entry_id),
            &signatures,
        ]);
        encode_tag(TRUST_BASE_TAG, &inner)
    }

    /// The deterministic tagged encoding, signatures included.
    pub fn to_cbor(&self) -> Vec<u8> {
        self.encode_inner(true)
    }

    /// The deterministic tagged encoding with the signature field encoded as `null`
    /// (not removed): the bytes the predecessor's members sign.
    pub fn sig_bytes(&self) -> Vec<u8> {
        self.encode_inner(false)
    }

    /// The identity: `SHA-256(sig_bytes)`, independent of the signatures.
    pub fn entry_id(&self) -> [u8; ID_LEN] {
        let mut id = [0u8; ID_LEN];
        id.copy_from_slice(sha256(&self.sig_bytes()).data());
        id
    }

    /// Strictly decode a tagged version-2 entry and validate its structure (not its
    /// signatures). The input must be the deterministic encoding of the decoded value.
    pub fn from_cbor(data: &[u8]) -> Result<Self, TrustBaseError> {
        if data.len() > MAX_ENTRY_BYTES {
            return Err(TrustBaseError::Encoding("entry exceeds the size bound"));
        }
        let top = Decoder::new(data);
        top.finish()?;
        let inner = top.expect_tag(TRUST_BASE_TAG)?;
        let items = inner.array(Some(10))?;
        if items[0].uint()? != TRUST_BASE_V2_VERSION {
            return Err(TrustBaseError::Encoding("record version is not 2"));
        }
        let network_id = NetworkId::new(
            u16::try_from(items[1].uint()?)
                .map_err(|_| TrustBaseError::Encoding("network id out of range"))?,
        )?;
        let epoch = items[2].uint()?;
        let epoch_start = items[3].uint()?;
        let member_items = items[4].array(None)?;
        if member_items.len() > MAX_MEMBERS {
            return Err(TrustBaseError::Encoding("too many members"));
        }
        let mut members = Vec::with_capacity(member_items.len());
        for item in &member_items {
            let f = item.array(Some(3))?;
            let node_id = String::from(f[0].text()?);
            let signing_key = PublicKey::from_bytes(f[1].bytes_value()?)
                .map_err(|_| TrustBaseError::Invalid("member key is not a valid compressed key"))?;
            members.push(TrustBaseMember {
                node_id,
                signing_key,
                weight: f[2].uint()?,
            });
        }
        let hash = |d: &Decoder<'_>| -> Result<OptionalHash, TrustBaseError> {
            Ok(d.nullable(|x| x.bytes_value().map(<[u8]>::to_vec).map_err(Into::into))?)
        };
        let state_hash = hash(&items[6])?;
        let change_record_hash = hash(&items[7])?;
        for h in [&state_hash, &change_record_hash].into_iter().flatten() {
            if h.is_empty() {
                return Err(TrustBaseError::Encoding(
                    "an absent hash is null, not an empty byte string",
                ));
            }
        }
        let previous_entry_id: [u8; ID_LEN] = items[8]
            .bytes_value()?
            .try_into()
            .map_err(|_| TrustBaseError::Invalid("previous entry id is not 32 bytes"))?;
        let signatures = if items[9].is_null() {
            None
        } else {
            let mut out = Vec::new();
            for (k, v) in items[9].map()? {
                out.push((String::from(k.text()?), v.bytes_value()?.to_vec()));
            }
            Some(out)
        };
        let entry = TrustBaseEntry {
            network_id,
            epoch,
            epoch_start,
            members,
            quorum_threshold: items[5].uint()?,
            state_hash,
            change_record_hash,
            previous_entry_id,
            signatures,
        };
        // exactly one byte form per entry (also rejects duplicate or unsorted map keys)
        if entry.to_cbor() != data {
            return Err(TrustBaseError::Encoding("not the deterministic encoding"));
        }
        entry.validate()?;
        Ok(entry)
    }

    /// Parse the JSON form of an entry (bft-go-base `RootTrustBaseV2` JSON tags), meant for an
    /// on-disk genesis file. Host only. An absent, `null` or empty hash is read as absent
    /// (`null`, the one canonical form). Compare the result's identity with the deployment's pin
    /// ([`TrustBaseHistory::from_genesis`](super::TrustBaseHistory::from_genesis)); a mismatch
    /// means the file is not the pinned genesis.
    #[cfg(feature = "std")]
    pub fn from_json(input: &str) -> Result<Self, TrustBaseError> {
        use serde_json::Value;
        const MAX_JSON_BYTES: usize = 1 << 20;
        let bad = TrustBaseError::Encoding;
        if input.len() > MAX_JSON_BYTES {
            return Err(bad("trust base JSON exceeds the size bound"));
        }
        let root: Value = serde_json::from_str(input).map_err(|_| bad("invalid JSON"))?;
        let num = |v: &Value| -> Result<u64, TrustBaseError> {
            match v {
                Value::Number(n) => n.as_u64().ok_or(bad("not an unsigned integer")),
                Value::String(s) => s.parse::<u64>().map_err(|_| bad("not an unsigned integer")),
                _ => Err(bad("not an unsigned integer")),
            }
        };
        let hex_bytes = |v: &Value| -> Result<Vec<u8>, TrustBaseError> {
            match v {
                Value::Null => Ok(Vec::new()),
                Value::String(s) => {
                    hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(|_| bad("invalid hex"))
                }
                _ => Err(bad("not a hex string")),
            }
        };
        if num(&root["version"])? != TRUST_BASE_V2_VERSION {
            return Err(bad("record version is not 2"));
        }
        let network_id = NetworkId::new(
            u16::try_from(num(&root["networkId"])?).map_err(|_| bad("network id out of range"))?,
        )?;
        let nodes = root["rootNodes"]
            .as_array()
            .ok_or(bad("rootNodes is not an array"))?;
        if nodes.len() > MAX_MEMBERS {
            return Err(bad("too many members"));
        }
        let mut members = Vec::with_capacity(nodes.len());
        for n in nodes {
            members.push(TrustBaseMember {
                node_id: String::from(n["nodeId"].as_str().ok_or(bad("nodeId is not a string"))?),
                signing_key: PublicKey::from_bytes(&hex_bytes(&n["sigKey"])?).map_err(|_| {
                    TrustBaseError::Invalid("member key is not a valid compressed key")
                })?,
                weight: num(&n["stake"])?,
            });
        }
        let opt_hash = |v: &Value| -> Result<OptionalHash, TrustBaseError> {
            let b = hex_bytes(v)?;
            Ok(if b.is_empty() { None } else { Some(b) })
        };
        let previous_entry_id: [u8; ID_LEN] = hex_bytes(&root["previousEntryId"])?
            .try_into()
            .map_err(|_| TrustBaseError::Invalid("previous entry id is not 32 bytes"))?;
        let signatures = match &root["signatures"] {
            Value::Null => None,
            Value::Object(m) => {
                let mut v = Vec::with_capacity(m.len());
                for (k, s) in m {
                    v.push((k.clone(), hex_bytes(s)?));
                }
                v.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
                Some(v)
            }
            _ => return Err(bad("signatures is not an object")),
        };
        let entry = TrustBaseEntry {
            network_id,
            epoch: num(&root["epoch"])?,
            epoch_start: num(&root["epochStartRound"])?,
            members,
            quorum_threshold: num(&root["quorumThreshold"])?,
            state_hash: opt_hash(&root["stateHash"])?,
            change_record_hash: opt_hash(&root["changeRecordHash"])?,
            previous_entry_id,
            signatures,
        };
        entry.validate()?;
        Ok(entry)
    }

    /// Check the entry's structure, not its signatures: epoch, members (sorted by raw node
    /// id bytes, unique, valid keys, positive bounded weights), the exact threshold, hash
    /// lengths, and genesis (zero predecessor, null signatures) versus non-genesis
    /// (non-empty signature map).
    pub fn validate(&self) -> Result<(), TrustBaseError> {
        let bad = TrustBaseError::Invalid;
        if self.epoch == 0 {
            return Err(bad("epoch is zero"));
        }
        let n = self.members.len();
        if n == 0 || n > MAX_MEMBERS {
            return Err(bad("member count outside 1..=256"));
        }
        let mut total = 0u64;
        for (i, m) in self.members.iter().enumerate() {
            if m.node_id.is_empty() || m.node_id.len() > MAX_NODE_ID_LEN {
                return Err(bad("node id is empty or too long"));
            }
            if i > 0 && self.members[i - 1].node_id.as_bytes() >= m.node_id.as_bytes() {
                return Err(bad("members are not strictly sorted by node id"));
            }
            if m.weight == 0 || m.weight > MAX_WEIGHT {
                return Err(bad("member weight outside 1..=2^40"));
            }
            if self.members[..i]
                .iter()
                .any(|o| o.signing_key == m.signing_key)
            {
                return Err(bad("two members share a signing key"));
            }
            total += m.weight; // at most 256 * 2^40
        }
        if Some(self.quorum_threshold) != Self::threshold_for(total) {
            return Err(bad("quorum threshold is not floor(2W/3)+1"));
        }
        for b in [&self.state_hash, &self.change_record_hash]
            .into_iter()
            .flatten()
        {
            if !b.is_empty() && b.len() != ID_LEN {
                return Err(bad("state or change hash is not empty or 32 bytes"));
            }
        }
        if self.is_genesis() {
            if self.signatures.is_some() {
                return Err(bad("the genesis entry carries signatures"));
            }
        } else if self.signatures.as_ref().map_or(true, Vec::is_empty) {
            return Err(bad("a non-genesis entry has no signatures"));
        }
        if let Some(sigs) = &self.signatures {
            // a canonical encoding has no repeated key; keep the in-memory form honest too
            if sigs.windows(2).any(|w| w[0].0 >= w[1].0) {
                return Err(bad("signature map keys are not strictly sorted"));
            }
        }
        Ok(())
    }

    /// Add `signer`'s signature over `SHA-256(sig_bytes)` under `node_id`, keeping the map
    /// sorted. A producing-side helper (needs the `client` feature); verification never uses it.
    #[cfg(feature = "client")]
    pub fn sign(&mut self, node_id: &str, signer: &impl Signer) {
        let digest: DataHash = sha256(&self.sig_bytes());
        let sig = signer.sign(&digest).encode().to_vec();
        self.add_signature(node_id, sig);
    }

    /// Insert (or replace) a raw signature under `node_id`.
    pub fn add_signature(&mut self, node_id: &str, signature: Vec<u8>) {
        let sigs = self.signatures.get_or_insert_with(Vec::new);
        match sigs.binary_search_by(|(id, _)| id.as_bytes().cmp(node_id.as_bytes())) {
            Ok(i) => sigs[i].1 = signature,
            Err(i) => sigs.insert(i, (String::from(node_id), signature)),
        }
    }

    /// Verify one member's signature over `data` and return the member's weight.
    ///
    /// The signature must be a canonical recoverable signature: exactly 65 bytes, low-S,
    /// with the recovery id that recovers to the member's key. The 64-byte compact form is
    /// not a trust base signature form.
    pub fn verify_member_signature(
        &self,
        data: &[u8],
        signature: &[u8],
        node_id: &str,
    ) -> Result<u64, TrustBaseError> {
        let m = self.member(node_id).ok_or_else(|| {
            TrustBaseError::Signature(format!("signer {node_id:?} is not a member"))
        })?;
        let sig = Signature::decode(signature).map_err(|_| {
            TrustBaseError::Signature(format!(
                "signer {node_id:?}: not a 65-byte recoverable signature"
            ))
        })?;
        let digest = sha256(data);
        if !sig.verify(digest.data(), &m.signing_key) {
            return Err(TrustBaseError::Signature(format!(
                "signer {node_id:?}: signature does not verify"
            )));
        }
        Ok(m.weight)
    }

    /// Verify, strictly, that `signatures` are by this entry's members over `data` and that
    /// their weight reaches this entry's threshold. Every supplied signature has to be valid
    /// and from a member; there is no early exit.
    pub fn verify_quorum_signatures(
        &self,
        data: &[u8],
        signatures: &[(String, Vec<u8>)],
    ) -> Result<(), TrustBaseError> {
        let mut weight = 0u64;
        for (i, (node_id, sig)) in signatures.iter().enumerate() {
            if signatures[..i].iter().any(|(other, _)| other == node_id) {
                return Err(TrustBaseError::Signature(format!(
                    "signer {node_id:?} appears twice"
                )));
            }
            let w = self.verify_member_signature(data, sig, node_id)?;
            weight = weight
                .checked_add(w)
                .ok_or_else(|| TrustBaseError::Signature(String::from("weight overflow")))?;
        }
        if weight < self.quorum_threshold {
            return Err(TrustBaseError::Signature(format!(
                "quorum not reached, signed weight {weight}, threshold {}",
                self.quorum_threshold
            )));
        }
        Ok(())
    }

    /// Check a genesis entry's structure. Its authority is a pin on its identity, which the
    /// caller compares.
    pub fn verify_genesis(&self) -> Result<(), TrustBaseError> {
        self.validate()?;
        if !self.is_genesis() {
            return Err(TrustBaseError::Invalid("not a genesis entry"));
        }
        Ok(())
    }

    /// Check that `self` is a valid entry extending `prev`: same network, epoch `prev+1`, a
    /// later start round, the predecessor's identity, and a strict quorum of `prev`'s
    /// members signing `sig_bytes`.
    pub fn verify_successor(&self, prev: &TrustBaseEntry) -> Result<(), TrustBaseError> {
        self.validate()?;
        if self.is_genesis() {
            return Err(TrustBaseError::Chain("a genesis entry has no predecessor"));
        }
        if self.network_id != prev.network_id {
            return Err(TrustBaseError::Chain("another network"));
        }
        if prev.epoch == u64::MAX || self.epoch != prev.epoch + 1 {
            return Err(TrustBaseError::Chain(
                "epoch is not the predecessor's plus one",
            ));
        }
        if self.epoch_start <= prev.epoch_start {
            return Err(TrustBaseError::Chain("epoch start does not increase"));
        }
        if self.previous_entry_id != prev.entry_id() {
            return Err(TrustBaseError::Chain("previous entry id does not match"));
        }
        let sigs = self.signatures.as_deref().unwrap_or(&[]);
        prev.verify_quorum_signatures(&self.sig_bytes(), sigs)
    }
}
