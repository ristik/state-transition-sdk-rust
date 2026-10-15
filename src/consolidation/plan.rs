//! Pure planning and checked reconstruction for proof consolidation.
//!
//! A token's *outer history* is its genesis and transfers, each carrying one
//! [`InclusionProof`]. Only these proofs are replaceable: proofs embedded in
//! signed mint justifications, split/burn dependencies or predicate data are
//! part of the signed transaction bytes and are never touched.

use alloc::vec::Vec;

use super::error::PartitionViewError;
use super::topology::PartitionTopology;
use crate::api::bft::{ShardId, UnicityCertificate};
use crate::api::inclusion_proof::InclusionProof;
use crate::api::StateId;
use crate::transaction::{
    CertifiedMintTransaction, CertifiedTransferTransaction, Token, Transaction,
};
use crate::verify::{verify_membership_in, SealSession, VerificationError};

/// Routes a state id to its shard by the admitted shard-prefix topology.
///
/// There is no modulo rule and no inference from timestamps: a state belongs to
/// the unique shard whose id is a bit-prefix of the state id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardRouter {
    shards: Vec<ShardId>,
}

impl ShardRouter {
    /// Router of a trusted topology (an empty scheme is the single shard).
    pub fn new(topology: &PartitionTopology) -> Result<Self, PartitionViewError> {
        Ok(Self {
            shards: topology.canonical_order()?,
        })
    }

    /// The shards in canonical (left-to-right) order.
    pub fn shards(&self) -> &[ShardId] {
        &self.shards
    }

    /// The shard serving `state_id`.
    pub fn route(&self, state_id: &StateId) -> &ShardId {
        // a complete prefix-free scheme: exactly one shard matches
        self.shards
            .iter()
            .find(|s| s.length() == 0 || s.is_prefix_of(state_id.bytes()))
            .unwrap_or(&self.shards[0])
    }
}

/// One replaceable proof of a token's outer history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OuterProof<'a> {
    /// Position: `0` is the genesis, `i` the `i`-th transfer (1-based).
    pub index: usize,
    /// The state the proof certifies.
    pub state_id: StateId,
    /// The original proof.
    pub proof: &'a InclusionProof,
}

/// The replaceable outer-history proofs of `token`, genesis first.
pub fn outer_proofs(token: &Token) -> Vec<OuterProof<'_>> {
    let genesis = token.genesis();
    let mut out = Vec::with_capacity(1 + token.transactions().len());
    out.push(OuterProof {
        index: 0,
        state_id: StateId::derive(
            genesis.transaction().lock_script(),
            genesis.transaction().source_state_hash(),
        ),
        proof: genesis.inclusion_proof(),
    });
    for (i, t) in token.transactions().iter().enumerate() {
        out.push(OuterProof {
            index: i + 1,
            state_id: StateId::derive(
                t.transaction().lock_script(),
                t.transaction().source_state_hash(),
            ),
            proof: t.inclusion_proof(),
        });
    }
    out
}

/// Number of distinct complete seals among the given proofs.
pub fn distinct_seals<'a>(proofs: impl IntoIterator<Item = &'a InclusionProof>) -> usize {
    let mut seen: Vec<Vec<u8>> = Vec::new();
    for p in proofs {
        let seal = p.unicity_certificate.unicity_seal.to_cbor();
        if !seen.contains(&seal) {
            seen.push(seal);
        }
    }
    seen.len()
}

/// The native root-round position the consolidated seal must reach, and the
/// shard that holds the newest authenticated evidence.
///
/// It can only be obtained by authenticating original proofs, never from a
/// caller-supplied number: an unknown bound means consolidation is unavailable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootRoundBound {
    round: u64,
    shard: ShardId,
}

impl RootRoundBound {
    /// Authenticate every `(state, original proof)` under the session's trust
    /// base (including its quorum signatures) and take the newest seal round
    /// (`RootChainRoundNumber`, the native position within one network's
    /// history). Ties choose the shard of the first evidence in input order (the
    /// reference implementation's rule).
    pub fn from_proofs(
        session: &mut SealSession<'_>,
        router: &ShardRouter,
        evidence: &[(StateId, &InclusionProof)],
    ) -> Result<Self, VerificationError> {
        let mut best: Option<(u64, ShardId)> = None;
        for (state_id, proof) in evidence {
            verify_membership_in(session, proof, state_id, proof.reference_time)?;
            let round = proof
                .unicity_certificate
                .unicity_seal
                .root_chain_round_number;
            let shard = router.route(state_id).clone();
            let better = best.as_ref().map_or(true, |(r, _)| round > *r);
            if better {
                best = Some((round, shard));
            }
        }
        let (round, shard) = best.ok_or(VerificationError::SealMalformed)?;
        Ok(Self { round, shard })
    }

    /// The required minimum root round.
    pub fn round(&self) -> u64 {
        self.round
    }

    /// The shard of the newest authenticated evidence (the default master).
    pub fn shard(&self) -> &ShardId {
        &self.shard
    }
}

/// Build the replacement of `original` from the aggregator's `served` proof and
/// the authenticated certificate `uc` of the shard: the original certification
/// data and reference time are kept byte-for-byte, only the tree path (from the
/// served proof) and the unicity certificate (derived) are new.
///
/// Fails if the served proof is not bound to the original certification.
pub fn replacement_proof(
    original: &InclusionProof,
    served: &InclusionProof,
    uc: &UnicityCertificate,
) -> Result<InclusionProof, &'static str> {
    if served.certification_data != original.certification_data {
        return Err("certification data differs from the original");
    }
    if served.reference_time != original.reference_time {
        return Err("reference time differs from the original");
    }
    Ok(InclusionProof {
        certification_data: original.certification_data.clone(),
        reference_time: original.reference_time,
        inclusion_certificate: served.inclusion_certificate.clone(),
        unicity_certificate: uc.clone(),
    })
}

/// Rebuild `token` with the outer-history proofs replaced, in
/// [`outer_proofs`] order. The signed transactions (and everything nested in
/// them) are cloned unchanged. The result is **unverified**; callers verify it
/// completely.
pub fn rebuild_token(token: &Token, proofs: Vec<InclusionProof>) -> Result<Token, &'static str> {
    if proofs.len() != 1 + token.transactions().len() {
        return Err("one replacement proof per outer-history transaction is required");
    }
    let mut proofs = proofs.into_iter();
    let genesis = CertifiedMintTransaction::new(
        token.genesis().transaction().clone(),
        proofs.next().expect("length checked"),
    );
    let transfers = token
        .transactions()
        .iter()
        .zip(proofs)
        .map(|(t, p)| CertifiedTransferTransaction::new(t.transaction().clone(), p))
        .collect();
    Ok(Token::new(genesis, transfers))
}
