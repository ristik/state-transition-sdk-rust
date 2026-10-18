//! The direct target of an **unsharded** partition.
//!
//! With the empty shard id and no shard-tree siblings the shard tree is one leaf:
//! the ordinary unicity certificate already commits (through its own
//! input-record, technical-record and configuration hashes, the partition path
//! and the signed seal) to everything a one-leaf partition view would repeat. The
//! target is therefore that certificate itself, authenticated with the same strict
//! rules and the same policy identity as an authenticated view's seal; no view is
//! decoded, authenticated or derived.
//!
//! This is a verified structural case, not a way to make views optional: it is
//! reachable only for an unsharded configuration, an empty shard id, zero siblings
//! and a configured partition, and every failure is an integrity error - never a
//! fallback.

use super::{view_policy, IntegrityError, PartitionTopology, SealAuthenticator, SealSession};
use crate::api::bft::{ShardId, UnicityCertificate};
use crate::api::AGGREGATION_PARTITION_ID;

/// A unicity certificate of an unsharded partition, authenticated as the common
/// target of a consolidation. Immutable; only [`authenticate`](Self::authenticate)
/// produces it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DirectTarget {
    uc: UnicityCertificate,
    policy: [u8; 32],
}

impl DirectTarget {
    /// Authenticate `uc` as the direct target of `partition` under the configured
    /// `topology`. The checks, in order: structure (empty shard id, no shard
    /// path), partition, configuration pin, the native body (the recomputed tree
    /// root is the signed seal hash) and finally the strict seal authentication
    /// (network, exact epoch, round at least the epoch start, shape, quorum) under
    /// the same policy namespace a view of this configuration uses. The authority
    /// comes from `session`, never from the response.
    pub(super) fn authenticate(
        uc: &UnicityCertificate,
        topology: &PartitionTopology,
        session: &mut SealSession<'_>,
    ) -> Result<Self, IntegrityError> {
        let context = |what| IntegrityError::Context { what };
        let shard = &uc.shard_tree_certificate.shard;
        if shard.length() != 0 {
            return Err(context("direct target needs the empty shard id"));
        }
        if !uc.shard_tree_certificate.sibling_hash_list.is_empty() {
            return Err(context("empty shard id with a nonempty shard path"));
        }
        if uc.unicity_tree_certificate.partition_identifier != AGGREGATION_PARTITION_ID {
            return Err(context("target is of another partition"));
        }
        if topology
            .shard_conf_hash(&ShardId::root())
            .is_some_and(|pin| pin.as_slice() != uc.shard_configuration_hash.as_slice())
        {
            return Err(context("target's shard configuration differs from the pin"));
        }
        let computed = uc.computed_seal_hash().map_err(|_| {
            IntegrityError::Target(crate::verify::VerificationError::SealRootMismatch)
        })?;
        if computed.data() != uc.unicity_seal.hash.as_slice() {
            return Err(IntegrityError::Target(
                crate::verify::VerificationError::SealRootMismatch,
            ));
        }
        // the policy identity of every view-less/viewed target of this configuration
        let policy = view_policy(Some(topology));
        session
            .authenticate_seal_under(&uc.unicity_seal, &policy)
            .map_err(IntegrityError::Target)?;
        Ok(Self {
            uc: uc.clone(),
            policy,
        })
    }

    /// The authenticated certificate: the certificate of every replacement proof.
    pub(super) fn certificate(&self) -> &UnicityCertificate {
        &self.uc
    }

    /// The seal-memo namespace the target was authenticated in.
    pub(super) fn policy(&self) -> &[u8; 32] {
        &self.policy
    }
}
