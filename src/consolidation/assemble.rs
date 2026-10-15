//! Tree reconstruction and authenticated assembly of ordinary certificates.

use alloc::vec::Vec;

use super::error::PartitionViewError;
use super::partition_view::{PartitionView, PartitionViewInputRecord, PartitionViewLeaf};
use super::shard_tree::ShardTree;
use super::topology::PartitionTopology;
use crate::api::bft::{
    ShardId, ShardTreeCertificate, UnicityCertificate, UnicitySeal, UnicityTreeCertificate,
};
use crate::api::NetworkId;
use crate::crypto::hash::{DataHasher, HashAlgorithm};
use crate::verify::SealAuthenticator;

/// One shard's result of [`PartitionView::assemble_certificates`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardCertificate {
    /// The shard.
    pub shard_id: ShardId,
    /// The shard's native tree path, available for every shard.
    pub shard_tree_certificate: ShardTreeCertificate,
    /// The ordinary unicity certificate; `None` when the shard's input record
    /// has no state hash or summary value (a shard that never certified a state,
    /// as the producer emits for non-participating shards). Such a record can
    /// not be an [`InputRecord`](crate::api::bft::InputRecord), and the shard can
    /// not hold token proofs; its leaf is still bound to the seal.
    pub certificate: Option<UnicityCertificate>,
}

impl PartitionView {
    /// Check that this is a well-formed view of `partition` with exactly the
    /// shards of the trusted `topology`, in canonical order, and that every
    /// admitted shard configuration hash matches. No hash tree is touched.
    pub fn validate_structure(
        &self,
        partition: u32,
        topology: &PartitionTopology,
    ) -> Result<(), PartitionViewError> {
        self.check_bounds()?;
        if self.partition_id != partition {
            return Err(PartitionViewError::PartitionMismatch);
        }
        let order = topology.canonical_order()?;
        if self.leaves.len() != order.len() {
            return Err(PartitionViewError::LeafSetMismatch("leaf count"));
        }
        for (leaf, id) in self.leaves.iter().zip(&order) {
            if &leaf.shard_id != id {
                return Err(PartitionViewError::LeafSetMismatch(
                    "unexpected shard or order",
                ));
            }
            if let Some(admitted) = topology.shard_conf_hash(id) {
                if admitted.as_slice() != leaf.shard_conf_hash.as_slice() {
                    return Err(PartitionViewError::ConfigHashMismatch);
                }
            }
        }
        Ok(())
    }

    /// Validate the structure and rebuild the native shard tree from the leaves.
    pub fn build_shard_tree(
        &self,
        partition: u32,
        topology: &PartitionTopology,
    ) -> Result<ShardTree, PartitionViewError> {
        self.validate_structure(partition, topology)?;
        ShardTree::build(
            self.leaves
                .iter()
                .map(|l| (l.shard_id.clone(), l.leaf_hash()))
                .collect(),
        )
    }

    /// Check that the view hashes into the unicity seal of `enclosing`: the
    /// structure and topology are validated, the enclosing certificate must be of
    /// this partition and the rebuilt shard tree root must evaluate through its
    /// partition path to the seal hash. The certificate's own shard leaf must
    /// match the view completely.
    ///
    /// The seal's signatures are **not** checked here; see
    /// [`authenticate`](Self::authenticate).
    pub fn verify_tree(
        &self,
        enclosing: &UnicityCertificate,
        partition: u32,
        topology: &PartitionTopology,
    ) -> Result<ShardTree, PartitionViewError> {
        let tree = self.build_shard_tree(partition, topology)?;
        let utc = &enclosing.unicity_tree_certificate;
        if utc.partition_identifier != self.partition_id {
            return Err(PartitionViewError::EnclosingCertificate(
                "certificate is of another partition",
            ));
        }
        let root = utc.compute_root_hash(tree.root_hash());
        if root.data() != enclosing.unicity_seal.hash.as_slice() {
            return Err(PartitionViewError::TreeRootMismatch);
        }

        // the enclosing certificate's own leaf and native shard path
        let own = &enclosing.shard_tree_certificate.shard;
        let leaf = self.leaves.iter().find(|l| &l.shard_id == own).ok_or(
            PartitionViewError::EnclosingCertificate("certificate shard is not in the view"),
        )?;
        if enclosing.shard_configuration_hash != leaf.shard_conf_hash {
            return Err(PartitionViewError::EnclosingCertificate(
                "shard configuration hash differs from the view",
            ));
        }
        if enclosing.technical_record_hash.as_deref() != Some(leaf.tr_hash.as_slice()) {
            return Err(PartitionViewError::EnclosingCertificate(
                "technical record hash differs from the view",
            ));
        }
        if PartitionViewInputRecord::from_input_record(&enclosing.input_record) != leaf.input_record
        {
            return Err(PartitionViewError::EnclosingCertificate(
                "input record differs from the view",
            ));
        }
        let own_cert = tree.certificate(own)?;
        if own_cert.sibling_hash_list != enclosing.shard_tree_certificate.sibling_hash_list {
            return Err(PartitionViewError::EnclosingCertificate(
                "shard tree certificate differs from the view",
            ));
        }
        crate::verify::check_seal_shape(&enclosing.unicity_seal)
            .map_err(PartitionViewError::Seal)?;
        Ok(tree)
    }

    /// Derive the ordinary certificate of every shard from an authenticated
    /// view. Compatibility entry point: it requires an admitted configuration
    /// hash for every shard in `topology` (complete pins), authenticates the
    /// view with [`authenticate`](Self::authenticate) and delegates to
    /// [`AuthenticatedView::certificates`].
    pub fn assemble_certificates(
        &self,
        enclosing: &UnicityCertificate,
        partition: u32,
        topology: &PartitionTopology,
        authenticator: &mut impl SealAuthenticator,
    ) -> Result<Vec<ShardCertificate>, PartitionViewError> {
        for id in topology.canonical_order()? {
            if topology.shard_conf_hash(&id).is_none() {
                return Err(PartitionViewError::ConfigHashRequired);
            }
        }
        self.authenticate(enclosing, partition, Some(topology), authenticator)?
            .certificates()
    }

    /// Authenticate this candidate view against an anchored authority.
    ///
    /// The view is untrusted data until every step passed, in this order:
    /// structure and canonical order (the topology is derived from the
    /// candidate itself, or taken from `pins` when the caller pins one), tree
    /// rebuild and partition path to the seal hash, exact match of the enclosing
    /// certificate's own leaf, and finally the strict authentication of the
    /// complete enclosing seal by `authority` (network, exact epoch, round at
    /// least the epoch start, quorum signatures). The authority comes from the
    /// caller's installed trust base, never from the response.
    ///
    /// `pins` is an optional, stricter policy: the scheme must equal the pinned
    /// one and every pinned configuration hash must match. Pins are part of the
    /// resulting view's [`identity`](AuthenticatedView::identity).
    ///
    /// Not enforced: the end boundary of the authority's epoch (needs
    /// authenticated history, which a fixed-authority session does not have).
    pub fn authenticate(
        &self,
        enclosing: &UnicityCertificate,
        partition: u32,
        pins: Option<&PartitionTopology>,
        authority: &mut impl SealAuthenticator,
    ) -> Result<AuthenticatedView, PartitionViewError> {
        let candidate_topology;
        let topology = match pins {
            Some(pinned) => pinned,
            None => {
                self.check_bounds()?;
                let ids: Vec<ShardId> = self.leaves.iter().map(|l| l.shard_id.clone()).collect();
                candidate_topology =
                    PartitionTopology::new(if ids.len() == 1 && ids[0].length() == 0 {
                        Vec::new()
                    } else {
                        ids
                    });
                &candidate_topology
            }
        };
        let tree = self.verify_tree(enclosing, partition, topology)?;
        // the policy this authentication is for namespaces the authority's memo
        let policy: [u8; 32] = {
            let d = DataHasher::new(HashAlgorithm::Sha256)
                .expect("sha256")
                .update(b"unicity-token/view-policy/v1")
                .update(&partition.to_be_bytes())
                .update(&[u8::from(pins.is_some())])
                .update(&pins.map_or([0u8; 32], PartitionTopology::digest))
                .finalize();
            let mut p = [0u8; 32];
            p.copy_from_slice(d.data());
            p
        };
        authority
            .authenticate_seal_under(&enclosing.unicity_seal, &policy)
            .map_err(PartitionViewError::Seal)?;

        let seal = enclosing.unicity_seal.clone();
        let mut identity = DataHasher::new(HashAlgorithm::Sha256)
            .expect("sha256")
            .update(b"unicity-token/authenticated-view/v1")
            .update(&authority.authority_identity())
            .update(&partition.to_be_bytes())
            .update(&pins.map_or([0u8; 32], PartitionTopology::digest))
            .update(&[u8::from(pins.is_some())]);
        let seal_bytes = seal.to_cbor();
        identity = identity
            .update(&(seal_bytes.len() as u64).to_be_bytes())
            .update(&seal_bytes);
        let mut id = [0u8; 32];
        id.copy_from_slice(identity.finalize().data());
        Ok(AuthenticatedView {
            partition_id: self.partition_id,
            leaves: self.leaves.clone(),
            tree,
            unicity_tree_certificate: enclosing.unicity_tree_certificate.clone(),
            seal,
            identity: id,
        })
    }
}

/// A partition view whose commitment to its seal and whose seal itself were
/// authenticated. It can only be produced by [`PartitionView::authenticate`];
/// it is immutable and is the only input of certificate assembly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedView {
    partition_id: u32,
    leaves: Vec<PartitionViewLeaf>,
    tree: ShardTree,
    unicity_tree_certificate: UnicityTreeCertificate,
    seal: UnicitySeal,
    identity: [u8; 32],
}

impl AuthenticatedView {
    /// The partition.
    pub fn partition_id(&self) -> u32 {
        self.partition_id
    }

    /// The authenticated leaves, in canonical shard order.
    pub fn leaves(&self) -> &[PartitionViewLeaf] {
        &self.leaves
    }

    /// The complete master seal, byte-for-byte as authenticated.
    pub fn seal(&self) -> &UnicitySeal {
        &self.seal
    }

    /// The network of the authenticated seal.
    pub fn network_id(&self) -> NetworkId {
        self.seal.network_id
    }

    /// The root epoch of the authenticated seal.
    pub fn epoch(&self) -> u64 {
        self.seal.epoch
    }

    /// The shard tree rebuilt from the leaves.
    pub fn shard_tree(&self) -> &ShardTree {
        &self.tree
    }

    /// Digest identifying this authentication: authority content, partition,
    /// pinned policy (if any) and the complete seal. Use it as (part of) any
    /// cache key for results derived from this view.
    pub fn identity(&self) -> &[u8; 32] {
        &self.identity
    }

    /// Derive every shard's tree path and, where the input record has a state
    /// hash and summary value, its ordinary version-1 unicity certificate, in
    /// canonical order. Each carries the identical master seal and partition
    /// path, so one quorum authentication covers all of them.
    pub fn certificates(&self) -> Result<Vec<ShardCertificate>, PartitionViewError> {
        self.leaves
            .iter()
            .map(|leaf| {
                let shard_tree_certificate = self.tree.certificate(&leaf.shard_id)?;
                let certificate =
                    leaf.input_record
                        .to_input_record()
                        .map(|input_record| UnicityCertificate {
                            input_record,
                            technical_record_hash: Some(leaf.tr_hash.clone()),
                            shard_configuration_hash: leaf.shard_conf_hash.clone(),
                            shard_tree_certificate: shard_tree_certificate.clone(),
                            unicity_tree_certificate: self.unicity_tree_certificate.clone(),
                            unicity_seal: self.seal.clone(),
                        });
                Ok(ShardCertificate {
                    shard_id: leaf.shard_id.clone(),
                    shard_tree_certificate,
                    certificate,
                })
            })
            .collect()
    }
}
