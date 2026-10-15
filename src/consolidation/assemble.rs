//! Tree reconstruction and authenticated assembly of ordinary certificates.

use alloc::vec::Vec;

use super::error::PartitionViewError;
use super::partition_view::{PartitionView, PartitionViewInputRecord};
use super::shard_tree::ShardTree;
use super::topology::PartitionTopology;
use crate::api::bft::UnicityCertificate;
use crate::verify::SealAuthenticator;

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
    /// [`assemble_certificates`](Self::assemble_certificates).
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

    /// Derive the ordinary version-1 unicity certificate of every shard, in
    /// canonical order.
    ///
    /// Requires every step of [`verify_tree`](Self::verify_tree), an admitted
    /// configuration hash for every shard in `topology`, and the seal of
    /// `enclosing` to be authenticated by `authenticator`. The derived
    /// certificates share the partition path and carry an identical copy of the
    /// complete master seal, so an operation-scoped authenticator pays for its
    /// quorum check once for all of them.
    pub fn assemble_certificates(
        &self,
        enclosing: &UnicityCertificate,
        partition: u32,
        topology: &PartitionTopology,
        authenticator: &mut impl SealAuthenticator,
    ) -> Result<Vec<UnicityCertificate>, PartitionViewError> {
        for id in topology.canonical_order()? {
            if topology.shard_conf_hash(&id).is_none() {
                return Err(PartitionViewError::ConfigHashRequired);
            }
        }
        let tree = self.verify_tree(enclosing, partition, topology)?;
        authenticator
            .authenticate_seal(&enclosing.unicity_seal)
            .map_err(PartitionViewError::Seal)?;

        self.leaves
            .iter()
            .map(|leaf| {
                Ok(UnicityCertificate {
                    input_record: leaf
                        .input_record
                        .to_input_record()
                        .ok_or(PartitionViewError::UnrepresentableInputRecord)?,
                    technical_record_hash: Some(leaf.tr_hash.clone()),
                    shard_configuration_hash: leaf.shard_conf_hash.clone(),
                    shard_tree_certificate: tree.certificate(&leaf.shard_id)?,
                    unicity_tree_certificate: enclosing.unicity_tree_certificate.clone(),
                    unicity_seal: enclosing.unicity_seal.clone(),
                })
            })
            .collect()
    }
}
