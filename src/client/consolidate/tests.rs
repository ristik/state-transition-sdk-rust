//! Token-level consolidation against an in-process simulated network: a
//! two-shard partition with real signed seals, a real radix SMT per shard,
//! retained historical views, and the SDK's own mint/transfer flows producing
//! tokens whose proofs sit under *different* seals.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use super::*;
use crate::api::bft::root_trust_base::RootTrustBaseNodeInfo;
use crate::api::bft::unicity_tree::HashStep;
use crate::api::bft::UcInterner;
use crate::api::bft::{UnicityCertificate, UnicitySeal, UnicityTreeCertificate};
use crate::api::inclusion_certificate::InclusionCertificate;
use crate::api::leaf_value::calculate_leaf_value;
use crate::api::{CertificationData, NetworkId};
use crate::cbor::{encode_byte_string, encode_tag, Decoder};
use crate::client::{
    certification_data_for, mint, transfer, AggregatorClient, BatchProof, ClientError,
};
use crate::consolidation::{PartitionView, PartitionViewInputRecord, PartitionViewLeaf};
use crate::crypto::hash::{sha256, DataHash, DataHasher, HashAlgorithm};
use crate::crypto::signature::PublicKey;
use crate::crypto::signer::{Secp256k1Signer, Signer};
use crate::predicate::builtin::SignaturePredicate;
use crate::radix::{bit_at, prefix_region};
use crate::transaction::ids::{StateMask, TokenSalt, TokenType};
use crate::transaction::{Transaction, TransferTransaction};
use crate::verify::{
    MintJustificationRegistry, MintJustificationVerifier, VerificationContext,
    DEFAULT_SEAL_MEMO_CAPACITY,
};
use alloc::vec;

const PARTITION: u32 = 7;
const T0: u64 = 1_731_504_000;

fn shard_ids() -> [ShardId; 2] {
    let (a, b) = ShardId::root().split();
    [a, b]
}

fn topology(pinned: bool) -> PartitionTopology {
    let mut t = PartitionTopology::new(shard_ids().to_vec());
    if pinned {
        for (i, s) in shard_ids().iter().enumerate() {
            t = t.with_shard_conf_hash(s, conf_hash(i));
        }
    }
    t
}

fn conf_hash(shard: usize) -> [u8; 32] {
    let mut h = [0u8; 32];
    h.copy_from_slice(sha256(&[b'c', shard as u8]).data());
    h
}

// ------------------------------------------------------------ radix SMT ----

fn leaf_hash(key: &[u8; 32], value: &DataHash) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(
        DataHasher::new(HashAlgorithm::Sha256)
            .unwrap()
            .update(&[0x00])
            .update(key)
            .update(value.data())
            .finalize()
            .data(),
    );
    out
}

type Paths = BTreeMap<[u8; 32], Vec<(usize, [u8; 32])>>;

fn build(entries: &[([u8; 32], [u8; 32])], paths: &mut Paths) -> [u8; 32] {
    if entries.len() == 1 {
        paths.entry(entries[0].0).or_default();
        return entries[0].1;
    }
    let (first, last) = (&entries[0].0, &entries[entries.len() - 1].0);
    let d = (0..256)
        .find(|&i| bit_at(first, i) != bit_at(last, i))
        .unwrap();
    let split = entries.partition_point(|e| !bit_at(&e.0, d));
    let l = build(&entries[..split], paths);
    let r = build(&entries[split..], paths);
    for e in &entries[..split] {
        paths.get_mut(&e.0).unwrap().push((d, r));
    }
    for e in &entries[split..] {
        paths.get_mut(&e.0).unwrap().push((d, l));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(
        DataHasher::new(HashAlgorithm::Sha256)
            .unwrap()
            .update(&[0x01, d as u8])
            .update(&prefix_region(first, d))
            .update(&l)
            .update(&r)
            .finalize()
            .data(),
    );
    out
}

/// Root (empty for no leaves) and the encoded inclusion certificate per key.
fn smt(leaves: &BTreeMap<[u8; 32], DataHash>) -> (Vec<u8>, BTreeMap<[u8; 32], Vec<u8>>) {
    if leaves.is_empty() {
        return (Vec::new(), BTreeMap::new());
    }
    let entries: Vec<_> = leaves.iter().map(|(k, v)| (*k, leaf_hash(k, v))).collect();
    let mut paths = Paths::new();
    let root = build(&entries, &mut paths);
    let certs = paths
        .into_iter()
        .map(|(k, mut p)| {
            p.sort_by_key(|(d, _)| *d);
            let mut bytes = vec![0u8; 32];
            for (d, _) in &p {
                bytes[d / 8] |= 0x80 >> (d % 8);
            }
            for (_, s) in &p {
                bytes.extend_from_slice(s);
            }
            (k, bytes)
        })
        .collect();
    (root.to_vec(), certs)
}

// ------------------------------------------------------------ simulation ----

struct Round {
    seal: UnicitySeal,
    roots: [Vec<u8>; 2],
    ucs: [UnicityCertificate; 2],
    view: PartitionView,
    leaves: [BTreeMap<[u8; 32], DataHash>; 2],
    paths: [BTreeMap<[u8; 32], Vec<u8>>; 2],
}

#[derive(Default)]
struct Faults {
    /// Serve this round (index) as "latest" instead of the newest.
    latest_override: Option<usize>,
    /// Rounds before this index are evicted.
    retained_from: usize,
    /// Fail every batch call with this.
    fail: Option<BatchFailure>,
    /// Run once after the next latest response (concurrent writes).
    after_latest: Option<fn(&mut Sim)>,
    /// Rewrite every latest response (an attacker or a faulty server).
    mangle_latest: Option<fn(&mut InclusionProofBatch)>,
}

struct Sim {
    signers: Vec<Secp256k1Signer>,
    trust_base: RootTrustBase,
    rounds: Vec<Round>,
    certs: BTreeMap<[u8; 32], (CertificationData, u64)>,
    leaves: [BTreeMap<[u8; 32], DataHash>; 2],
    submissions: usize,
    batch_calls: usize,
    faults: Faults,
    /// One partition with the empty shard id: no sidecar view is ever served.
    unsharded: bool,
}

fn shard_of(key: &[u8; 32]) -> usize {
    usize::from(bit_at(key, 0))
}

/// The unsharded configuration: the single empty shard, its configuration pinned.
fn unsharded_topology(pinned: bool) -> PartitionTopology {
    let t = PartitionTopology::single_shard();
    if pinned {
        t.with_shard_conf_hash(&ShardId::root(), conf_hash(0))
    } else {
        t
    }
}

impl Sim {
    fn new() -> Self {
        Self::with_sharding(false)
    }

    fn new_unsharded() -> Self {
        Self::with_sharding(true)
    }

    fn shard_index(&self, key: &[u8; 32]) -> usize {
        if self.unsharded {
            0
        } else {
            shard_of(key)
        }
    }

    fn with_sharding(unsharded: bool) -> Self {
        let signers: Vec<_> = (1..=4u8)
            .map(|i| Secp256k1Signer::from_bytes(&[i; 32]).unwrap())
            .collect();
        let nodes = signers
            .iter()
            .enumerate()
            .map(|(i, s)| RootTrustBaseNodeInfo {
                node_id: format!("root-{i}"),
                signing_key: s.public_key(),
                stake: 1,
            })
            .collect();
        let trust_base = RootTrustBase::new(1, NetworkId::LOCAL, 1, 1, nodes, 3);
        let mut sim = Sim {
            signers,
            trust_base,
            rounds: Vec::new(),
            certs: BTreeMap::new(),
            leaves: [BTreeMap::new(), BTreeMap::new()],
            submissions: 0,
            batch_calls: 0,
            faults: Faults::default(),
            unsharded,
        };
        sim.advance();
        sim
    }

    /// Finish a root round: roots, view, signed seal, local certificates.
    fn advance(&mut self) {
        let r = self.rounds.len() as u64 + 1;
        let prev = self.rounds.last();
        let mut roots: [Vec<u8>; 2] = [Vec::new(), Vec::new()];
        let mut paths: [BTreeMap<[u8; 32], Vec<u8>>; 2] = Default::default();
        let mut view_leaves = Vec::new();
        for s in 0..if self.unsharded { 1 } else { 2 } {
            let (root, p) = smt(&self.leaves[s]);
            let prev_root = prev.map_or(Vec::new(), |p| p.roots[s].clone());
            let changed = prev_root != root;
            view_leaves.push(PartitionViewLeaf {
                shard_id: if self.unsharded {
                    ShardId::root()
                } else {
                    shard_ids()[s].clone()
                },
                input_record: PartitionViewInputRecord {
                    round_number: r,
                    epoch: 0,
                    previous_hash: Some(prev_root),
                    hash: Some(root.clone()),
                    summary_value: Some(Vec::new()),
                    timestamp: T0 + r,
                    block_hash: changed.then(|| sha256(&[r as u8, s as u8]).data().to_vec()),
                    sum_of_earned_fees: 0,
                    executed_transactions_hash: None,
                },
                tr_hash: sha256(&[b't', r as u8, s as u8]).data().to_vec(),
                shard_conf_hash: conf_hash(s).to_vec(),
            });
            roots[s] = root;
            paths[s] = p;
        }
        let view = PartitionView {
            partition_id: PARTITION,
            leaves: view_leaves,
        };
        let tree = view
            .build_shard_tree(
                PARTITION,
                &if self.unsharded {
                    unsharded_topology(true)
                } else {
                    topology(true)
                },
            )
            .unwrap();
        let utc = UnicityTreeCertificate {
            partition_identifier: PARTITION,
            steps: vec![HashStep {
                key: 1,
                hash: vec![9; 32],
            }],
        };
        let mut seal = UnicitySeal {
            network_id: NetworkId::LOCAL,
            root_chain_round_number: self.trust_base.epoch_start_round + r,
            epoch: self.trust_base.epoch,
            timestamp: T0 + r,
            previous_hash: prev.map(|p| p.seal.hash.clone()),
            hash: utc.compute_root_hash(tree.root_hash()).data().to_vec(),
            signatures: Vec::new(),
        };
        let digest = seal.calculate_hash();
        for (i, s) in self.signers.iter().take(3).enumerate() {
            seal.signatures
                .push((format!("root-{i}"), s.sign(&digest).encode().to_vec()));
        }
        let uc = |s: usize| {
            let leaf = &view.leaves[s];
            UnicityCertificate {
                input_record: leaf.input_record.to_input_record(),
                technical_record_hash: Some(leaf.tr_hash.clone()),
                shard_configuration_hash: leaf.shard_conf_hash.clone(),
                shard_tree_certificate: tree.certificate(&leaf.shard_id).unwrap(),
                unicity_tree_certificate: utc.clone(),
                unicity_seal: seal.clone(),
            }
        };
        self.rounds.push(Round {
            ucs: [uc(0), uc(view.leaves.len() - 1)],
            seal,
            roots,
            view,
            leaves: self.leaves.clone(),
            paths,
        });
    }

    fn proof_at(&self, round: usize, key: &[u8; 32]) -> Option<InclusionProof> {
        let s = self.shard_index(key);
        let r = &self.rounds[round];
        r.leaves[s].get(key)?;
        let (data, reference_time) = self.certs.get(key)?.clone();
        Some(InclusionProof {
            certification_data: data,
            reference_time,
            inclusion_certificate: InclusionCertificate::decode(&r.paths[s][key]).unwrap(),
            unicity_certificate: r.ucs[s].clone(),
        })
    }
}

/// One shard's aggregator facade over the shared simulation.
#[derive(Clone)]
struct Node {
    sim: Arc<Mutex<Sim>>,
    shard: usize,
}

impl AggregatorClient for Node {
    type Error = &'static str;

    /// Certify immediately: the leaf enters the current tree, a new round is
    /// sealed (so every certification lands under a different seal).
    fn submit_certification_request(&self, data: &CertificationData) -> Result<(), Self::Error> {
        let mut sim = self.sim.lock().unwrap();
        sim.submissions += 1;
        let key = *StateId::derive(data.lock_script(), data.source_state_hash()).bytes();
        let reference_time = T0 + sim.rounds.len() as u64 + 1;
        let value = calculate_leaf_value(data.transaction_hash(), reference_time);
        sim.certs.insert(key, (data.clone(), reference_time));
        let shard = sim.shard_index(&key);
        sim.leaves[shard].insert(key, value);
        sim.advance();
        Ok(())
    }

    fn get_inclusion_proof(&self, state_id: &StateId) -> Result<InclusionProof, Self::Error> {
        let sim = self.sim.lock().unwrap();
        sim.proof_at(sim.rounds.len() - 1, state_id.bytes())
            .ok_or("unknown state")
    }
}

fn unavailable(detail: &str) -> BatchFailure {
    BatchFailure::Rpc {
        code: rpc_code::PROOF_UNAVAILABLE,
        message: "Proof unavailable".into(),
        reason: Some("proof_unavailable".into()),
        detail: Some(detail.into()),
        retryable: Some(true),
        indexes: Default::default(),
    }
}

impl BatchAggregatorClient for Node {
    fn get_inclusion_proofs(
        &self,
        request: &BatchRequest<'_>,
        _options: &RequestOptions,
    ) -> Result<InclusionProofBatch, BatchFailure> {
        let mut sim = self.sim.lock().unwrap();
        sim.batch_calls += 1;
        if let Some(f) = &sim.faults.fail {
            return Err(f.clone());
        }
        let proofs_at = |sim: &Sim, round: usize| -> Result<Vec<BatchProof>, BatchFailure> {
            request
                .state_ids
                .iter()
                .map(|id| {
                    sim.proof_at(round, id.bytes())
                        .map(|proof| BatchProof {
                            block_number: round as u64,
                            proof,
                        })
                        .ok_or_else(|| unavailable("state_not_included"))
                })
                .collect()
        };
        match request.state_root {
            StateRoot::Latest => {
                let round = sim.faults.latest_override.unwrap_or(sim.rounds.len() - 1);
                let proofs = proofs_at(&sim, round)?;
                let partition_view = (!sim.unsharded).then(|| sim.rounds[round].view.clone());
                if let Some(hook) = sim.faults.after_latest.take() {
                    hook(&mut sim);
                }
                let mut batch = InclusionProofBatch {
                    proofs,
                    partition_view,
                };
                if let Some(mangle) = sim.faults.mangle_latest {
                    mangle(&mut batch);
                }
                Ok(batch)
            }
            StateRoot::Exact(root) => {
                // the oldest retained round with this root: its seal is older than the master's
                let round = (sim.faults.retained_from..sim.rounds.len())
                    .find(|&i| sim.rounds[i].roots[self.shard] == root.to_vec())
                    .ok_or_else(|| unavailable("view_not_retained"))?;
                Ok(InclusionProofBatch {
                    proofs: proofs_at(&sim, round)?,
                    partition_view: None,
                })
            }
        }
    }
}

// ------------------------------------------------------------- fixtures ----

type TestClient = ProofClient<Node, SystemClock, ThreadedExecutor>;

fn client(sim: &Arc<Mutex<Sim>>, pinned: bool) -> TestClient {
    let tb = sim.lock().unwrap().trust_base.clone();
    ProofClient::with_host_defaults(
        ProofClientConfig {
            partition_id: PARTITION,
            topology: topology(pinned),
        },
        (0..2)
            .map(|i| {
                (
                    shard_ids()[i].clone(),
                    Node {
                        sim: sim.clone(),
                        shard: i,
                    },
                )
            })
            .collect(),
        tb,
        2,
    )
    .unwrap()
}

fn recipient(seed: u8) -> (Secp256k1Signer, SignaturePredicate) {
    let s = Secp256k1Signer::from_bytes(&[seed; 32]).unwrap();
    let p = SignaturePredicate::new(s.public_key());
    (s, p)
}

fn node(sim: &Arc<Mutex<Sim>>) -> Node {
    Node {
        sim: sim.clone(),
        shard: 0,
    }
}

/// A token with `transfers` transfers, minted/transferred through the SDK's own
/// flows against the simulated aggregator.
fn make_token(
    sim: &Arc<Mutex<Sim>>,
    salt: u8,
    justification: Option<Vec<u8>>,
    transfers: usize,
) -> Token {
    let tb = sim.lock().unwrap().trust_base.clone();
    let agg = node(sim);
    let (mut owner, p) = recipient(50);
    let mut token = mint(
        &agg,
        &tb,
        NetworkId::LOCAL,
        &p,
        TokenType::new([1; 32]),
        TokenSalt::from_bytes([salt; 32]),
        None,
        justification,
        None,
    )
    .unwrap_or_else(|e: ClientError<_>| panic!("mint: {e}"));
    for i in 0..transfers {
        let (next, np) = recipient(51 + i as u8);
        token = transfer(
            &agg,
            &tb,
            &token,
            &np,
            &owner,
            StateMask::from_bytes([i as u8; 32]),
            None,
            None,
        )
        .unwrap_or_else(|e: ClientError<_>| panic!("transfer: {e}"));
        owner = next;
    }
    token
}

/// Mint with a justification: assembled like [`mint`] but not verified (that needs
/// the justification verifier, which only the test registry has).
fn mint_justified(
    sim: &Arc<Mutex<Sim>>,
    salt: u8,
    justification: Vec<u8>,
    transfers: usize,
) -> Token {
    let tb = sim.lock().unwrap().trust_base.clone();
    let agg = node(sim);
    let (mut owner, p) = recipient(50);
    let tx = crate::transaction::MintTransaction::create(
        NetworkId::LOCAL,
        crate::predicate::EncodedPredicate::from_predicate(&p),
        TokenType::new([1; 32]),
        TokenSalt::from_bytes([salt; 32]),
        None,
        Some(justification),
        None,
    )
    .unwrap();
    let signer = crate::transaction::Minter::signer(tx.token_id()).unwrap();
    agg.submit_certification_request(&certification_data_for(&tx, &signer))
        .unwrap();
    let id = StateId::derive(tx.lock_script(), tx.source_state_hash());
    let proof = agg.get_inclusion_proof(&id).unwrap();
    let mut token = Token::new(
        crate::transaction::CertifiedMintTransaction::new(tx, proof),
        Vec::new(),
    );
    for i in 0..transfers {
        let (next, np) = recipient(51 + i as u8);
        let mut registry = MintJustificationRegistry::new();
        registry.register(Box::new(EmbedsToken)).unwrap();
        // transfer() verifies without a registry: build the transfer by hand
        let (src, lock) = token.latest_state();
        let t = TransferTransaction::new(
            src,
            lock,
            crate::predicate::EncodedPredicate::from_predicate(&np),
            StateMask::from_bytes([i as u8; 32]).bytes().to_vec(),
            None,
            None,
        );
        agg.submit_certification_request(&certification_data_for(&t, &owner))
            .unwrap();
        let id = StateId::derive(t.lock_script(), t.source_state_hash());
        let proof = agg.get_inclusion_proof(&id).unwrap();
        let mut txs = token.transactions().to_vec();
        txs.push(crate::transaction::CertifiedTransferTransaction::new(
            t, proof,
        ));
        token = Token::new(token.genesis().clone(), txs);
        token.verify_with(&tb, &registry).unwrap();
        owner = next;
    }
    token
}

/// A token whose outer proofs touch both shards.
fn spread_token(transfers: usize) -> (Arc<Mutex<Sim>>, Token) {
    for salt in 1..=200u8 {
        let sim = Arc::new(Mutex::new(Sim::new()));
        let token = make_token(&sim, salt, None, transfers);
        let router = ShardRouter::new(&topology(false)).unwrap();
        let shards: Vec<_> = outer_proofs(&token)
            .iter()
            .map(|o| router.route(&o.state_id).clone())
            .collect();
        if shards.contains(&shard_ids()[0]) && shards.contains(&shard_ids()[1]) {
            return (sim, token);
        }
    }
    panic!("no salt spreads the token over both shards");
}

fn quick() -> ConsolidateOptions {
    ConsolidateOptions {
        timeout_ms: 10_000,
        ..Default::default()
    }
}

fn tx_bytes(t: &Token) -> Vec<Vec<u8>> {
    let mut v = vec![t.genesis().transaction().to_cbor()];
    v.extend(t.transactions().iter().map(|x| x.transaction().to_cbor()));
    v
}

// ----------------------------------------------------------------- tests ----

#[test]
fn consolidates_into_a_verified_token_with_one_outer_seal() {
    for pinned in [false, true] {
        let (sim, token) = spread_token(3);
        let tb = sim.lock().unwrap().trust_base.clone();
        let before = token.clone();
        let outer_before = distinct_seals(outer_proofs(&token).iter().map(|o| o.proof));
        assert!(
            outer_before >= 3,
            "every certification landed under its own seal"
        );
        let submissions = sim.lock().unwrap().submissions;

        let out = client(&sim, pinned).consolidate(&token, &quick()).unwrap();
        let ConsolidationOutcome::Consolidated {
            token: out,
            summary,
        } = out
        else {
            panic!("{out:?}")
        };
        assert_eq!(token, before, "the input is untouched");
        assert_eq!(
            sim.lock().unwrap().submissions,
            submissions,
            "nothing is submitted"
        );

        // an ordinary, fully verified token
        out.verify(&tb).unwrap();
        assert_eq!(out.id(), token.id());
        assert_eq!(Token::from_cbor(&out.to_cbor()).unwrap(), out);
        // signed transactions byte-identical, original certification data and reference times kept
        assert_eq!(tx_bytes(&out), tx_bytes(&token));
        for (a, b) in outer_proofs(&out).iter().zip(outer_proofs(&token)) {
            assert_eq!(a.proof.certification_data, b.proof.certification_data);
            assert_eq!(a.proof.reference_time, b.proof.reference_time);
        }
        // one shared seal in the outer history
        assert_eq!(
            distinct_seals(outer_proofs(&out).iter().map(|o| o.proof)),
            1
        );
        assert_eq!(summary.outer_seals_before, outer_before);
        assert_eq!(summary.outer_seals_after, 1);
        assert_eq!(summary.shards, 2);
        assert_eq!(summary.requests, 2, "master wave + one exact-root request");
        assert_eq!(summary.verification_quorum_checks, 1);
        assert!(!summary.already_shared);
        let master_seal = &outer_proofs(&out)[0].proof.unicity_certificate.unicity_seal;
        assert_eq!(
            Some(master_seal.root_chain_round_number),
            summary.master_round
        );
        assert!(master_seal.root_chain_round_number >= summary.required_round);
    }
}

#[test]
fn already_consolidated_tokens_need_no_requests() {
    let (sim, token) = spread_token(2);
    let c = client(&sim, false);
    let ConsolidationOutcome::Consolidated { token: once, .. } =
        c.consolidate(&token, &quick()).unwrap()
    else {
        panic!()
    };
    let calls = sim.lock().unwrap().batch_calls;
    let ConsolidationOutcome::Consolidated {
        token: twice,
        summary,
    } = c.consolidate(&once, &quick()).unwrap()
    else {
        panic!()
    };
    assert_eq!(twice, once);
    assert!(summary.already_shared);
    assert_eq!(summary.requests, 0);
    assert_eq!(sim.lock().unwrap().batch_calls, calls, "no batch call");
}

#[test]
fn ordinary_flows_never_consolidate() {
    let (sim, token) = spread_token(2);
    let tb = sim.lock().unwrap().trust_base.clone();
    token.verify(&tb).unwrap();
    let _ = Token::from_cbor(&token.to_cbor()).unwrap();
    let _ = crate::verify::verify_token_with_seal_stats(
        &token,
        &tb,
        &MintJustificationRegistry::new(),
        VerificationPolicy::default(),
    );
    assert_eq!(
        sim.lock().unwrap().batch_calls,
        0,
        "mint/transfer/verify issue no batch request"
    );
}

#[test]
fn unavailable_outcomes_leave_the_input_untouched() {
    let (sim, token) = spread_token(3);
    let c = client(&sim, false);
    let rounds = sim.lock().unwrap().rounds.len();
    let unavailable = |out: Result<ConsolidationOutcome, ConsolidationError>| match out {
        Ok(ConsolidationOutcome::Unavailable { reason, retryable }) => (reason, retryable),
        other => panic!("{other:?}"),
    };

    // a latest view older than the evidence: publication lag
    sim.lock().unwrap().faults.latest_override = Some(0);
    assert_eq!(
        unavailable(c.consolidate(&token, &quick())),
        (UnavailableReason::TargetNotYetAvailable, true)
    );
    sim.lock().unwrap().faults = Faults::default();

    // every historical view was evicted: the peer's target root is gone
    sim.lock().unwrap().faults.retained_from = rounds;
    let out = c.consolidate(&token, &quick());
    assert_eq!(
        unavailable(out),
        (UnavailableReason::TargetNotRetained, true)
    );
    sim.lock().unwrap().faults = Faults::default();

    // no batch capability
    sim.lock().unwrap().faults.fail = Some(BatchFailure::Rpc {
        code: rpc_code::METHOD_NOT_FOUND,
        message: "Method not found".into(),
        reason: None,
        detail: None,
        retryable: None,
        indexes: Default::default(),
    });
    assert_eq!(
        unavailable(c.consolidate(&token, &quick())),
        (UnavailableReason::UnsupportedCapability, false)
    );

    // busy
    sim.lock().unwrap().faults.fail = Some(BatchFailure::Rpc {
        code: rpc_code::CONCURRENCY_LIMIT,
        message: "busy".into(),
        reason: Some("busy".into()),
        detail: Some("active_requests".into()),
        retryable: Some(true),
        indexes: Default::default(),
    });
    assert_eq!(
        unavailable(c.consolidate(&token, &quick())),
        (UnavailableReason::Busy, true)
    );

    // an operational failure is an error, never unavailability
    sim.lock().unwrap().faults.fail = Some(BatchFailure::Rpc {
        code: rpc_code::DATABASE_ERROR,
        message: "db".into(),
        reason: None,
        detail: None,
        retryable: None,
        indexes: Default::default(),
    });
    assert!(matches!(
        c.consolidate(&token, &quick()),
        Err(ConsolidationError::Server { .. })
    ));
    sim.lock().unwrap().faults.fail = Some(BatchFailure::Transport("refused".into()));
    assert!(matches!(
        c.consolidate(&token, &quick()),
        Err(ConsolidationError::Transport { .. })
    ));
    sim.lock().unwrap().faults = Faults::default();

    // after all of it the token is unchanged and the network can still serve it
    assert!(matches!(
        c.consolidate(&token, &quick()).unwrap(),
        ConsolidationOutcome::Consolidated { .. }
    ));
}

#[test]
fn concurrent_writes_between_the_waves_do_not_change_the_attempt() {
    let (sim, token) = spread_token(3);
    // the other shard keeps certifying while the exact-root wave is prepared
    sim.lock().unwrap().faults.after_latest = Some(|sim| {
        for k in 0..3u8 {
            let key = [k.wrapping_mul(97) | 0x80; 32];
            sim.leaves[1].insert(key, sha256(&[k]));
            sim.advance();
        }
    });
    let ConsolidationOutcome::Consolidated {
        token: out,
        summary,
    } = client(&sim, true).consolidate(&token, &quick()).unwrap()
    else {
        panic!()
    };
    assert!(sim.lock().unwrap().rounds.len() > summary.master_round.unwrap() as usize);
    out.verify(&sim.lock().unwrap().trust_base).unwrap();
    assert_eq!(summary.outer_seals_after, 1);
}

#[test]
fn master_override_must_participate_and_input_must_verify() {
    let (sim, token) = spread_token(2);
    let c = client(&sim, false);
    // a participating override is honored
    let router = ShardRouter::new(&topology(false)).unwrap();
    let other = router.shards()[0].clone();
    let ConsolidationOutcome::Consolidated { summary, .. } = c
        .consolidate(
            &token,
            &ConsolidateOptions {
                master: Some(other.clone()),
                ..quick()
            },
        )
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(summary.master, Some(other));

    // an input that does not verify is refused before any request
    let calls = sim.lock().unwrap().batch_calls;
    let mut bad = token.clone();
    let mut proofs: Vec<_> = outer_proofs(&bad).iter().map(|o| o.proof.clone()).collect();
    proofs[0]
        .unicity_certificate
        .unicity_seal
        .signatures
        .clear();
    bad = rebuild_token(&bad, proofs).unwrap();
    assert!(matches!(
        c.consolidate(&bad, &quick()),
        Err(ConsolidationError::InvalidToken(_))
    ));
    assert_eq!(sim.lock().unwrap().batch_calls, calls);
}

// ------------------------------------------------- nested signed proofs ----

const WRAP_TAG: u64 = 39_999;

/// Accepts a justification that embeds a whole source token (as a split would)
/// and verifies it recursively, with the proofs it carries and their own seals.
struct EmbedsToken;

impl MintJustificationVerifier for EmbedsToken {
    fn tag(&self) -> u64 {
        WRAP_TAG
    }

    fn verify(
        &self,
        genesis: &crate::transaction::CertifiedMintTransaction,
        context: &mut VerificationContext<'_>,
    ) -> Result<(), crate::verify::VerificationError> {
        let bytes = genesis
            .transaction()
            .justification()
            .ok_or(crate::verify::VerificationError::MalformedMintJustification)?;
        let inner = Decoder::new(bytes)
            .expect_tag(WRAP_TAG)
            .and_then(|d| d.bytes_value().map(<[u8]>::to_vec))
            .map_err(|_| crate::verify::VerificationError::MalformedMintJustification)?;
        let source = Token::from_cbor(&inner)
            .map_err(|_| crate::verify::VerificationError::MalformedMintJustification)?;
        context.verify_embedded_token(&source, inner.len())
    }
}

#[test]
fn nested_signed_proofs_stay_byte_identical_and_keep_their_seals() {
    let sim = Arc::new(Mutex::new(Sim::new()));
    // the embedded source token has its own history under its own seals
    let source = make_token(&sim, 3, None, 2);
    let justification = encode_tag(WRAP_TAG, &encode_byte_string(&source.to_cbor()));
    let wrapper = mint_justified(&sim, 9, justification.clone(), 2);

    let mut registry = MintJustificationRegistry::new();
    registry.register(Box::new(EmbedsToken)).unwrap();
    let c = client(&sim, false).with_verification(registry, VerificationPolicy::default());
    let ConsolidationOutcome::Consolidated {
        token: out,
        summary,
    } = c.consolidate(&wrapper, &quick()).unwrap()
    else {
        panic!("not consolidated")
    };

    // signed bytes (incl. the embedded token and its proofs) are untouched
    assert_eq!(tx_bytes(&out), tx_bytes(&wrapper));
    assert_eq!(
        out.genesis().transaction().justification(),
        Some(&justification[..])
    );
    // the outer history shares one seal; whole verification still needs the nested seals
    assert_eq!(summary.outer_seals_after, 1);
    assert!(
        summary.verification_quorum_checks >= 2,
        "nested proofs keep their own seals: {}",
        summary.verification_quorum_checks
    );
    // and the result verifies with the same registry
    let mut registry = MintJustificationRegistry::new();
    registry.register(Box::new(EmbedsToken)).unwrap();
    let tb = sim.lock().unwrap().trust_base.clone();
    out.verify_with(&tb, &registry).unwrap();
    // without the justification verifier the (input and) output are refused
    assert!(out.verify(&tb).is_err());
}

#[test]
fn transfer_transaction_bytes_are_preserved() {
    // sanity of the fixture helpers used above
    let (sim, token) = spread_token(1);
    let t: &TransferTransaction = token.transactions()[0].transaction();
    assert_eq!(
        StateId::derive(t.lock_script(), t.source_state_hash()),
        outer_proofs(&token)[1].state_id
    );
    let _ = certification_data_for(t, &Secp256k1Signer::from_bytes(&[50; 32]).unwrap());
    let _ = PublicKey::from_bytes(&[2; 33]).err();
    drop(sim);
}

// ------------------------------------------------ admission and policy ----

fn client_with(
    sim: &Arc<Mutex<Sim>>,
    partition: u32,
    topology: PartitionTopology,
    mutate_tb: impl Fn(&mut RootTrustBase),
) -> TestClient {
    let mut tb = sim.lock().unwrap().trust_base.clone();
    mutate_tb(&mut tb);
    ProofClient::with_host_defaults(
        ProofClientConfig {
            partition_id: partition,
            topology,
        },
        (0..2)
            .map(|i| {
                (
                    shard_ids()[i].clone(),
                    Node {
                        sim: sim.clone(),
                        shard: i,
                    },
                )
            })
            .collect(),
        tb,
        2,
    )
    .unwrap()
}

#[test]
fn already_shared_results_are_not_reused_outside_the_configured_policy() {
    let (sim, token) = spread_token(3);
    let ConsolidationOutcome::Consolidated { token: shared, .. } =
        client(&sim, true).consolidate(&token, &quick()).unwrap()
    else {
        panic!()
    };
    let calls = sim.lock().unwrap().batch_calls;

    // the matching configuration reuses it without any request
    let ConsolidationOutcome::Consolidated { summary, .. } =
        client(&sim, true).consolidate(&shared, &quick()).unwrap()
    else {
        panic!()
    };
    assert!(summary.already_shared);
    assert_eq!(sim.lock().unwrap().batch_calls, calls);

    // another partition
    let other_partition = client_with(&sim, PARTITION + 1, topology(true), |_| {});
    assert!(matches!(
        other_partition.consolidate(&shared, &quick()),
        Err(ConsolidationError::Integrity(
            IntegrityError::Context { .. }
        ))
    ));

    // wrong configuration pins
    let mut wrong = PartitionTopology::new(shard_ids().to_vec());
    for s in shard_ids() {
        wrong = wrong.with_shard_conf_hash(&s, [0xee; 32]);
    }
    let wrong_pins = client_with(&sim, PARTITION, wrong, |_| {});
    assert!(matches!(
        wrong_pins.consolidate(&shared, &quick()),
        Err(ConsolidationError::Integrity(
            IntegrityError::Context { .. }
        ))
    ));

    // another authority epoch: the shared seal is not acceptable as a target, and the
    // network's own latest seal is not authenticated either
    let other_epoch = client_with(&sim, PARTITION, topology(true), |tb| tb.epoch += 1);
    let out = other_epoch.consolidate(&shared, &quick());
    assert!(
        matches!(
            out,
            Err(ConsolidationError::Integrity(IntegrityError::View(_)))
        ),
        "{out:?}"
    );
    // ... and it did go to the network instead of short-cutting
    assert!(sim.lock().unwrap().batch_calls > calls);
}

fn synthetic_items(n: usize) -> Vec<ProofItem> {
    let sim = Arc::new(Mutex::new(Sim::new()));
    let token = make_token(&sim, 1, None, 0);
    let proof = outer_proofs(&token)[0].proof.clone();
    (0..n)
        .map(|i| ProofItem {
            state_id: StateId::from_cbor(Decoder::new(&encode_byte_string(
                sha256(&(i as u64).to_be_bytes()).data(),
            )))
            .unwrap(),
            proof: proof.clone(),
        })
        .collect()
}

fn eight_shard_client() -> TestClient {
    let sim = Arc::new(Mutex::new(Sim::new()));
    let mut scheme = vec![ShardId::root()];
    for _ in 0..3 {
        scheme = scheme
            .iter()
            .flat_map(|s| {
                let (z, o) = s.split();
                [z, o]
            })
            .collect();
    }
    let tb = sim.lock().unwrap().trust_base.clone();
    ProofClient::with_host_defaults(
        ProofClientConfig {
            partition_id: PARTITION,
            topology: PartitionTopology::new(scheme.clone()),
        },
        scheme
            .into_iter()
            .map(|s| {
                (
                    s,
                    Node {
                        sim: sim.clone(),
                        shard: 0,
                    },
                )
            })
            .collect(),
        tb,
        2,
    )
    .unwrap()
}

fn open_budget<'a>(clock: &'a SystemClock, cancel: &'a CancelToken) -> Budget<'a, SystemClock> {
    Budget {
        clock,
        deadline_ms: u64::MAX,
        cancel,
        abort: CancelToken::new(),
    }
}

#[test]
fn admission_work_is_linear_in_the_input_and_oversize_is_refused_first() {
    let c = eight_shard_client();
    let (clock, cancel) = (SystemClock::new(), CancelToken::new());
    let budget = open_budget(&clock, &cancel);
    let mut counts = Vec::new();
    for n in [100usize, 200, 400, 800, 1_600] {
        let items = synthetic_items(n);
        let mut work = AdmissionWork::default();
        let (groups, first_of, shard_of) = match c.group(&items, &budget, &mut work) {
            Ok(x) => x,
            Err(_) => panic!("{n} distinct states fit"),
        };
        assert_eq!(first_of, (0..n).collect::<Vec<_>>());
        assert_eq!(shard_of.len(), n);
        assert_eq!(groups.iter().map(|g| g.ids.len()).sum::<usize>(), n);
        counts.push((n, work));
    }
    for (n, w) in &counts {
        let n = *n as u64;
        assert_eq!(
            w.steps, n,
            "one index operation per input: linear, not quadratic"
        );
        assert_eq!(
            w.group_lookups, n,
            "one array index per distinct state, not a scan of the groups"
        );
        // routing is a binary search over S = 8 shards: at most ceil(log2 8)+1 prefix comparisons
        assert!(
            w.route_comparisons <= 4 * n,
            "{} comparisons for {n} inputs",
            w.route_comparisons
        );
    }

    // beyond what 8 endpoints could ever carry: refused as soon as the distinct count exceeds it
    let items = synthetic_items(8 * MAX_BATCH_STATE_IDS + 1);
    let mut work = AdmissionWork::default();
    assert!(matches!(
        c.group(&items, &budget, &mut work),
        Err(Stop::Error(ConsolidationError::TooManyStates { .. }))
    ));
    assert!(work.steps <= items.len() as u64);

    // duplicates are sent once, so they do not count against the cap
    let one = synthetic_items(1).remove(0);
    let copies = vec![one; 8 * MAX_BATCH_STATE_IDS + 5];
    let mut work = AdmissionWork::default();
    let (groups, first_of, _) = c
        .group(&copies, &budget, &mut work)
        .unwrap_or_else(|_| panic!("one distinct state fits"));
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].ids.len(), 1);
    assert!(first_of.iter().all(|&f| f == 0));

    // a single shard over its limit is refused as soon as it is exceeded
    let one_shard: Vec<ProofItem> = synthetic_items(4_000)
        .into_iter()
        .filter(|i| i.state_id.bytes()[0] >> 5 == 0)
        .take(MAX_BATCH_STATE_IDS + 1)
        .collect();
    let mut work = AdmissionWork::default();
    assert!(matches!(
        c.group(&one_shard, &budget, &mut work),
        Err(Stop::Error(ConsolidationError::TooManyStates { .. }))
    ));
    assert_eq!(
        work.steps,
        one_shard.len() as u64,
        "stops at the offending item"
    );

    // a cancelled attempt does no admission work
    cancel.cancel();
    let mut work = AdmissionWork::default();
    assert!(matches!(
        c.group(&synthetic_items(10), &budget, &mut work),
        Err(Stop::Error(ConsolidationError::Cancelled))
    ));
    assert_eq!(work, AdmissionWork::default());
}

/// Routing cost per input is logarithmic in the number of shards, and agrees with a
/// linear scan of the scheme (the slow reference model).
#[test]
fn routing_is_a_binary_search_that_agrees_with_the_linear_scan() {
    let mut per_route = Vec::new();
    for k in 1..=10u32 {
        let mut scheme = vec![ShardId::root()];
        for _ in 0..k {
            scheme = scheme
                .iter()
                .flat_map(|s| {
                    let (z, o) = s.split();
                    [z, o]
                })
                .collect();
        }
        let s = scheme.len();
        let router = ShardRouter::from_canonical_unchecked(scheme.clone());
        let mut comparisons = 0u64;
        for i in 0..2_000u64 {
            let id = StateId::from_cbor(Decoder::new(&encode_byte_string(
                sha256(&i.to_be_bytes()).data(),
            )))
            .unwrap();
            let got = router.route_index_counted(&id, &mut comparisons);
            let expected = scheme
                .iter()
                .position(|sh| sh.is_prefix_of(id.bytes()))
                .unwrap();
            assert_eq!(got, expected, "S={s}");
        }
        per_route.push((s, comparisons as f64 / 2_000.0));
    }
    for (s, c) in &per_route {
        assert!(
            *c <= f64::from(s.ilog2()) + 1.0,
            "S={s}: {c} comparisons per route"
        );
    }
    // 512x the shards costs about ten times more comparisons, not 512x
    assert!(per_route[9].1 < 12.0 * per_route[0].1);
    // uneven scheme
    let (a, b) = ShardId::root().split();
    let (b0, b1) = b.split();
    let router = ShardRouter::new(&PartitionTopology::new(vec![b1, a.clone(), b0])).unwrap();
    let key = |first: u8| {
        let mut x = [0u8; 32];
        x[0] = first;
        StateId::from_cbor(Decoder::new(&encode_byte_string(&x))).unwrap()
    };
    assert_eq!(router.route(&key(0x10)), &a);
    assert_eq!(
        router.route(&key(0x90)),
        &ShardId::decode(&[0b1010_0000]).unwrap()
    );
    assert_eq!(
        router.route(&key(0xd0)),
        &ShardId::decode(&[0b1110_0000]).unwrap()
    );
}

/// One operation, one session: the input's own verification authenticates each
/// distinct evidence seal once; consolidation adds only its own target check.
#[test]
fn token_consolidation_checks_each_evidence_quorum_once() {
    let (sim, token) = spread_token(3);
    let e = distinct_seals(outer_proofs(&token).iter().map(|o| o.proof));
    let ConsolidationOutcome::Consolidated { summary, .. } =
        client(&sim, false).consolidate(&token, &quick()).unwrap()
    else {
        panic!()
    };
    assert_eq!(
        summary.input_quorum_checks as usize, e,
        "E evidence seals, once each"
    );
    assert_eq!(
        summary.consolidation_quorum_checks, 1,
        "only the master seal is new"
    );
    assert_eq!(
        summary.input_quorum_checks + summary.consolidation_quorum_checks,
        e as u64 + 1
    );
    assert_eq!(summary.certificates_derived, 2);

    // already shared: the view-policy check of the shared seal is the only extra quorum
    let ConsolidationOutcome::Consolidated { token: shared, .. } =
        client(&sim, false).consolidate(&token, &quick()).unwrap()
    else {
        panic!()
    };
    let ConsolidationOutcome::Consolidated { summary, .. } =
        client(&sim, false).consolidate(&shared, &quick()).unwrap()
    else {
        panic!()
    };
    assert!(summary.already_shared);
    assert_eq!(summary.input_quorum_checks, 1);
    assert_eq!(summary.consolidation_quorum_checks, 1);
}

#[test]
fn duplicate_inputs_are_deduplicated_but_conflicts_are_refused() {
    let (sim, token) = spread_token(3);
    let c = client(&sim, false);
    let mut items: Vec<ProofItem> = outer_proofs(&token)
        .iter()
        .map(|o| ProofItem {
            state_id: o.state_id.clone(),
            proof: o.proof.clone(),
        })
        .collect();
    let n = items.len();
    items.push(items[1].clone());
    items.push(items[0].clone());
    let BundleOutcome::Consolidated(bundle) = c.consolidate_proofs(&items, &quick()).unwrap()
    else {
        panic!()
    };
    assert_eq!(bundle.proofs.len(), n + 2, "one output per input");
    assert_eq!(bundle.proofs[n], bundle.proofs[1]);
    assert_eq!(bundle.proofs[n + 1], bundle.proofs[0]);
    assert_eq!(
        bundle.summary.requests, 2,
        "distinct states are requested once"
    );

    // the same state with different original certification
    let mut conflicting = items.clone();
    conflicting[n].proof.reference_time += 1;
    assert!(matches!(
        c.consolidate_proofs(&conflicting, &quick()),
        Err(ConsolidationError::Configuration(_))
    ));
}

// ------------------------------------------- counted verification work ----

fn stats_of(
    token: &Token,
    tb: &RootTrustBase,
    capacity: usize,
) -> (
    Result<(), crate::verify::VerificationError>,
    crate::verify::SealStats,
) {
    crate::verify::verify_token_with_memo_capacity(
        token,
        tb,
        &MintJustificationRegistry::new(),
        VerificationPolicy::default(),
        capacity,
    )
}

/// Verification of a token costs one quorum check per distinct seal, one body check
/// per distinct certificate and one leaf check per proof: after consolidation that is
/// 1 quorum + m bodies + L leaves, independent of L.
#[test]
fn verification_work_is_one_quorum_m_bodies_and_l_leaves() {
    let mut consolidated = Vec::new();
    let mut original = Vec::new();
    for transfers in [1usize, 2, 4, 6, 9] {
        let (sim, token) = spread_token(transfers);
        let tb = sim.lock().unwrap().trust_base.clone();
        let l = 1 + transfers;
        let ConsolidationOutcome::Consolidated { token: out, .. } =
            client(&sim, false).consolidate(&token, &quick()).unwrap()
        else {
            panic!()
        };
        let (r, st) = stats_of(&token, &tb, DEFAULT_SEAL_MEMO_CAPACITY);
        r.unwrap();
        original.push((l, st));
        let (r, st) = stats_of(&out, &tb, DEFAULT_SEAL_MEMO_CAPACITY);
        r.unwrap();
        consolidated.push((l, st));
        // m = participating shards (the two shards of this partition)
        let m = distinct_certificates(&out);
        assert!(m <= 2);
        assert_eq!(st.quorum_checks, 1, "L={l}");
        assert_eq!(
            st.body_checks as usize, m,
            "L={l}: one body check per distinct certificate"
        );
        assert_eq!(
            st.body_hits as usize,
            l - m,
            "L={l}: every other proof reuses it"
        );
    }
    // flat in L after consolidation ...
    assert!(consolidated
        .iter()
        .all(|(_, s)| s.body_checks == consolidated[0].1.body_checks));
    // ... while the unconsolidated token pays per proof (each landed in its own round)
    for (l, st) in &original {
        assert_eq!(st.quorum_checks as usize, *l, "distinct seals, L={l}");
        assert_eq!(st.body_checks as usize, *l);
        assert_eq!(st.body_hits, 0);
    }
}

fn distinct_certificates(t: &Token) -> usize {
    let mut seen: Vec<Vec<u8>> = Vec::new();
    for o in outer_proofs(t) {
        let b = o.proof.unicity_certificate.to_cbor();
        if !seen.contains(&b) {
            seen.push(b);
        }
    }
    seen.len()
}

/// The memoized verifier and the reference that repeats everything must agree on
/// every verdict, including each way of tampering with a certificate.
#[test]
fn memoized_verification_equals_the_reference_on_tampered_tokens() {
    let (sim, token) = spread_token(4);
    let tb = sim.lock().unwrap().trust_base.clone();
    let ConsolidationOutcome::Consolidated { token: shared, .. } =
        client(&sim, false).consolidate(&token, &quick()).unwrap()
    else {
        panic!()
    };
    type Edit = Box<dyn Fn(&mut Vec<InclusionProof>)>;
    let edits: Vec<(&str, Edit)> = vec![
        ("none", Box::new(|_| {})),
        (
            "signature byte",
            Box::new(|p| p[2].unicity_certificate.unicity_seal.signatures[0].1[5] ^= 1),
        ),
        (
            "extra signature witness",
            Box::new(|p| {
                p[1].unicity_certificate
                    .unicity_seal
                    .signatures
                    .push(("x".into(), vec![1; 65]))
            }),
        ),
        (
            "drop signatures below quorum",
            Box::new(|p| p[3].unicity_certificate.unicity_seal.signatures.truncate(2)),
        ),
        (
            "shard sibling",
            Box::new(|p| {
                p[1].unicity_certificate
                    .shard_tree_certificate
                    .sibling_hash_list[0][0] ^= 1
            }),
        ),
        (
            "partition step",
            Box::new(|p| p[4].unicity_certificate.unicity_tree_certificate.steps[0].hash[0] ^= 1),
        ),
        (
            "seal hash",
            Box::new(|p| p[2].unicity_certificate.unicity_seal.hash[0] ^= 1),
        ),
        (
            "ir hash",
            Box::new(|p| p[3].unicity_certificate.input_record.hash.as_mut().unwrap()[0] ^= 1),
        ),
        (
            "swap certificates",
            Box::new(|p| {
                let a = p[0].unicity_certificate.clone();
                p[0].unicity_certificate = p[1].unicity_certificate.clone();
                p[1].unicity_certificate = a;
            }),
        ),
    ];
    for base in [&token, &shared] {
        for (name, edit) in &edits {
            let mut proofs: Vec<_> = outer_proofs(base).iter().map(|o| o.proof.clone()).collect();
            edit(&mut proofs);
            let tampered = rebuild_token(base, proofs).unwrap();
            let (reference, _) = stats_of(&tampered, &tb, 0);
            for cap in [1usize, 2, DEFAULT_SEAL_MEMO_CAPACITY] {
                let (got, _) = stats_of(&tampered, &tb, cap);
                assert_eq!(got, reference, "{name}, capacity {cap}");
            }
            // swapping two proofs' certificates is a no-op when both already carry the same one
            let noop = *name == "swap certificates" && std::ptr::eq(base, &shared);
            if *name != "none" && *name != "extra signature witness" && !noop {
                assert!(reference.is_err(), "{name} must be rejected");
            }
        }
    }
}

#[test]
fn a_different_signature_witness_never_inherits_a_body_verdict() {
    let (sim, token) = spread_token(1);
    let tb = sim.lock().unwrap().trust_base.clone();
    let mut proofs: Vec<_> = outer_proofs(&token)
        .iter()
        .map(|o| o.proof.clone())
        .collect();
    // two proofs with the very same certificate except for an extra (ignored) witness
    proofs[1].unicity_certificate = proofs[0].unicity_certificate.clone();
    let mut twin = proofs[1].clone();
    twin.unicity_certificate
        .unicity_seal
        .signatures
        .push(("extra".into(), vec![9; 65]));
    // the proofs' own paths do not fit these certificates; only the body counters matter here
    let seals = |p: &InclusionProof| p.unicity_certificate.clone();
    let mut session = crate::verify::SealSession::new(&tb);
    let (a, b) = (seals(&proofs[0]), seals(&twin));
    assert_ne!(a, b);
    let policy = [0u8; 32];
    assert!(!session.body_verified(&a, &policy));
    session.remember_body(&a, &policy);
    assert!(session.body_verified(&a, &policy));
    assert!(
        !session.body_verified(&b, &policy),
        "another witness is another key"
    );
    assert!(
        !session.body_verified(&a, &[1u8; 32]),
        "another policy is another key"
    );
}

#[test]
fn nested_proofs_share_the_operation_memo() {
    let sim = Arc::new(Mutex::new(Sim::new()));
    let source = make_token(&sim, 3, None, 1);
    let justification = encode_tag(WRAP_TAG, &encode_byte_string(&source.to_cbor()));
    let wrapper = mint_justified(&sim, 9, justification, 1);
    let tb = sim.lock().unwrap().trust_base.clone();
    let mut registry = MintJustificationRegistry::new();
    registry.register(Box::new(EmbedsToken)).unwrap();
    let (r, st) = crate::verify::verify_token_with_memo_capacity(
        &wrapper,
        &tb,
        &registry,
        VerificationPolicy::default(),
        DEFAULT_SEAL_MEMO_CAPACITY,
    );
    r.unwrap();
    let proofs = 2 + 2; // wrapper genesis + transfer, source genesis + transfer
    assert_eq!(
        (st.body_checks + st.body_hits) as usize,
        proofs,
        "every proof goes through the shared memo"
    );
    let (_, off) = crate::verify::verify_token_with_memo_capacity(
        &wrapper,
        &tb,
        &registry,
        VerificationPolicy::default(),
        0,
    );
    assert_eq!(off.body_hits, 0);
    assert_eq!(off.body_checks as usize, proofs);
}

// --------------------------------------------- certificate decode work ----

fn distinct_ucs(t: &Token) -> usize {
    distinct_certificates(t)
}

/// Each distinct complete certificate encoding of a token is parsed once, however
/// many proofs carry it: decodes = distinct certificates, hits = the repeats.
#[test]
fn certificate_decodes_equal_the_distinct_certificates() {
    let mut flat = Vec::new();
    let mut raw = Vec::new();
    for transfers in [1usize, 2, 4, 6, 9] {
        let (sim, token) = spread_token(transfers);
        let l = 1 + transfers;
        let ConsolidationOutcome::Consolidated { token: out, .. } =
            client(&sim, false).consolidate(&token, &quick()).unwrap()
        else {
            panic!()
        };
        // consolidated: m distinct certificates for L proofs
        let (decoded, st) = Token::from_cbor_stats(&out.to_cbor()).unwrap();
        assert_eq!(decoded, out);
        let m = distinct_ucs(&out);
        assert_eq!(st.uc_decodes as usize, m, "L={l}");
        assert_eq!(st.uc_hits as usize, l - m, "L={l}");
        flat.push((l, st.uc_decodes));
        // original: every proof has its own certificate, nothing to share
        let (_, st) = Token::from_cbor_stats(&token.to_cbor()).unwrap();
        assert_eq!(st.uc_decodes as usize, l);
        assert_eq!(st.uc_hits, 0);
        raw.push((l, st.uc_decodes));
    }
    assert!(
        flat.iter().all(|(_, d)| *d <= 2),
        "flat in L after consolidation: {flat:?}"
    );
    assert!(
        raw.windows(2).all(|w| w[1].1 > w[0].1),
        "grows with L without sharing: {raw:?}"
    );
}

/// Interning decodes exactly like the plain decoder, never remembers failures, and a
/// different witness is a different encoding.
#[test]
fn interned_decoding_equals_plain_decoding() {
    let (sim, token) = spread_token(3);
    let ConsolidationOutcome::Consolidated { token: shared, .. } =
        client(&sim, false).consolidate(&token, &quick()).unwrap()
    else {
        panic!()
    };
    for t in [&token, &shared] {
        let bytes = t.to_cbor();
        let plain =
            Token::from_cbor_with_limits(&bytes, crate::cbor::DecodeLimits::DEFAULT).unwrap();
        let (interned, _) = Token::from_cbor_stats(&bytes).unwrap();
        assert_eq!(plain, interned);
        assert_eq!(interned.to_cbor(), bytes);
    }
    // one interner across two decodes (as for a token and its embedded source token)
    let bytes = shared.to_cbor();
    let mut interner = UcInterner::new();
    let a = Token::from_cbor_interned(&bytes, crate::cbor::DecodeLimits::DEFAULT, &mut interner)
        .unwrap();
    let after_first = interner.stats();
    let b = Token::from_cbor_interned(&bytes, crate::cbor::DecodeLimits::DEFAULT, &mut interner)
        .unwrap();
    assert_eq!(a, b);
    assert_eq!(
        interner.stats().uc_decodes,
        after_first.uc_decodes,
        "second token decodes nothing"
    );

    // a tampered encoding is its own entry; failed decodes are not remembered
    let mut witness = shared.clone();
    let mut proofs: Vec<_> = outer_proofs(&witness)
        .iter()
        .map(|o| o.proof.clone())
        .collect();
    proofs[0]
        .unicity_certificate
        .unicity_seal
        .signatures
        .push(("x".into(), vec![1; 65]));
    witness = rebuild_token(&witness, proofs).unwrap();
    let mut interner = UcInterner::new();
    Token::from_cbor_interned(
        &witness.to_cbor(),
        crate::cbor::DecodeLimits::DEFAULT,
        &mut interner,
    )
    .unwrap();
    assert_eq!(
        interner.stats().uc_decodes as usize,
        distinct_ucs(&witness),
        "the extra witness is a distinct certificate"
    );
    let mut broken = bytes.clone();
    let last = broken.len() - 1;
    broken[last] ^= 0xff;
    let mut interner = UcInterner::new();
    let _ = Token::from_cbor_interned(&broken, crate::cbor::DecodeLimits::DEFAULT, &mut interner);
    let before = interner.stats();
    let _ = Token::from_cbor_interned(&broken, crate::cbor::DecodeLimits::DEFAULT, &mut interner);
    // a failure caused a re-decode attempt, it was never served from the memo
    assert!(interner.stats().uc_decodes >= before.uc_decodes);
    // capacity 0 disables interning: the reference behavior
    let mut off = UcInterner::with_capacity(0);
    Token::from_cbor_interned(&bytes, crate::cbor::DecodeLimits::DEFAULT, &mut off).unwrap();
    assert_eq!(off.stats().uc_hits, 0);
    assert_eq!(off.stats().uc_decodes as usize, outer_proofs(&shared).len());
}

/// Nested tokens decode through the verification operation's interner.
struct EmbedsTokenCounting(Arc<Mutex<crate::api::bft::DecodeStats>>);

impl MintJustificationVerifier for EmbedsTokenCounting {
    fn tag(&self) -> u64 {
        WRAP_TAG
    }
    fn verify(
        &self,
        genesis: &crate::transaction::CertifiedMintTransaction,
        context: &mut VerificationContext<'_>,
    ) -> Result<(), crate::verify::VerificationError> {
        let bad = || crate::verify::VerificationError::MalformedMintJustification;
        let bytes = genesis.transaction().justification().ok_or_else(bad)?;
        let inner = Decoder::new(bytes)
            .expect_tag(WRAP_TAG)
            .and_then(|d| d.bytes_value().map(<[u8]>::to_vec))
            .map_err(|_| bad())?;
        let limits = context.policy().limits.decode;
        let source =
            Token::from_cbor_interned(&inner, limits, context.interner()).map_err(|_| bad())?;
        *self.0.lock().unwrap() = context.interner().stats();
        context.verify_embedded_token(&source, inner.len())
    }
}

#[test]
fn embedded_tokens_decode_through_the_operation_interner() {
    let sim = Arc::new(Mutex::new(Sim::new()));
    let source = make_token(&sim, 3, None, 3);
    let ConsolidationOutcome::Consolidated { token: source, .. } =
        client(&sim, false).consolidate(&source, &quick()).unwrap()
    else {
        panic!()
    };
    let l = outer_proofs(&source).len();
    let m = distinct_ucs(&source);
    assert!(m < l, "the embedded token shares certificates");
    let justification = encode_tag(WRAP_TAG, &encode_byte_string(&source.to_cbor()));
    let wrapper = mint_justified(&sim, 9, justification, 0);
    let seen = Arc::new(Mutex::new(crate::api::bft::DecodeStats::default()));
    let mut registry = MintJustificationRegistry::new();
    registry
        .register(Box::new(EmbedsTokenCounting(seen.clone())))
        .unwrap();
    let tb = sim.lock().unwrap().trust_base.clone();
    let (r, _) = crate::verify::verify_token_with_memo_capacity(
        &wrapper,
        &tb,
        &registry,
        VerificationPolicy::default(),
        DEFAULT_SEAL_MEMO_CAPACITY,
    );
    r.unwrap();
    let st = *seen.lock().unwrap();
    assert_eq!(
        st.uc_decodes as usize, m,
        "each distinct embedded certificate parsed once"
    );
    assert_eq!(st.uc_hits as usize, l - m);
}

// --------------------------------------------- unsharded direct target ----

fn unsharded_client_with(
    sim: &Arc<Mutex<Sim>>,
    partition: u32,
    topology: PartitionTopology,
) -> TestClient {
    let tb = sim.lock().unwrap().trust_base.clone();
    ProofClient::with_host_defaults(
        ProofClientConfig {
            partition_id: partition,
            topology,
        },
        vec![(ShardId::root(), node(sim))],
        tb,
        2,
    )
    .unwrap()
}

fn unsharded_client(sim: &Arc<Mutex<Sim>>, pinned: bool) -> TestClient {
    unsharded_client_with(sim, PARTITION, unsharded_topology(pinned))
}

fn unsharded_token(transfers: usize) -> (Arc<Mutex<Sim>>, Token) {
    let sim = Arc::new(Mutex::new(Sim::new_unsharded()));
    let token = make_token(&sim, 1, None, transfers);
    (sim, token)
}

fn each_certificate(batch: &mut InclusionProofBatch, f: impl Fn(&mut UnicityCertificate)) {
    for p in &mut batch.proofs {
        f(&mut p.proof.unicity_certificate);
    }
}

#[test]
fn an_unsharded_latest_batch_consolidates_without_any_view() {
    for pinned in [false, true] {
        let (sim, token) = unsharded_token(3);
        let tb = sim.lock().unwrap().trust_base.clone();
        let before = token.clone();
        assert!(distinct_seals(outer_proofs(&token).iter().map(|o| o.proof)) >= 3);
        let calls = sim.lock().unwrap().batch_calls;

        let out = unsharded_client(&sim, pinned)
            .consolidate(&token, &quick())
            .unwrap();
        let ConsolidationOutcome::Consolidated {
            token: out,
            summary,
        } = out
        else {
            panic!("{out:?}")
        };
        assert_eq!(token, before);
        out.verify(&tb).unwrap();
        assert_eq!(tx_bytes(&out), tx_bytes(&token));
        assert_eq!(
            distinct_seals(outer_proofs(&out).iter().map(|o| o.proof)),
            1
        );
        // one latest request, one wave, no view, nothing derived
        assert_eq!(sim.lock().unwrap().batch_calls, calls + 1);
        assert_eq!((summary.requests, summary.shards), (1, 1));
        assert_eq!(summary.certificates_derived, 0);
        assert_eq!(summary.verification_quorum_checks, 1);
        assert_eq!(summary.outer_seals_after, 1);
        assert!(!summary.already_shared);
        for (a, b) in outer_proofs(&out).iter().zip(outer_proofs(&token)) {
            assert_eq!(a.proof.certification_data, b.proof.certification_data);
            assert_eq!(a.proof.reference_time, b.proof.reference_time);
        }

        // already shared: no request, the strict authority is still checked
        let again = unsharded_client(&sim, pinned)
            .consolidate(&out, &quick())
            .unwrap();
        let ConsolidationOutcome::Consolidated { summary, .. } = again else {
            panic!("{again:?}")
        };
        assert!(summary.already_shared);
        assert_eq!(sim.lock().unwrap().batch_calls, calls + 1);
    }
}

#[test]
fn the_direct_target_never_falls_back_or_downgrades() {
    let unsharded = |mangle: fn(&mut InclusionProofBatch)| {
        let (sim, token) = unsharded_token(2);
        sim.lock().unwrap().faults.mangle_latest = Some(mangle);
        let out = unsharded_client(&sim, true).consolidate(&token, &quick());
        (sim, token, out)
    };
    let context = |out: &Result<ConsolidationOutcome, ConsolidationError>| {
        matches!(
            out,
            Err(ConsolidationError::Integrity(
                IntegrityError::Context { .. }
            ))
        )
    };

    // an empty shard id with a nonempty shard path
    let (_, _, out) = unsharded(|b| {
        each_certificate(b, |uc| {
            uc.shard_tree_certificate.sibling_hash_list = vec![vec![0; 32]]
        })
    });
    assert!(context(&out), "{out:?}");

    // a malformed sidecar beside an unsharded certificate: validated through the
    // view path (and refused), never ignored in favor of the direct target
    let (_, _, out) = unsharded(|b| {
        b.partition_view = Some(PartitionView {
            partition_id: PARTITION,
            leaves: Vec::new(),
        })
    });
    assert!(
        matches!(
            out,
            Err(ConsolidationError::Integrity(IntegrityError::View(_)))
        ),
        "{out:?}"
    );

    // a nonempty shard without its view stays unavailable
    let (_, _, out) = unsharded(|b| {
        each_certificate(b, |uc| {
            uc.shard_tree_certificate.shard = ShardId::root().split().0
        })
    });
    assert!(matches!(
        out,
        Ok(ConsolidationOutcome::Unavailable {
            reason: UnavailableReason::PartitionViewUnavailable,
            ..
        })
    ));

    // forged material: a changed root, a tampered signature
    let (_, _, out) =
        unsharded(|b| each_certificate(b, |uc| uc.input_record.hash.as_mut().unwrap()[0] ^= 1));
    assert!(
        matches!(
            out,
            Err(ConsolidationError::Integrity(IntegrityError::Target(_)))
        ),
        "{out:?}"
    );
    let (_, _, out) =
        unsharded(|b| each_certificate(b, |uc| uc.unicity_seal.signatures[0].1[3] ^= 1));
    assert!(
        matches!(
            out,
            Err(ConsolidationError::Integrity(IntegrityError::Target(_)))
        ),
        "{out:?}"
    );
    // a seal of a quorum-less witness
    let (_, _, out) =
        unsharded(|b| each_certificate(b, |uc| uc.unicity_seal.signatures.truncate(1)));
    assert!(
        matches!(
            out,
            Err(ConsolidationError::Integrity(IntegrityError::Target(_)))
        ),
        "{out:?}"
    );

    // mixed certificates in one batch
    let (_, _, out) = unsharded(|b| {
        let last = b.proofs.len() - 1;
        b.proofs[last]
            .proof
            .unicity_certificate
            .unicity_seal
            .timestamp += 1;
    });
    assert!(
        matches!(out, Err(ConsolidationError::InvalidResponse { .. })),
        "{out:?}"
    );

    // a sharded configuration never accepts an unsharded certificate or a missing view
    let (sim, token) = spread_token(3);
    let c = client(&sim, true);
    sim.lock().unwrap().faults.mangle_latest = Some(|b| b.partition_view = None);
    assert!(matches!(
        c.consolidate(&token, &quick()),
        Ok(ConsolidationOutcome::Unavailable {
            reason: UnavailableReason::PartitionViewUnavailable,
            retryable: true
        })
    ));
    sim.lock().unwrap().faults.mangle_latest = Some(|b| {
        b.partition_view = None;
        each_certificate(b, |uc| uc.shard_tree_certificate.shard = ShardId::root());
    });
    let out = c.consolidate(&token, &quick());
    assert!(context(&out), "{out:?}");
}

#[test]
fn the_direct_target_is_bound_to_the_configured_partition_and_pins() {
    let (sim, token) = unsharded_token(2);
    let other_partition = unsharded_client_with(&sim, PARTITION + 1, unsharded_topology(false));
    let out = other_partition.consolidate(&token, &quick());
    assert!(
        matches!(
            out,
            Err(ConsolidationError::Integrity(
                IntegrityError::Context { .. }
            ))
        ),
        "{out:?}"
    );
    let wrong_pin = unsharded_client_with(
        &sim,
        PARTITION,
        PartitionTopology::single_shard().with_shard_conf_hash(&ShardId::root(), [0xee; 32]),
    );
    let out = wrong_pin.consolidate(&token, &quick());
    assert!(
        matches!(
            out,
            Err(ConsolidationError::Integrity(
                IntegrityError::Context { .. }
            ))
        ),
        "{out:?}"
    );
}

#[test]
fn a_stale_direct_target_is_unavailable_not_accepted() {
    let (sim, token) = unsharded_token(2);
    let rounds = sim.lock().unwrap().rounds.len();
    // serve a genuinely signed round older than the evidence
    sim.lock().unwrap().faults.latest_override = Some(rounds - 3);
    let out = unsharded_client(&sim, false).consolidate(&token, &quick());
    assert!(
        matches!(
            out,
            Ok(ConsolidationOutcome::Unavailable {
                reason: UnavailableReason::TargetNotYetAvailable,
                retryable: true
            })
        ),
        "{out:?}"
    );
}

#[test]
fn direct_replacements_share_the_session_memo() {
    // loose proofs: one quorum verification for the target, reused by every replacement
    let (sim, token) = unsharded_token(3);
    let items: Vec<ProofItem> = outer_proofs(&token)
        .iter()
        .map(|o| ProofItem {
            state_id: o.state_id.clone(),
            proof: o.proof.clone(),
        })
        .collect();
    let out = unsharded_client(&sim, true)
        .consolidate_proofs(&items, &quick())
        .unwrap();
    let BundleOutcome::Consolidated(bundle) = out else {
        panic!("{out:?}")
    };
    assert_eq!(bundle.summary.requests, 1);
    assert_eq!(bundle.summary.certificates_derived, 0);
    // the original evidence's seals, then exactly one more quorum for the target
    assert_eq!(
        bundle.summary.consolidation_quorum_checks,
        distinct_seals(items.iter().map(|i| &i.proof)) as u64 + 1
    );
    assert_eq!(distinct_seals(bundle.proofs.iter()), 1);
}

/// A cancelled or already-expired attempt returns at once; it does not verify the input token
/// first (an invalid token must not turn into `InvalidToken` either).
#[test]
fn a_cancelled_or_expired_call_does_not_verify_the_input_token_first() {
    let (sim, token) = spread_token(2);
    let c = client(&sim, false);
    let mut proofs: Vec<_> = outer_proofs(&token)
        .iter()
        .map(|o| o.proof.clone())
        .collect();
    proofs[0]
        .unicity_certificate
        .unicity_seal
        .signatures
        .clear();
    let bad = rebuild_token(&token, proofs).unwrap();
    assert!(matches!(
        c.consolidate(&bad, &quick()),
        Err(ConsolidationError::InvalidToken(_))
    ));
    for t in [&token, &bad] {
        let options = quick();
        options.cancel.cancel();
        assert!(matches!(
            c.consolidate(t, &options),
            Err(ConsolidationError::Cancelled)
        ));
        let options = ConsolidateOptions {
            timeout_ms: 0,
            ..quick()
        };
        assert!(matches!(
            c.consolidate(t, &options),
            Err(ConsolidationError::Timeout)
        ));
    }
}

/// An executor that loses results must produce an error, not a panic.
struct ShortExecutor;

impl WaveExecutor for ShortExecutor {
    fn run<I: Sync, T: Send>(&self, inputs: &[I], job: &(dyn Fn(&I) -> T + Sync)) -> Vec<T> {
        inputs.iter().skip(1).map(job).collect()
    }
}

#[test]
fn a_wave_executor_returning_fewer_results_than_jobs_is_an_error() {
    let (sim, token) = spread_token(2);
    let tb = sim.lock().unwrap().trust_base.clone();
    let c = ProofClient::new(
        ProofClientConfig {
            partition_id: PARTITION,
            topology: topology(false),
        },
        (0..2)
            .map(|i| {
                (
                    shard_ids()[i].clone(),
                    Node {
                        sim: sim.clone(),
                        shard: i,
                    },
                )
            })
            .collect(),
        tb,
        SystemClock::new(),
        ShortExecutor,
    )
    .unwrap();
    assert!(matches!(
        c.consolidate(&token, &quick()),
        Err(ConsolidationError::Configuration(_))
    ));
}
