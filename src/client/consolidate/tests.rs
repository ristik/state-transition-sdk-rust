//! Token-level consolidation against an in-process simulated network: a
//! two-shard partition with real signed seals, a real radix SMT per shard,
//! retained historical views, and the SDK's own mint/transfer flows producing
//! tokens whose proofs sit under *different* seals.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use super::*;
use crate::api::bft::root_trust_base::RootTrustBaseNodeInfo;
use crate::api::bft::unicity_tree::HashStep;
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
use crate::verify::{MintJustificationRegistry, MintJustificationVerifier, VerificationContext};

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
}

fn shard_of(key: &[u8; 32]) -> usize {
    usize::from(bit_at(key, 0))
}

impl Sim {
    fn new() -> Self {
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
        for s in 0..2 {
            let (root, p) = smt(&self.leaves[s]);
            let prev_root = prev.map_or(Vec::new(), |p| p.roots[s].clone());
            let changed = prev_root != root;
            view_leaves.push(PartitionViewLeaf {
                shard_id: shard_ids()[s].clone(),
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
        let tree = view.build_shard_tree(PARTITION, &topology(true)).unwrap();
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
                input_record: leaf.input_record.to_input_record().unwrap(),
                technical_record_hash: Some(leaf.tr_hash.clone()),
                shard_configuration_hash: leaf.shard_conf_hash.clone(),
                shard_tree_certificate: tree.certificate(&leaf.shard_id).unwrap(),
                unicity_tree_certificate: utc.clone(),
                unicity_seal: seal.clone(),
            }
        };
        self.rounds.push(Round {
            ucs: [uc(0), uc(1)],
            seal,
            roots,
            view,
            leaves: self.leaves.clone(),
            paths,
        });
    }

    fn proof_at(&self, round: usize, key: &[u8; 32]) -> Option<InclusionProof> {
        let s = shard_of(key);
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
        sim.leaves[shard_of(&key)].insert(key, value);
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
                let partition_view = Some(sim.rounds[round].view.clone());
                if let Some(hook) = sim.faults.after_latest.take() {
                    hook(&mut sim);
                }
                Ok(InclusionProofBatch {
                    proofs,
                    partition_view,
                })
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
