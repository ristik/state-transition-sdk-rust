//! Orchestration of explicit consolidation against the shared Go fixture corpus
//! (aggregator-go `testdata/uc-consolidation/v1`, see `PROVENANCE.txt`) served by
//! loopback mock shards through the real HTTP batch adapter
//! (`get_inclusion_proofs.v1`, aggregator-go PR 193 shapes).
//!
//! The corpus holds proof bundles, not tokens, so these tests drive
//! [`ProofClient::consolidate_proofs`]; token semantics are covered by the
//! in-crate simulation tests.
#![cfg(feature = "http")]
#![allow(clippy::result_large_err)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use unicity_token::api::bft::root_trust_base::RootTrustBaseNodeInfo;
use unicity_token::api::bft::{RootTrustBase, ShardId};
use unicity_token::api::{InclusionProofResponse, NetworkId, StateId};
use unicity_token::cbor::Decoder;
use unicity_token::client::{
    BundleOutcome, CancelToken, ConsolidateOptions, ConsolidationError, HttpAggregatorClient,
    IntegrityError, ProofClient, ProofClientConfig, ProofItem, SystemClock, ThreadedExecutor,
    UnavailableReason,
};
use unicity_token::consolidation::{PartitionTopology, PartitionViewError};
use unicity_token::crypto::signature::PublicKey;
use unicity_token::verify::VerificationError;

fn corpus(path: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/uc-consolidation/corpus-v1")
        .join(path);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn corpus_bytes(path: &str) -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/uc-consolidation/corpus-v1")
        .join(path);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn shard(bits: &str) -> ShardId {
    let mut id = ShardId::root();
    for c in bits.chars() {
        let (z, o) = id.split();
        id = if c == '0' { z } else { o };
    }
    id
}

fn trust_base(path: &str) -> RootTrustBase {
    let bytes = corpus_bytes(path);
    let items = Decoder::new(&bytes)
        .expect_tag(39000)
        .unwrap()
        .array(Some(10))
        .unwrap();
    let nodes = items[4]
        .array(None)
        .unwrap()
        .into_iter()
        .map(|n| {
            let f = n.array(Some(3)).unwrap();
            RootTrustBaseNodeInfo {
                node_id: f[0].text().unwrap().into(),
                signing_key: PublicKey::from_bytes(f[1].bytes_value().unwrap()).unwrap(),
                stake: f[2].uint().unwrap(),
            }
        })
        .collect();
    RootTrustBase::try_new(
        items[0].uint().unwrap(),
        NetworkId::new(items[1].uint().unwrap() as u16).unwrap(),
        items[2].uint().unwrap(),
        items[3].uint().unwrap(),
        nodes,
        items[5].uint().unwrap(),
    )
    .unwrap()
}

// ---------------------------------------------------------------- mock shard

/// What a mock shard answers.
#[derive(Clone)]
enum Reply {
    /// A JSON-RPC result.
    Result(Value),
    /// A JSON-RPC error object.
    Error(i64, Value),
    /// A bare HTTP status.
    Status(u16),
    /// Close the connection without answering.
    Drop,
}

struct Shard {
    url: String,
    /// The `params` of every request received.
    params: Arc<Mutex<Vec<Value>>>,
}

#[derive(Default)]
struct Gauge {
    now: AtomicUsize,
    max: AtomicUsize,
}

fn read_request(stream: &mut std::net::TcpStream) -> Option<String> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = stream.read(&mut tmp).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..pos]).to_lowercase();
            let len: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
            if buf.len() >= pos + 4 + len {
                return Some(String::from_utf8_lossy(&buf[pos + 4..pos + 4 + len]).into_owned());
            }
        }
    }
}

impl Shard {
    fn start(
        reply: impl Fn(&Value) -> Reply + Send + 'static,
        delay: Duration,
        gauge: Arc<Gauge>,
    ) -> Shard {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!(
            "http://127.0.0.1:{}/",
            listener.local_addr().unwrap().port()
        );
        let params = Arc::new(Mutex::new(Vec::new()));
        let log = params.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let reply_fn = &reply;
                let Some(body) = read_request(&mut stream) else {
                    continue;
                };
                let request: Value = serde_json::from_str(&body).unwrap();
                log.lock().unwrap().push(request["params"].clone());
                let now = gauge.now.fetch_add(1, Ordering::SeqCst) + 1;
                gauge.max.fetch_max(now, Ordering::SeqCst);
                std::thread::sleep(delay);
                gauge.now.fetch_sub(1, Ordering::SeqCst);
                let (status, body) = match reply_fn(&request["params"]) {
                    Reply::Result(r) => (
                        "200 OK",
                        json!({"jsonrpc":"2.0","id":request["id"],"result":r}).to_string(),
                    ),
                    Reply::Error(code, data) => (
                        "200 OK",
                        json!({"jsonrpc":"2.0","id":request["id"],
                               "error":{"code":code,"message":"x","data":data}})
                        .to_string(),
                    ),
                    Reply::Status(s) => (
                        match s {
                            500 => "500 Internal Server Error",
                            _ => "503 Service Unavailable",
                        },
                        "{}".to_string(),
                    ),
                    Reply::Drop => continue,
                };
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        Shard { url, params }
    }
}

// --------------------------------------------------------------- case setup

struct Case {
    dir: &'static str,
    topology: PartitionTopology,
    partition: u32,
    trust_base: RootTrustBase,
    items: Vec<ProofItem>,
    master_shard: String,
    master_reply: Value,
    peers: Vec<(String, Value)>,
    expected: Value,
}

fn load(dir: &'static str) -> Case {
    let context: Value = serde_json::from_str(&corpus(&format!("{dir}/context.json"))).unwrap();
    let requests: Value = serde_json::from_str(&corpus(&format!("{dir}/requests.json"))).unwrap();
    let responses: Value = serde_json::from_str(&corpus(&format!("{dir}/responses.json"))).unwrap();
    let expected: Value = serde_json::from_str(&corpus(&format!("{dir}/expected.json"))).unwrap();

    let shards: Vec<String> = context["shards"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_string())
        .collect();
    let ids: Vec<ShardId> = shards.iter().map(|s| shard(s)).collect();
    let mut topology = PartitionTopology::new(if ids.len() == 1 { vec![] } else { ids.clone() });
    for (id, cfg) in ids.iter().zip(context["shardConfigs"].as_array().unwrap()) {
        let h: [u8; 32] = hex::decode(cfg["hash"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        topology = topology.with_shard_conf_hash(id, h);
    }

    let items = requests["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            let req = hex::decode(e["request"].as_str().unwrap()).unwrap();
            let f = Decoder::new(&req)
                .expect_tag(39030)
                .unwrap()
                .array(Some(4))
                .unwrap();
            let state_id = StateId::from_cbor(f[1]).unwrap();
            let proof = hex::decode(e["proof"].as_str().unwrap()).unwrap();
            let InclusionProofResponse::Certified { proof, .. } =
                InclusionProofResponse::from_cbor(Decoder::new(&proof)).unwrap()
            else {
                panic!("evidence is certified")
            };
            ProofItem { state_id, proof }
        })
        .collect();

    Case {
        dir,
        topology,
        partition: context["partitionId"].as_u64().unwrap() as u32,
        trust_base: trust_base(&format!("{dir}/trust-base.cbor")),
        items,
        master_shard: requests["master"]["shard"].as_str().unwrap().to_string(),
        master_reply: responses["master"]["result"].clone(),
        peers: responses["peers"]
            .as_array()
            .map(|p| {
                p.iter()
                    .map(|p| {
                        (
                            p["shard"].as_str().unwrap().to_string(),
                            p["response"]["result"].clone(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default(),
        expected,
    }
}

type Client = ProofClient<HttpAggregatorClient, SystemClock, ThreadedExecutor>;

struct Run {
    client: Client,
    shards: Vec<(String, Shard)>,
}

impl Run {
    fn shard(&self, bits: &str) -> &Shard {
        &self.shards.iter().find(|(b, _)| b == bits).unwrap().1
    }
}

/// Start one mock per participating shard with the given replies.
fn start(
    case: &Case,
    master: impl Fn(&Value) -> Reply + Send + 'static,
    peer: impl Fn(&str, &Value) -> Reply + Send + Clone + 'static,
    delay: Duration,
    max_parallel: usize,
    gauge: Arc<Gauge>,
) -> Run {
    let mut shards = vec![(
        case.master_shard.clone(),
        Shard::start(master, delay, gauge.clone()),
    )];
    for (bits, _) in &case.peers {
        let (b, p) = (bits.clone(), peer.clone());
        shards.push((
            bits.clone(),
            Shard::start(move |params| p(&b, params), delay, gauge.clone()),
        ));
    }
    let endpoints = shards
        .iter()
        .map(|(bits, s)| (shard(bits), HttpAggregatorClient::new_insecure_http(&s.url)))
        .collect();
    let client = ProofClient::with_host_defaults(
        ProofClientConfig {
            partition_id: case.partition,
            topology: case.topology.clone(),
        },
        endpoints,
        case.trust_base.clone(),
        max_parallel,
    )
    .unwrap();
    Run { client, shards }
}

/// Serve exactly the corpus's recorded responses.
fn replay(case: &Case, max_parallel: usize) -> Run {
    let master = case.master_reply.clone();
    let peers = case.peers.clone();
    start(
        case,
        move |_| Reply::Result(master.clone()),
        move |bits, _| Reply::Result(peers.iter().find(|(b, _)| b == bits).unwrap().1.clone()),
        Duration::ZERO,
        max_parallel,
        Arc::new(Gauge::default()),
    )
}

fn opts() -> ConsolidateOptions {
    ConsolidateOptions {
        timeout_ms: 5_000,
        ..Default::default()
    }
}

const POSITIVE: [&str; 6] = [
    "shards-1",
    "shards-4",
    "shards-8",
    "shards-4-timeout-unchanged",
    "nil-vs-empty",
    "large-values",
];

#[test]
fn corpus_cases_consolidate_to_the_reference_proofs() {
    for dir in POSITIVE {
        let case = load(dir);
        let run = replay(&case, 4);
        let outcome = run
            .client
            .consolidate_proofs(&case.items, &opts())
            .unwrap_or_else(|e| panic!("{dir}: {e}"));
        let BundleOutcome::Consolidated(bundle) = outcome else {
            panic!("{dir}: unavailable")
        };
        assert_eq!(bundle.proofs.len(), case.items.len(), "{dir}");

        // the reference bundle's proofs, byte for byte (the aggregator's block number
        // prefixes the proof in the reference encoding)
        let mut expected: Vec<String> = Vec::new();
        for s in case.expected["bundle"].as_array().unwrap() {
            for p in s["proofs"].as_array().unwrap() {
                expected.push(p.as_str().unwrap().to_string());
            }
        }
        for p in &bundle.proofs {
            let mine = hex::encode(p.to_cbor());
            assert!(
                expected
                    .iter()
                    .any(|e| e.starts_with("82") && e.ends_with(&mine)),
                "{dir}: replacement proof equals one of the reference's"
            );
        }

        let s = &bundle.summary;
        assert_eq!(s.outer_seals_after, 1, "{dir}");
        // lazy derivation: certificates of the m participating shards, not of all S
        assert_eq!(
            s.certificates_derived,
            1 + case.peers.len(),
            "{dir}: m derivations"
        );
        assert_eq!(s.admission.steps as usize, case.items.len(), "{dir}");
        assert!(s.outer_seals_before >= 2, "{dir}");
        assert_eq!(
            s.requests,
            1 + case.peers.len(),
            "{dir}: master wave + one request per peer"
        );
        // evidence seals (distinct) plus the master seal, authenticated once each
        let evidence = case.expected["counters"]["evidenceQuorumChecks"]
            .as_u64()
            .unwrap();
        assert_eq!(s.consolidation_quorum_checks, evidence + 1, "{dir}");
        assert_eq!(s.master, Some(shard(&case.master_shard)), "{dir}");

        // wire shape of the requests: master asks for "latest", peers for the exact
        // root of the authenticated view
        let m = run.shard(&case.master_shard).params.lock().unwrap();
        assert_eq!(m.len(), 1, "{dir}");
        assert_eq!(m[0]["stateRoot"], "latest");
        let ids = m[0]["stateIds"].as_array().unwrap();
        assert!(ids.iter().all(|i| i.as_str().unwrap().len() == 64));
        for (bits, _) in &case.peers {
            let p = run.shard(bits).params.lock().unwrap();
            assert_eq!(p.len(), 1, "{dir}");
            let root = p[0]["stateRoot"].as_str().unwrap();
            assert_eq!(root.len(), 64, "{dir}: exact root");
            let want = case.expected["shards"]
                .as_array()
                .unwrap()
                .iter()
                .find(|s| s["shard"] == *bits)
                .unwrap()["stateRoot"]
                .as_str()
                .unwrap();
            assert_eq!(
                root, want,
                "{dir}: the peer is asked for the root the view names"
            );
        }
        let _ = case.dir;
    }
}

#[test]
fn exact_root_wave_is_bounded_parallel() {
    let case = load("shards-8"); // three peers
    let gauge = Arc::new(Gauge::default());
    let master = case.master_reply.clone();
    let peers = case.peers.clone();
    let run = start(
        &case,
        move |_| Reply::Result(master.clone()),
        move |bits, _| Reply::Result(peers.iter().find(|(b, _)| b == bits).unwrap().1.clone()),
        Duration::from_millis(150),
        2,
        gauge.clone(),
    );
    let started = std::time::Instant::now();
    let out = run.client.consolidate_proofs(&case.items, &opts());
    assert!(matches!(out, Ok(BundleOutcome::Consolidated(_))), "{out:?}");
    // master (150ms) then three peers on two threads: two rounds
    assert_eq!(
        gauge.max.load(Ordering::SeqCst),
        2,
        "bounded by max_parallel"
    );
    // wall-clock is not asserted (shared hosts); the concurrency gauge above is the metric
    let _ = started;
}

// ------------------------------------------------------ classification table

fn rpc_error(code: i64, detail: &str, retryable: bool) -> Reply {
    Reply::Error(
        code,
        json!({"reason":"x","detail":detail,"retryable":retryable}),
    )
}

fn run_with_master(reply: Reply) -> Result<BundleOutcome, ConsolidationError> {
    let case = load("shards-4");
    let run = start(
        &case,
        move |_| reply.clone(),
        |_, _| panic!("no peer is contacted when the master failed"),
        Duration::ZERO,
        4,
        Arc::new(Gauge::default()),
    );
    run.client.consolidate_proofs(&case.items, &opts())
}

#[test]
fn rpc_failures_are_typed_not_collapsed_into_unavailable() {
    use UnavailableReason::*;
    let unavailable = |r| move |out: Result<BundleOutcome, ConsolidationError>| matches!(out, Ok(BundleOutcome::Unavailable { reason, .. }) if reason == r);
    // the specified material/pressure outcomes
    assert!(unavailable(UnsupportedCapability)(run_with_master(
        rpc_error(-32601, "", false)
    )));
    assert!(unavailable(Busy)(run_with_master(rpc_error(
        -32006,
        "active_requests",
        true
    ))));
    assert!(unavailable(TargetNotRetained)(run_with_master(rpc_error(
        -32008,
        "view_not_retained",
        true
    ))));
    assert!(unavailable(TargetNotYetAvailable)(run_with_master(
        rpc_error(-32008, "no_finalized_view", true)
    )));
    assert!(unavailable(TargetNotYetAvailable)(run_with_master(
        rpc_error(-32008, "state_not_included", true)
    )));
    assert!(unavailable(PartitionViewUnavailable)(run_with_master(
        rpc_error(-32008, "partition_view_unavailable", true)
    )));
    assert!(unavailable(UnsupportedConfiguration)(run_with_master(
        rpc_error(-32008, "unsupported_configuration", false)
    )));
    match run_with_master(rpc_error(-32008, "unsupported_configuration", false)) {
        Ok(BundleOutcome::Unavailable { retryable, .. }) => assert!(!retryable),
        other => panic!("{other:?}"),
    }
    // operational failures keep their own type
    assert!(matches!(
        run_with_master(rpc_error(-32004, "", false)),
        Err(ConsolidationError::Server { .. })
    ));
    assert!(matches!(
        run_with_master(rpc_error(-32603, "", false)),
        Err(ConsolidationError::Server { .. })
    ));
    assert!(matches!(
        run_with_master(rpc_error(-32099, "", false)),
        Err(ConsolidationError::Server { .. })
    ));
    for (code, detail) in [
        (-32602, "malformed_params"),
        (-32007, "state_count"),
        (-32600, "invalid_envelope"),
    ] {
        assert!(matches!(
            run_with_master(rpc_error(code, detail, false)),
            Err(ConsolidationError::Rejected { .. })
        ));
    }
    // HTTP/connection failures are transport errors
    assert!(matches!(
        run_with_master(Reply::Status(500)),
        Err(ConsolidationError::Transport { .. })
    ));
    assert!(matches!(
        run_with_master(Reply::Drop),
        Err(ConsolidationError::Transport { .. })
    ));
    // a malformed result
    assert!(matches!(
        run_with_master(Reply::Result(json!({"proofs": "nope"}))),
        Err(ConsolidationError::InvalidResponse { .. })
    ));
    assert!(matches!(
        run_with_master(Reply::Result(json!({"proofs": [], "surprise": 1}))),
        Err(ConsolidationError::InvalidResponse { .. })
    ));
}

#[test]
fn peer_failures_are_typed_too() {
    let case = load("shards-4");
    let master = case.master_reply.clone();
    for (reply, check) in [
        (rpc_error(-32008, "view_not_retained", true), 0),
        (rpc_error(-32004, "", false), 1),
        (Reply::Status(503), 2),
    ] {
        let m = master.clone();
        let r = reply.clone();
        let run = start(
            &case,
            move |_| Reply::Result(m.clone()),
            move |_, _| r.clone(),
            Duration::ZERO,
            4,
            Arc::new(Gauge::default()),
        );
        let out = run.client.consolidate_proofs(&case.items, &opts());
        match check {
            0 => assert!(matches!(
                out,
                Ok(BundleOutcome::Unavailable {
                    reason: UnavailableReason::TargetNotRetained,
                    retryable: true
                })
            )),
            1 => assert!(matches!(out, Err(ConsolidationError::Server { .. }))),
            _ => assert!(matches!(out, Err(ConsolidationError::Transport { .. }))),
        }
    }
}

// ----------------------------------------------------------------- integrity

/// Re-encode a hex result element after `edit` changed its certified proof.
fn edit_proof(
    hex_cbor: &Value,
    edit: impl Fn(&mut unicity_token::api::inclusion_proof::InclusionProof),
) -> Value {
    let bytes = hex::decode(hex_cbor.as_str().unwrap()).unwrap();
    let InclusionProofResponse::Certified {
        block_number,
        mut proof,
    } = InclusionProofResponse::from_cbor(Decoder::new(&bytes)).unwrap()
    else {
        panic!()
    };
    edit(&mut proof);
    Value::String(hex::encode(
        InclusionProofResponse::Certified {
            block_number,
            proof,
        }
        .to_cbor(),
    ))
}

fn consolidate_with(master: Value, peer: Value) -> Result<BundleOutcome, ConsolidationError> {
    let case = load("shards-4");
    let run = start(
        &case,
        move |_| Reply::Result(master.clone()),
        move |_, _| Reply::Result(peer.clone()),
        Duration::ZERO,
        4,
        Arc::new(Gauge::default()),
    );
    run.client.consolidate_proofs(&case.items, &opts())
}

#[test]
fn integrity_failures_are_never_unavailability() {
    let case = load("shards-4");
    let master = case.master_reply.clone();
    let peer = case.peers[0].1.clone();

    // the unmodified responses succeed
    assert!(matches!(
        consolidate_with(master.clone(), peer.clone()),
        Ok(BundleOutcome::Consolidated(_))
    ));

    // a partition view of another vector: does not hash into the seal
    let mut m = master.clone();
    let view = m["partitionView"].as_str().unwrap().to_string();
    let mut bytes = hex::decode(&view).unwrap();
    let n = bytes.len();
    bytes[n - 5] ^= 1; // inside the last leaf's configuration hash
    m["partitionView"] = Value::String(hex::encode(bytes));
    assert!(matches!(
        consolidate_with(m, peer.clone()),
        Err(ConsolidationError::Integrity(IntegrityError::View(_)))
    ));

    // invalid signature witness in the master's certificate
    let mut m = master.clone();
    let proofs: Vec<Value> = m["proofs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            edit_proof(p, |p| {
                p.unicity_certificate.unicity_seal.signatures[0].1[3] ^= 1
            })
        })
        .collect();
    m["proofs"] = Value::Array(proofs);
    assert!(matches!(
        consolidate_with(m, peer.clone()),
        Err(ConsolidationError::Integrity(IntegrityError::View(
            PartitionViewError::Seal(VerificationError::QuorumNotMet)
        )))
    ));

    // a master proof for other certification data
    let mut m = master.clone();
    let mut proofs = m["proofs"].as_array().unwrap().clone();
    proofs.swap(0, 1);
    m["proofs"] = Value::Array(proofs);
    assert!(matches!(
        consolidate_with(m, peer.clone()),
        Err(ConsolidationError::Integrity(
            IntegrityError::Binding { .. }
        ))
    ));

    // missing / extra / duplicated proofs
    let mut m = master.clone();
    let mut proofs = m["proofs"].as_array().unwrap().clone();
    proofs.pop();
    m["proofs"] = Value::Array(proofs);
    assert!(matches!(
        consolidate_with(m, peer.clone()),
        Err(ConsolidationError::InvalidResponse { .. })
    ));
    let mut p = peer.clone();
    let mut proofs = p["proofs"].as_array().unwrap().clone();
    proofs.push(proofs[0].clone());
    p["proofs"] = Value::Array(proofs);
    assert!(matches!(
        consolidate_with(master.clone(), p),
        Err(ConsolidationError::InvalidResponse { .. })
    ));

    // the peer serves another root than the one requested
    let mut p = peer.clone();
    let proofs: Vec<Value> = p["proofs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| edit_proof(x, |x| x.unicity_certificate.input_record.hash[0] ^= 1))
        .collect();
    p["proofs"] = Value::Array(proofs);
    assert!(matches!(
        consolidate_with(master.clone(), p),
        Err(ConsolidationError::Integrity(
            IntegrityError::RootSubstitution { .. }
        ))
    ));

    // an exact-root response must not carry a partition view
    let mut p = peer.clone();
    p["partitionView"] = master["partitionView"].clone();
    assert!(matches!(
        consolidate_with(master.clone(), p),
        Err(ConsolidationError::InvalidResponse { .. })
    ));

    // a latest response without a partition view is unavailable, not an integrity failure
    let mut m = master.clone();
    m.as_object_mut().unwrap().remove("partitionView");
    assert!(matches!(
        consolidate_with(m, peer.clone()),
        Ok(BundleOutcome::Unavailable {
            reason: UnavailableReason::PartitionViewUnavailable,
            ..
        })
    ));

    // a served proof folding to another leaf value
    let mut p = peer;
    let proofs: Vec<Value> = p["proofs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| edit_proof(x, |x| x.reference_time += 1))
        .collect();
    p["proofs"] = Value::Array(proofs);
    assert!(matches!(
        consolidate_with(master, p),
        Err(ConsolidationError::Integrity(
            IntegrityError::Binding { .. }
        ))
    ));
}

// ------------------------------------------------- deadline and cancellation

#[test]
fn deadline_and_cancellation_are_typed_and_stop_the_attempt() {
    let case = load("shards-4");
    let master = case.master_reply.clone();

    // a cancelled token makes no request at all
    let run = replay(&case, 4);
    let cancel = CancelToken::new();
    cancel.cancel();
    let out = run
        .client
        .consolidate_proofs(&case.items, &ConsolidateOptions { cancel, ..opts() });
    assert_eq!(out, Err(ConsolidationError::Cancelled));
    assert!(run
        .shards
        .iter()
        .all(|(_, s)| s.params.lock().unwrap().is_empty()));

    // a master slower than the one total deadline
    let m = master.clone();
    let run = start(
        &case,
        move |_| Reply::Result(m.clone()),
        |_, _| Reply::Result(json!({"proofs": []})),
        Duration::from_millis(800),
        4,
        Arc::new(Gauge::default()),
    );
    let started = std::time::Instant::now();
    let out = run.client.consolidate_proofs(
        &case.items,
        &ConsolidateOptions {
            timeout_ms: 200,
            ..opts()
        },
    );
    assert_eq!(out, Err(ConsolidationError::Timeout));
    assert!(
        started.elapsed() < Duration::from_millis(700),
        "the request timeout fits the budget"
    );
    assert!(
        run.shard("11").params.lock().unwrap().is_empty(),
        "no peer is contacted after the deadline"
    );

    // cancellation while the master is in flight: nothing else is started
    let m = master;
    let run = start(
        &case,
        move |_| Reply::Result(m.clone()),
        |_, _| Reply::Result(json!({"proofs": []})),
        Duration::from_millis(300),
        4,
        Arc::new(Gauge::default()),
    );
    let cancel = CancelToken::new();
    let c2 = cancel.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        c2.cancel();
    });
    let out = run
        .client
        .consolidate_proofs(&case.items, &ConsolidateOptions { cancel, ..opts() });
    assert_eq!(out, Err(ConsolidationError::Cancelled));
    assert!(run.shard("11").params.lock().unwrap().is_empty());
}

#[test]
fn configuration_is_validated() {
    let case = load("shards-4");
    let ep = |b: &str| {
        (
            shard(b),
            HttpAggregatorClient::new_insecure_http("http://127.0.0.1:1/"),
        )
    };
    let cfg = || ProofClientConfig {
        partition_id: case.partition,
        topology: case.topology.clone(),
    };
    let build = |eps: Vec<(ShardId, HttpAggregatorClient)>| {
        Client::with_host_defaults(cfg(), eps, case.trust_base.clone(), 2)
    };
    assert!(build(vec![ep("00"), ep("11")]).is_ok());
    assert!(
        build(vec![ep("00"), ep("00")]).is_err(),
        "duplicate endpoint"
    );
    assert!(
        build(vec![ep("0")]).is_err(),
        "endpoint shard outside the topology"
    );
    // a state of a shard without a configured endpoint is a configuration error, not a guess
    let client = build(vec![ep("00")]).unwrap();
    let out = client.consolidate_proofs(&case.items, &opts());
    assert!(
        matches!(out, Err(ConsolidationError::Configuration(_))),
        "{out:?}"
    );
    // nothing to consolidate
    assert!(matches!(
        client.consolidate_proofs(&[], &opts()),
        Err(ConsolidationError::Configuration(_))
    ));
}

#[test]
fn a_bad_master_path_is_an_integrity_error_before_any_peer_is_asked() {
    use unicity_token::api::InclusionCertificate;
    let case = load("shards-4");
    let master = case.master_reply.clone();
    let mut m = master.clone();
    let mut proofs = m["proofs"].as_array().unwrap().clone();
    proofs[0] = edit_proof(&proofs[0], |p| {
        let mut b = p.inclusion_certificate.encode();
        let last = b.len() - 1;
        b[last] ^= 1; // a sibling hash of the first master leaf
        p.inclusion_certificate = InclusionCertificate::decode(&b).unwrap();
    });
    m["proofs"] = Value::Array(proofs);
    let run = start(
        &case,
        move |_| Reply::Result(m.clone()),
        // the peer would report unavailability: it must never get the chance to hide the failure
        |_, _| rpc_error(-32008, "view_not_retained", true),
        Duration::ZERO,
        4,
        Arc::new(Gauge::default()),
    );
    let out = run.client.consolidate_proofs(&case.items, &opts());
    assert!(
        matches!(
            out,
            Err(ConsolidationError::Integrity(IntegrityError::Verification(
                _
            )))
        ),
        "{out:?}"
    );
    assert!(
        run.shard("11").params.lock().unwrap().is_empty(),
        "no peer request after a bad master proof"
    );

    // sanity: with an intact master the same peer failure is the typed unavailability
    let m = master.clone();
    let run = start(
        &case,
        move |_| Reply::Result(m.clone()),
        |_, _| rpc_error(-32008, "view_not_retained", true),
        Duration::ZERO,
        4,
        Arc::new(Gauge::default()),
    );
    assert!(matches!(
        run.client.consolidate_proofs(&case.items, &opts()),
        Ok(BundleOutcome::Unavailable { .. })
    ));
    assert_eq!(run.shard("11").params.lock().unwrap().len(), 1);
}

// ------------------------------------------------ proof status hint details --

fn hinted(detail: &str, retryable: bool, indexes: Value) -> Reply {
    Reply::Error(
        -32008,
        json!({"reason":"proof_unavailable","detail":detail,"retryable":retryable,"indexes":indexes}),
    )
}

/// `state_pending` is retryable unavailability; the other hints are non-retryable
/// unavailability with their own reasons: a routing or input problem, never "retry".
#[test]
fn status_hint_details_map_to_distinct_typed_outcomes() {
    use UnavailableReason::*;
    let cases = [
        ("state_pending", true, StatePending, true),
        ("state_expired", false, StateExpired, false),
        ("state_unknown", false, StateUnknown, false),
        ("state_not_in_root", false, StateNotInRoot, false),
    ];
    for (detail, server_retryable, reason, retryable) in cases {
        match run_with_master(hinted(detail, server_retryable, json!({"pending": [0]}))).unwrap() {
            BundleOutcome::Unavailable {
                reason: got,
                retryable: r,
            } => {
                assert_eq!(got, reason, "{detail}");
                assert_eq!(r, retryable, "{detail}");
            }
            other => panic!("{detail}: {other:?}"),
        }
    }
    // the server's retryable flag cannot make a non-retryable hint retryable
    match run_with_master(hinted("state_unknown", true, json!({"unknown": [1]}))).unwrap() {
        BundleOutcome::Unavailable { retryable, .. } => assert!(!retryable),
        other => panic!("{other:?}"),
    }
    // the older details keep their mapping
    assert!(matches!(
        run_with_master(rpc_error(-32008, "state_not_included", true)).unwrap(),
        BundleOutcome::Unavailable {
            reason: UnavailableReason::TargetNotYetAvailable,
            ..
        }
    ));
}

#[test]
fn a_peer_reports_a_leaf_missing_from_the_exact_root() {
    let case = load("shards-4");
    let master = case.master_reply.clone();
    let run = start(
        &case,
        move |_| Reply::Result(master.clone()),
        |_, _| hinted("state_not_in_root", false, json!({"not_in_root": [0, 2]})),
        Duration::ZERO,
        4,
        Arc::new(Gauge::default()),
    );
    match run.client.consolidate_proofs(&case.items, &opts()).unwrap() {
        BundleOutcome::Unavailable { reason, retryable } => {
            assert_eq!(reason, UnavailableReason::StateNotInRoot);
            assert!(!retryable);
        }
        other => panic!("{other:?}"),
    }
}

/// The transport keeps the offending request indexes per class, as the server
/// sends them (`{"pending":[1]}`, mixed: `{"unknown":[0],"pending":[2,3]}`,
/// exact root: `{"not_in_root":[...]}`).
#[test]
fn the_transport_exposes_the_offending_indexes_per_class() {
    use std::collections::BTreeMap;
    use unicity_token::client::{
        BatchAggregatorClient, BatchFailure, BatchRequest, RequestOptions, StateRoot, UNCLASSIFIED,
    };
    let case = load("shards-4");
    let ids: Vec<_> = case
        .items
        .iter()
        .take(4)
        .map(|i| i.state_id.clone())
        .collect();
    let fetch = |reply: Reply| {
        let shard = Shard::start(
            move |_| reply.clone(),
            Duration::ZERO,
            Arc::new(Gauge::default()),
        );
        HttpAggregatorClient::new_insecure_http(&shard.url)
            .get_inclusion_proofs(
                &BatchRequest {
                    state_ids: &ids,
                    state_root: StateRoot::Latest,
                },
                &RequestOptions { timeout_ms: 2_000 },
            )
            .unwrap_err()
    };
    let indexes = |reply: Reply| match fetch(reply) {
        BatchFailure::Rpc { indexes, .. } => indexes,
        other => panic!("{other:?}"),
    };
    let map = |entries: &[(&str, &[usize])]| -> BTreeMap<String, Vec<usize>> {
        entries
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_vec()))
            .collect()
    };

    // the server's golden shapes
    assert_eq!(
        indexes(hinted("state_pending", true, json!({"pending": [1]}))),
        map(&[("pending", &[1])])
    );
    assert_eq!(
        indexes(hinted(
            "state_not_in_root",
            false,
            json!({"not_in_root": [0, 2]})
        )),
        map(&[("not_in_root", &[0, 2])])
    );
    // a mixed outcome keeps every class (the detail carries the precedence winner)
    match fetch(hinted(
        "state_unknown",
        false,
        json!({"unknown": [0], "pending": [2, 3]}),
    )) {
        BatchFailure::Rpc {
            code,
            detail,
            retryable,
            indexes,
            ..
        } => {
            assert_eq!(code, -32008);
            assert_eq!(detail.as_deref(), Some("state_unknown"));
            assert_eq!(retryable, Some(false));
            assert_eq!(indexes, map(&[("unknown", &[0]), ("pending", &[2, 3])]));
        }
        other => panic!("{other:?}"),
    }
    // a bare array is tolerated as one unclassified entry
    assert_eq!(
        indexes(hinted("state_expired", false, json!([0, 3]))),
        map(&[(UNCLASSIFIED, &[0, 3])])
    );
    // absent, null, wrongly typed or non-numeric entries never fail the call
    assert!(indexes(rpc_error(-32008, "view_not_retained", true)).is_empty());
    assert!(indexes(hinted("state_pending", true, Value::Null)).is_empty());
    assert!(indexes(hinted("state_pending", true, json!("1,2"))).is_empty());
    assert_eq!(
        indexes(hinted(
            "state_pending",
            true,
            json!({"pending": [1, "x", -2, 3], "junk": 5})
        )),
        map(&[("pending", &[1, 3])])
    );
}

// ------------------------------------- the real server's status errors (#210) --

fn batch_fixture(name: &str) -> (i64, Value) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/uc-consolidation/proof-status/v1")
        .join(format!("batch-{name}.json"));
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    (
        v["error"]["code"].as_i64().unwrap(),
        v["error"]["data"].clone(),
    )
}

fn served_error(name: &str) -> Reply {
    let (code, data) = batch_fixture(name);
    Reply::Error(code, data)
}

/// Every status error of the real server maps to its typed outcome, and the mixed outcome
/// follows the server's precedence (unknown over expired over pending), while the
/// transport keeps every class of offending indexes.
#[test]
fn the_real_servers_status_errors_map_to_typed_outcomes() {
    use std::collections::BTreeMap;
    use unicity_token::client::{
        BatchAggregatorClient, BatchFailure, BatchRequest, RequestOptions, StateRoot,
    };
    use UnavailableReason::*;
    let case = load("shards-4");
    let ids: Vec<_> = case
        .items
        .iter()
        .take(4)
        .map(|i| i.state_id.clone())
        .collect();
    let classes = |m: &[(&str, &[usize])]| -> BTreeMap<String, Vec<usize>> {
        m.iter().map(|(k, v)| (k.to_string(), v.to_vec())).collect()
    };
    type Expect = (
        &'static str,
        UnavailableReason,
        bool,
        &'static str,
        BTreeMap<String, Vec<usize>>,
    );
    let expected: [Expect; 5] = [
        (
            "pending",
            StatePending,
            true,
            "state_pending",
            classes(&[("pending", &[1, 3])]),
        ),
        (
            "expired",
            StateExpired,
            false,
            "state_expired",
            classes(&[("expired", &[0])]),
        ),
        (
            "unknown",
            StateUnknown,
            false,
            "state_unknown",
            classes(&[("unknown", &[1])]),
        ),
        (
            "mixed",
            StateUnknown,
            false,
            "state_unknown",
            classes(&[("expired", &[2]), ("pending", &[0]), ("unknown", &[3])]),
        ),
        (
            "not-in-root",
            StateNotInRoot,
            false,
            "state_not_in_root",
            classes(&[("not_in_root", &[1, 3])]),
        ),
    ];
    for (name, reason, retryable, detail, indexes) in expected {
        // the typed transport error
        let shard = Shard::start(
            move |_| served_error(name),
            Duration::ZERO,
            Arc::new(Gauge::default()),
        );
        match HttpAggregatorClient::new_insecure_http(&shard.url)
            .get_inclusion_proofs(
                &BatchRequest {
                    state_ids: &ids,
                    state_root: StateRoot::Latest,
                },
                &RequestOptions { timeout_ms: 2_000 },
            )
            .unwrap_err()
        {
            BatchFailure::Rpc {
                code,
                detail: d,
                retryable: r,
                indexes: i,
                ..
            } => {
                assert_eq!(code, -32008, "{name}");
                assert_eq!(d.as_deref(), Some(detail), "{name}");
                assert_eq!(r, Some(retryable), "{name}");
                assert_eq!(i, indexes, "{name}");
            }
            other => panic!("{name}: {other:?}"),
        }
        // the consolidation outcome (as the master's answer)
        match run_with_master(served_error(name)).unwrap() {
            BundleOutcome::Unavailable {
                reason: got,
                retryable: got_retryable,
            } => {
                assert_eq!(got, reason, "{name}");
                assert_eq!(got_retryable, retryable, "{name}");
            }
            other => panic!("{name}: {other:?}"),
        }
    }
}
