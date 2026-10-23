//! Consumer of the negative cases of the shared Go fixture corpus
//! `testdata/uc-consolidation/v1` (see `PROVENANCE.txt`).
//!
//! Every directory under `negative/` is enumerated with `read_dir`, overlaid on
//! its base case exactly as the reference does (`changedFiles` replace,
//! `removedFiles` delete) and run through the real consolidation path: the
//! HTTP batch adapter against a scripted loopback server that serves the case's
//! `responses.json`, then [`ProofClient::consolidate_proofs`] over the case's
//! original evidence (`requests.json`) under its trusted context and trust base.
//! The result is classified into the reference's outcome vocabulary and must
//! equal the case's `expected.json`.
//!
//! A case the SDK maps differently on purpose is listed in [`ALLOW_LIST`] with
//! its reason and the outcome the SDK produces instead; a vendored case that is
//! neither equal nor listed fails, as does an allow-list entry that no longer
//! applies.
#![cfg(feature = "http")]

mod trust_support;

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};

use serde_json::Value;
use unicity_token::api::bft::ShardId;
use unicity_token::api::{InclusionProofResponse, StateId};
use unicity_token::cbor::Decoder;
use unicity_token::client::{
    BatchFailure, BundleOutcome, ConsolidateOptions, ConsolidationError, HttpAggregatorClient,
    IntegrityError, ProofClient, ProofClientConfig, ProofItem, UnavailableReason,
};
use unicity_token::consolidation::{PartitionTopology, PartitionViewError};
use unicity_token::verify::VerificationError;

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/uc-consolidation/corpus-v1")
}

/// A case's files by relative path.
type Files = BTreeMap<String, Vec<u8>>;

fn read_tree(dir: &Path) -> Files {
    fn walk(root: &Path, dir: &Path, out: &mut Files) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(root, &path, out);
            } else {
                let rel = path.strip_prefix(root).unwrap();
                out.insert(rel.to_str().unwrap().to_string(), fs::read(&path).unwrap());
            }
        }
    }
    let mut out = Files::new();
    walk(dir, dir, &mut out);
    out
}

fn json(files: &Files, name: &str) -> Value {
    serde_json::from_slice(files.get(name).unwrap_or_else(|| panic!("{name} missing"))).unwrap()
}

fn shard(bits: &str) -> ShardId {
    let mut id = ShardId::root();
    for c in bits.chars() {
        let (zero, one) = id.split();
        id = if c == '0' { zero } else { one };
    }
    id
}

// ---------------------------------------------------------------- scripted server

/// Serve `body` (a complete JSON-RPC response) for every request, echoing the
/// request's id. Returns the endpoint URL.
fn serve(body: Value) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "http://127.0.0.1:{}/",
        listener.local_addr().unwrap().port()
    );
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let Some(request) = read_request(&mut stream) else {
                continue;
            };
            let request: Value = serde_json::from_str(&request).unwrap();
            let mut reply = body.clone();
            reply["id"] = request["id"].clone();
            let reply = reply.to_string();
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                reply.len()
            );
        }
    });
    url
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

// ---------------------------------------------------------------- running a case

/// What the SDK did with a case.
#[derive(Debug)]
enum Got {
    /// Refused while decoding the original evidence, before any request.
    Input,
    /// The client could not be configured with the trusted context.
    Config,
    /// The real path ran to this result.
    Ran(Box<Result<BundleOutcome, ConsolidationError>>),
}

fn run(files: &Files) -> Got {
    let context = json(files, "context.json");
    let requests = json(files, "requests.json");
    let responses = json(files, "responses.json");

    // the trusted topology: the shard scheme and the admitted configuration hashes
    let shards: Vec<String> = context["shards"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_string())
        .collect();
    let ids: Vec<ShardId> = shards.iter().map(|s| shard(s)).collect();
    let mut topology = PartitionTopology::new(if ids.len() == 1 { vec![] } else { ids.clone() });
    for (id, cfg) in ids.iter().zip(context["shardConfigs"].as_array().unwrap()) {
        let hash: [u8; 32] = hex::decode(cfg["hash"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        topology = topology.with_shard_conf_hash(id, hash);
    }

    // the original evidence
    let mut items = Vec::new();
    for e in requests["evidence"].as_array().into_iter().flatten() {
        let item = (|| {
            let request = hex::decode(e["request"].as_str().ok_or("request")?)
                .map_err(|e| format!("request hex: {e}"))?;
            let fields = Decoder::new(&request)
                .expect_tag(39030)
                .and_then(|d| d.array(Some(4)))
                .map_err(|e| format!("request: {e}"))?;
            let state_id = StateId::from_cbor(fields[1]).map_err(|e| format!("state id: {e}"))?;
            let proof = hex::decode(e["proof"].as_str().ok_or("proof")?)
                .map_err(|e| format!("proof hex: {e}"))?;
            match InclusionProofResponse::from_cbor(Decoder::new(&proof)) {
                Ok(InclusionProofResponse::Certified { proof, .. }) => {
                    Ok(ProofItem { state_id, proof })
                }
                Ok(_) => Err("evidence is not a certified proof".to_string()),
                Err(e) => Err(format!("proof: {e}")),
            }
        })();
        match item {
            Ok(item) => items.push(item),
            Err(_) => return Got::Input,
        }
    }

    // one scripted server per participating shard, at the shard's endpoint
    let mut endpoints = vec![(
        shard(requests["master"]["shard"].as_str().unwrap()),
        HttpAggregatorClient::new_insecure_http(serve(responses["master"].clone())),
    )];
    for peer in responses["peers"].as_array().into_iter().flatten() {
        endpoints.push((
            shard(peer["shard"].as_str().unwrap()),
            HttpAggregatorClient::new_insecure_http(serve(peer["response"].clone())),
        ));
    }

    let client = match ProofClient::with_host_defaults(
        ProofClientConfig { topology },
        endpoints,
        trust_support::history_from_corpus_trust_base(&files["trust-base.cbor"]),
        4,
    ) {
        Ok(client) => client,
        Err(_) => return Got::Config,
    };
    // the corpus names the master shard (its latest batch carries the view)
    let options = ConsolidateOptions {
        timeout_ms: 5_000,
        master: Some(shard(requests["master"]["shard"].as_str().unwrap())),
        ..Default::default()
    };
    Got::Ran(Box::new(client.consolidate_proofs(&items, &options)))
}

// ---------------------------------------------------------------- classification

/// The reference's outcome class of a verification failure of a *seal*.
fn seal_class(e: &VerificationError) -> String {
    use VerificationError::*;
    match e {
        // the fork's trust base history: an unknown signer or an epoch outside the history
        // is refused by name, not as a missed quorum
        QuorumNotMet
        | SealNetworkMismatch
        // the fork's native seal rule refuses a seal carrying any unknown or invalid signature
        // (the other-authority case) instead of counting the valid ones towards a quorum
        | SealSignerInvalid
        | EpochBeforeGenesis
        | UnknownTrustEpoch { .. }
        | SealAfterAuthorityEnd
        | SealBeforeEpochStart => "unauthenticated".into(),
        SealMalformed => "invalid_input".into(),
        other => format!("unmapped seal failure {other:?}"),
    }
}

/// The reference's outcome class of a failure to authenticate the original evidence.
fn evidence_class(e: &VerificationError) -> String {
    use VerificationError::*;
    match e {
        RequestExpired => "expired".into(),
        ReferenceTimeAfterRound => "reference_time_after_target".into(),
        PathInvalid | ReferenceTimeMismatch | CertificationDataMismatch => {
            "binding_mismatch".into()
        }
        other => seal_class(other),
    }
}

fn view_class(e: &PartitionViewError) -> String {
    use PartitionViewError::*;
    match e {
        Seal(e) => seal_class(e),
        // a view or enclosing certificate that is malformed, inconsistent with itself or
        // with the trusted scheme
        Decode(_)
        | TooLarge { .. }
        | UnsupportedVersion(_)
        | NotCanonical
        | Bounds(_)
        | InvalidTopology(_)
        | PartitionMismatch
        | LeafSetMismatch(_)
        | ConfigHashMismatch
        | ConfigHashRequired
        | TreeRootMismatch
        | EnclosingCertificate(_) => "invalid_input".into(),
        other => format!("unmapped view failure {other:?}"),
    }
}

fn rpc_class(failure: &BatchFailure) -> String {
    match failure {
        BatchFailure::Rpc { code: -32602, .. } => "invalid_request".into(),
        BatchFailure::Rpc { code: -32007, .. } => "limit_exceeded".into(),
        other => format!("unmapped rpc failure {other:?}"),
    }
}

/// The reference's outcome class of what the SDK did.
fn classify(got: &Got) -> String {
    let Got::Ran(result) = got else {
        // undecodable evidence, or a trusted context that does not configure a client
        return "invalid_input".into();
    };
    match result.as_ref() {
        Ok(BundleOutcome::Consolidated(_)) => "consolidated".into(),
        Ok(BundleOutcome::Unavailable { reason, .. }) => match reason {
            UnavailableReason::Busy => "busy",
            UnavailableReason::UnsupportedCapability => "unsupported_method",
            UnavailableReason::UnsupportedConfiguration => "unsupported",
            UnavailableReason::TargetNotRetained
            | UnavailableReason::TargetNotYetAvailable
            | UnavailableReason::PartitionViewUnavailable
            | UnavailableReason::StatePending
            | UnavailableReason::StateExpired
            | UnavailableReason::StateUnknown
            | UnavailableReason::StateNotInRoot => "unavailable",
            _ => "unmapped unavailable reason",
        }
        .into(),
        Err(ConsolidationError::Server { .. }) => "infrastructure".into(),
        Err(ConsolidationError::Rejected { failure, .. }) => rpc_class(failure),
        // a response that does not decode or does not answer the request
        Err(ConsolidationError::InvalidResponse { .. }) => "invalid_input".into(),
        Err(ConsolidationError::Integrity(e)) => match e {
            IntegrityError::View(e) => view_class(e),
            IntegrityError::Evidence(e) => evidence_class(e),
            IntegrityError::Binding { .. } | IntegrityError::RootSubstitution { .. } => {
                "binding_mismatch".into()
            }
            IntegrityError::Context { .. } => "incompatible_lineage".into(),
            IntegrityError::Verification(VerificationError::PathInvalid) => {
                "binding_mismatch".into()
            }
            other => format!("unmapped integrity failure {other:?}"),
        },
        // an input the client refuses to act on
        Err(ConsolidationError::Configuration(_)) => "invalid_input".into(),
        Err(other) => format!("unmapped failure {other:?}"),
    }
}

/// For an `rpc` case: the wire facts the failed call must have surfaced.
fn check_rpc(name: &str, rpc: &Value, got: &Got) {
    let Got::Ran(result) = got else {
        panic!("{name}: the call must have been made")
    };
    let code = rpc["code"].as_i64().unwrap();
    let retryable = rpc["retryable"].as_bool().unwrap();
    match result.as_ref() {
        Ok(BundleOutcome::Unavailable { retryable: r, .. }) => {
            assert_eq!(*r, retryable, "{name}: retryability comes from the wire");
        }
        Err(ConsolidationError::Server { failure, .. })
        | Err(ConsolidationError::Rejected { failure, .. }) => {
            let BatchFailure::Rpc {
                code: c,
                detail,
                retryable: r,
                ..
            } = failure
            else {
                panic!("{name}: a JSON-RPC failure, got {failure:?}")
            };
            assert_eq!(*c, code, "{name}: the original code is kept");
            if let Some(want) = rpc.get("detail").and_then(Value::as_str) {
                assert_eq!(detail.as_deref(), Some(want), "{name}: detail");
            }
            if let Some(r) = r {
                assert_eq!(*r, retryable, "{name}: retryability comes from the wire");
            }
        }
        other => panic!("{name}: not a typed rpc outcome: {other:?}"),
    }
}

/// Cases the SDK maps differently on purpose: the case, why, and the class the
/// SDK produces instead. Each entry is verified to still differ from the
/// reference and to produce exactly this class.
const ALLOW_LIST: &[(&str, &str, &str)] = &[
    (
        "context-network-mismatch",
        "the SDK's trusted context has no declared network: the network is the trust \
         base's, so there is no assertion to contradict it (a foreign network is refused \
         through the seals: trust-base-other-network)",
        "consolidated",
    ),
    (
        "context-wrong-partition",
        "the aggregation partition is an SDK constant, not a context field; the \
         partition of the evidence and of the view is enforced instead \
         (validly-signed-other-partition, view-wrong-partition)",
        "consolidated",
    ),
    (
        "evidence-duplicate",
        "duplicate inputs are accepted by design: states are deduplicated and every \
         input receives the replacement of its first occurrence",
        "consolidated",
    ),
    (
        "evidence-missing-for-request",
        "the SDK derives the batch request from the evidence, so a request without \
         evidence cannot be expressed; the shorter request no longer matches the \
         recorded response, which is refused as an invalid response",
        "invalid_input",
    ),
    (
        "request-differs-from-evidence",
        "the SDK takes no request apart from the evidence (the request is derived from \
         the authenticated original), so the two cannot disagree",
        "consolidated",
    ),
    (
        "request-wrong-state-id",
        "the SDK takes no request apart from the evidence (the request is derived from \
         the authenticated original), so the two cannot disagree",
        "consolidated",
    ),
    (
        "rmin-master-stale",
        "a latest seal older than the evidence is publication lag, not forgery: \
         Unavailable(TargetNotYetAvailable), retryable",
        "unavailable",
    ),
    (
        "rmin-unknown",
        "the bound can only come from authenticated evidence and the SDK has no input \
         without it: an empty input is a caller error before any request",
        "invalid_input",
    ),
    (
        "proof-reference-time-after-target",
        "the replacement's binding to the original (equal reference time) is checked \
         before its relation to the target, so the refusal is a binding mismatch",
        "binding_mismatch",
    ),
];

#[test]
fn negative_cases_produce_their_expected_outcome() {
    let root = corpus_root();
    let mut names: Vec<String> = fs::read_dir(root.join("negative"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();

    // the directory listing is the case list: it must be the manifest's, so a newly
    // vendored case is handled below or fails
    let manifest: Value =
        serde_json::from_slice(&fs::read(root.join("manifest.json")).unwrap()).unwrap();
    let mut listed: Vec<(String, String)> = manifest["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["kind"] == "negative")
        .map(|c| {
            (
                c["name"]
                    .as_str()
                    .unwrap()
                    .strip_prefix("negative/")
                    .unwrap()
                    .to_string(),
                c["outcome"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    listed.sort();
    assert_eq!(
        names,
        listed.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>(),
        "the vendored directories are the manifest's negative cases"
    );
    for (name, _) in ALLOW_LIST.iter().map(|(n, _, _)| (n, ())) {
        assert!(names.contains(&name.to_string()), "{name}: no such case");
    }

    let mut bases: BTreeMap<String, Files> = BTreeMap::new();
    let mut per_class: BTreeMap<String, usize> = BTreeMap::new();
    let mut failures = Vec::new();
    for name in &names {
        let neg = read_tree(&root.join("negative").join(name));
        let expected: Value = serde_json::from_slice(&neg["expected.json"]).unwrap();
        assert_eq!(
            expected["outcome"],
            listed.iter().find(|(n, _)| n == name).unwrap().1,
            "{name}: expected.json agrees with the manifest"
        );
        let base = expected["base"].as_str().unwrap().to_string();
        let mut files = bases
            .entry(base.clone())
            .or_insert_with(|| read_tree(&root.join(&base)))
            .clone();
        for f in expected["changedFiles"].as_array().unwrap() {
            let f = f.as_str().unwrap();
            files.insert(f.to_string(), neg[f].clone());
        }
        for f in expected["removedFiles"].as_array().into_iter().flatten() {
            files.remove(f.as_str().unwrap());
        }

        // a view the codec refuses has the pipeline's class (`pipelineOutcome`)
        let want = expected
            .get("pipelineOutcome")
            .unwrap_or(&expected["outcome"])
            .as_str()
            .unwrap()
            .to_string();
        let got = run(&files);
        let class = classify(&got);
        match ALLOW_LIST.iter().find(|(n, _, _)| n == name) {
            Some((_, _, rust)) => {
                if class != *rust || class == want {
                    failures.push(format!(
                        "{name}: allow-listed as {rust} (reference {want}), got {class}: {got:?}"
                    ));
                }
            }
            None => {
                if class != want {
                    failures.push(format!("{name}: expected {want}, got {class}: {got:?}"));
                }
            }
        }
        if expected["stage"] == "rpc" {
            check_rpc(name, &expected["rpc"], &got);
        }
        *per_class.entry(want).or_default() += 1;
    }
    println!(
        "{} negative cases; per reference class: {per_class:?}",
        names.len()
    );
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}
