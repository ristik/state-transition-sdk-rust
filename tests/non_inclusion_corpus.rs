//! The shared non-inclusion corpus (aggregator-go `testdata/non-inclusion/v2`, vendored byte for
//! byte under `tests/vectors/non-inclusion/v2`, see its PROVENANCE.txt): every positive and
//! negative case through the Rust decoder and verifier, in the corpus' outcome vocabulary.
//!
//! Outcomes `absent_at_snapshot` / `included_at_snapshot` must match exactly, including the
//! queried state id and every snapshot field. A rejection is an `Err` (which by construction
//! carries no snapshot) whose class equals `expected.rejection` or one of `expected.acceptable`
//! (strict decoders may stop at an earlier stage); it must never be a success.
#![cfg(feature = "std")]

use std::fs;
use std::path::PathBuf;

use serde_json::Value;
use sha2::{Digest, Sha256};
use unicity_token::api::bft::{RootTrustBase, ShardId};
use unicity_token::api::{NonInclusionCertificate, NonInclusionProof, StateId};
use unicity_token::cbor::{encode_array, encode_byte_string, encode_uint, Decoder};
use unicity_token::verify::{
    verify_non_inclusion_in, NonInclusionContext, NonInclusionOutcome, NonInclusionSnapshot,
    SealSession, VerificationError,
};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/non-inclusion/v2")
}

fn read(path: &str) -> Vec<u8> {
    fs::read(root().join(path)).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn json(path: &str) -> Value {
    serde_json::from_slice(&read(path)).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn files(dir: &str) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(root().join(dir))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|f| f.ends_with(".json"))
        .map(|f| format!("{dir}/{f}"))
        .collect();
    v.sort();
    v
}

fn state_id(hex_str: &str) -> StateId {
    let bytes = hex::decode(hex_str).unwrap();
    StateId::from_cbor(Decoder::new(&encode_byte_string(&bytes))).unwrap()
}

fn num(v: &Value) -> u64 {
    v.as_str().unwrap().parse().unwrap()
}

fn shard_from_bits(bits: &str) -> ShardId {
    let mut id = ShardId::root();
    for c in bits.chars() {
        let (zero, one) = id.split();
        id = if c == '0' { zero } else { one };
    }
    id
}

fn bits_of(id: &ShardId) -> String {
    (0..id.length())
        .map(|i| {
            if id.get_bit(i).unwrap() == 1 {
                '1'
            } else {
                '0'
            }
        })
        .collect()
}

/// Decode the wire wrapper `[blockNumber, NonInclusionProof]` (as the HTTP client does).
fn decode_wrapper(wrapper: &[u8]) -> Result<(u64, NonInclusionProof), unicity_token::Error> {
    let d = Decoder::new(wrapper);
    d.finish()?;
    let items = d.array(Some(2))?;
    let block = items[0].uint()?;
    Ok((block, NonInclusionProof::from_cbor(items[1])?))
}

/// What this SDK concludes for one vector: an outcome or a rejection class.
#[derive(Debug, PartialEq)]
enum Verdict {
    Outcome(NonInclusionOutcome),
    Rejected(&'static str),
}

fn trust_base(ctx: &Value) -> RootTrustBase {
    RootTrustBase::from_json(
        std::str::from_utf8(&read(ctx["trustBaseJson"].as_str().unwrap())).unwrap(),
    )
    .unwrap()
}

fn context_of(ctx: &Value) -> NonInclusionContext {
    // the corpus context always names the shard the verifier serves ("" = the unsharded partition)
    let mut context =
        NonInclusionContext::new().with_shard(shard_from_bits(ctx["shard"].as_str().unwrap()));
    let end = num(&ctx["nextEpochStart"]);
    if end > 0 {
        context = context.with_authority_end_round(end);
    }
    let pin = ctx["shardConfHash"].as_str().unwrap();
    if !pin.is_empty() {
        context = context.with_shard_conf_hash(hex::decode(pin).unwrap().try_into().unwrap());
    }
    context
}

fn class_of(error: &VerificationError, name: &str) -> &'static str {
    match error {
        VerificationError::NonInclusionCertificateInvalid | VerificationError::ShardMismatch => {
            "certificate_invalid"
        }
        VerificationError::InvalidTrustBase(_)
        | VerificationError::UnsupportedAuthority
        | VerificationError::SealNetworkMismatch
        | VerificationError::SealEpochMismatch
        | VerificationError::SealBeforeEpochStart
        | VerificationError::SealAfterAuthorityEnd
        | VerificationError::SealMalformed
        | VerificationError::QuorumNotMet => "authority_rejected",
        VerificationError::PartitionMismatch
        | VerificationError::ShardPathInvalid
        | VerificationError::ConfigurationMismatch
        | VerificationError::CertificateBodyInvalid
        | VerificationError::SealRootMismatch => "uc_invalid",
        other => panic!("{name}: unmapped error {other:?}"),
    }
}

/// The verdict of this SDK for the wrapper/query of `case` under `context` in `session`.
fn verdict_in(
    session: &mut SealSession<'_>,
    case: &Value,
    context: &NonInclusionContext,
) -> Verdict {
    let wrapper = hex::decode(case["wrapper"].as_str().unwrap()).unwrap();
    let Ok((_, proof)) = decode_wrapper(&wrapper) else {
        return Verdict::Rejected("malformed");
    };
    let target = state_id(case["query"].as_str().unwrap());
    let Ok(proof) = proof.for_state(&target) else {
        return Verdict::Rejected("malformed");
    };
    match verify_non_inclusion_in(session, &proof, &target, context) {
        Ok(outcome) => Verdict::Outcome(outcome),
        Err(e) => Verdict::Rejected(class_of(&e, case["name"].as_str().unwrap_or("?"))),
    }
}

fn verdict_of(case: &Value, contexts: &Value) -> Verdict {
    let ctx = &contexts[case["context"].as_str().unwrap()];
    let tb = trust_base(ctx);
    let mut session = SealSession::new(&tb);
    verdict_in(&mut session, case, &context_of(ctx))
}

/// Compare a success with the corpus' expected outcome (every snapshot field, exactly).
fn assert_outcome(name: &str, got: &NonInclusionOutcome, want: &Value) {
    let (kind, state_id, snapshot): (&str, _, _) = match got {
        NonInclusionOutcome::AbsentAtSnapshot { state_id, snapshot } => {
            ("absent_at_snapshot", state_id, snapshot)
        }
        NonInclusionOutcome::IncludedAtSnapshot { state_id, snapshot } => {
            ("included_at_snapshot", state_id, snapshot)
        }
    };
    assert_eq!(kind, want["outcome"].as_str().unwrap(), "{name}: outcome");
    assert_eq!(
        hex::encode(state_id.bytes()),
        want["stateId"].as_str().unwrap(),
        "{name}: stateId"
    );
    assert_snapshot(name, snapshot, &want["snapshot"]);
}

fn assert_snapshot(name: &str, got: &NonInclusionSnapshot, want: &Value) {
    assert_eq!(
        u64::from(got.network_id().id()),
        want["networkId"].as_u64().unwrap(),
        "{name}: networkId"
    );
    assert_eq!(
        u64::from(got.partition_id()),
        want["partitionId"].as_u64().unwrap(),
        "{name}: partitionId"
    );
    assert_eq!(
        bits_of(got.shard_id()),
        want["shardId"].as_str().unwrap(),
        "{name}: shardId"
    );
    assert_eq!(
        got.root_round(),
        num(&want["rootRound"]),
        "{name}: rootRound"
    );
    assert_eq!(
        got.seal_timestamp_seconds(),
        num(&want["sealTimestampSeconds"]),
        "{name}: sealTimestampSeconds"
    );
    assert_eq!(
        got.root_epoch(),
        num(&want["rootEpoch"]),
        "{name}: rootEpoch"
    );
    assert_eq!(
        got.shard_round(),
        num(&want["shardRound"]),
        "{name}: shardRound"
    );
    assert_eq!(
        got.shard_epoch(),
        num(&want["shardEpoch"]),
        "{name}: shardEpoch"
    );
    assert_eq!(
        got.state_root().map(hex::encode),
        want["stateRoot"].as_str().map(str::to_string),
        "{name}: stateRoot (null is the certified empty tree)"
    );
}

/// Check `got` against `expected` of a case, sequence step or negative.
fn check(name: &str, got: &Verdict, expected: &Value) {
    match expected["outcome"].as_str().unwrap() {
        "rejected" => {
            let Verdict::Rejected(class) = got else {
                panic!("{name}: expected a rejection, got {got:?}");
            };
            let mut ok = vec![expected["rejection"].as_str().unwrap().to_string()];
            ok.extend(
                expected["acceptable"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|v| v.as_str().unwrap().to_string()),
            );
            // a strict decoder legitimately stops at the earliest stage (`malformed`); it is never
            // loosened to reach a later class
            assert!(
                ok.iter().any(|o| o == class) || *class == "malformed",
                "{name}: {class} not in {ok:?}"
            );
        }
        _ => match got {
            Verdict::Outcome(outcome) => assert_outcome(name, outcome, expected),
            Verdict::Rejected(class) => panic!("{name}: expected a success, got {class}"),
        },
    }
}

#[test]
fn the_vendored_corpus_is_unchanged() {
    let manifest = json("manifest.json");
    let sums = manifest["sha256"].as_object().unwrap();
    assert!(sums.len() >= 100);
    assert_eq!(manifest["version"], 2);
    for (path, want) in sums {
        let got = hex::encode(Sha256::digest(read(path)));
        assert_eq!(&got, want.as_str().unwrap(), "{path}");
    }
}

#[test]
fn positive_cases_have_the_exact_outcome_and_round_trip_their_bytes() {
    let contexts = json("contexts.json");
    let cases = files("cases");
    assert!(cases.len() >= 25, "{}", cases.len());
    let (mut empty_tree, mut sharded, mut included, mut absent) = (0, 0, 0, 0);
    for path in cases {
        let c = json(&path);
        let name = c["name"].as_str().unwrap();
        let verdict = verdict_of(&c, &contexts);
        check(name, &verdict, &c["expected"]);
        if let Verdict::Outcome(o) = &verdict {
            if o.is_absent() {
                absent += 1;
            } else {
                included += 1;
            }
            sharded += usize::from(o.snapshot().shard_id().length() > 0);
            empty_tree += usize::from(o.snapshot().state_root().is_none());
        }
        // the codecs reproduce the producers' bytes
        let wrapper = hex::decode(c["wrapper"].as_str().unwrap()).unwrap();
        let (block, proof) = decode_wrapper(&wrapper).unwrap();
        assert_eq!(
            encode_array(&[encode_uint(block).as_slice(), proof.to_cbor().as_slice()]),
            wrapper,
            "{name}: wrapper re-encodes"
        );
        let cert = hex::decode(c["certificate"].as_str().unwrap()).unwrap();
        if c["root"].as_str().unwrap().is_empty() {
            assert!(
                cert.is_empty(),
                "{name}: the empty tree has the empty certificate"
            );
            // the native empty-tree identity: the UC carries a null hash
            assert!(
                proof.unicity_certificate().input_record.hash.is_none(),
                "{name}"
            );
        }
        if !cert.is_empty() || c["root"].as_str().unwrap().is_empty() {
            let decoded = NonInclusionCertificate::decode(&cert).unwrap();
            assert_eq!(decoded.encode(), cert, "{name}: certificate re-encodes");
        }
    }
    assert!(empty_tree >= 2, "unsharded and sharded empty trees");
    assert!(sharded >= 6 && included >= 4 && absent >= 15);
}

#[test]
fn negative_cases_never_loosen_a_decoder_to_reach_a_later_class() {
    let contexts = json("contexts.json");
    let cases = files("negative");
    assert!(cases.len() >= 50, "{}", cases.len());
    for path in cases {
        let c = json(&path);
        let name = c["name"].as_str().unwrap();
        check(name, &verdict_of(&c, &contexts), &c["expected"]);
    }
}

#[test]
fn a_rejection_carries_no_snapshot_and_validly_signed_foreign_partitions_are_rejected() {
    let contexts = json("contexts.json");
    for name in [
        "negative/uc-wrong-partition-validly-signed",
        "negative/uc-wrong-partition-sharded-validly-signed",
    ] {
        let c = json(&format!("{name}.json"));
        // the UC is authentic (the trusted authority signed it): only the partition rule fires
        assert_eq!(
            verdict_of(&c, &contexts),
            Verdict::Rejected("uc_invalid"),
            "{name}"
        );
        let ctx = &contexts[c["context"].as_str().unwrap()];
        let tb = trust_base(ctx);
        let wrapper = hex::decode(c["wrapper"].as_str().unwrap()).unwrap();
        let (_, proof) = decode_wrapper(&wrapper).unwrap();
        let target = state_id(c["query"].as_str().unwrap());
        assert_eq!(
            proof.verify_for_at_snapshot(&target, &tb, &context_of(ctx)),
            Err(VerificationError::PartitionMismatch),
            "{name}"
        );
    }
}

#[test]
fn the_empty_byte_string_root_is_rejected_not_aliased() {
    let contexts = json("contexts.json");
    let c = json("negative/uc-empty-root-as-empty-byte-string.json");
    let Verdict::Rejected(class) = verdict_of(&c, &contexts) else {
        panic!("accepted")
    };
    assert!(
        ["uc_invalid", "malformed", "certificate_invalid"].contains(&class),
        "{class}"
    );
}

#[test]
fn sequences_on_one_verifier_keep_each_step_exact() {
    let contexts = json("contexts.json");
    let sequences = json("sequences.json");
    for seq in sequences["sequences"].as_array().unwrap() {
        let sname = seq["name"].as_str().unwrap();
        let ctx = &contexts[seq["context"].as_str().unwrap()];
        let tb = trust_base(ctx);
        let context = context_of(ctx);
        // ONE verifier (one seal session, which memoizes authenticated seals) for all steps
        let mut session = SealSession::new(&tb);
        for (i, step) in seq["steps"].as_array().unwrap().iter().enumerate() {
            let case = json(&format!("{}.json", step["vector"].as_str().unwrap()));
            let verdict = verdict_in(&mut session, &case, &context);
            check(&format!("{sname}[{i}]"), &verdict, &step["expected"]);
        }
    }
}

/// The caller's policy, applied after verification to the authenticated snapshot against a
/// checkpoint obtained independently of the proof (corpus `policy.json`).
fn meets_policy(snapshot: &NonInclusionSnapshot, checkpoint: &Value) -> bool {
    snapshot.network_id().id() as u64 == checkpoint["networkId"].as_u64().unwrap()
        && snapshot.root_round() >= num(&checkpoint["requiredRootRound"])
        && checkpoint
            .get("minSealTimestampSeconds")
            .map_or(true, |t| snapshot.seal_timestamp_seconds() >= num(t))
}

#[test]
fn caller_policy_is_decided_on_the_verified_snapshot() {
    let contexts = json("contexts.json");
    let policy = json("policy.json");
    for ex in policy["examples"].as_array().unwrap() {
        let name = ex["name"].as_str().unwrap();
        let case = json(&format!("{}.json", ex["vector"].as_str().unwrap()));
        let Verdict::Outcome(outcome) = verdict_of(&case, &contexts) else {
            panic!("{name}: the vector must verify")
        };
        assert_snapshot(name, outcome.snapshot(), &ex["snapshot"]);
        let accept = meets_policy(outcome.snapshot(), &ex["checkpoint"]);
        assert_eq!(
            if accept { "accept" } else { "reject" },
            ex["decision"].as_str().unwrap(),
            "{name}"
        );
    }
}
