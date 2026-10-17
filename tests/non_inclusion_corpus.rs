//! The shared non-inclusion corpus (aggregator-go `testdata/non-inclusion/v1`, vendored byte for
//! byte under `tests/vectors/non-inclusion/v1`, see its PROVENANCE.txt): every positive and
//! negative case through the Rust decoder and verifier, in the corpus' verdict vocabulary.
//!
//! Positives must match exactly; a negative must be a rejection equal to `expected.verdict` or one
//! of `expected.acceptable` (strict decoders may stop at an earlier stage), and must never be
//! `absent`/`state_included` unless the corpus says so.
#![cfg(feature = "std")]

use std::fs;
use std::path::PathBuf;

use serde_json::Value;
use sha2::{Digest, Sha256};
use unicity_token::api::bft::RootTrustBase;
use unicity_token::api::{NonInclusionCertificate, NonInclusionProof, StateId};
use unicity_token::cbor::{encode_array, encode_byte_string, encode_uint, Decoder};
use unicity_token::verify::{NonInclusionContext, VerificationError};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/non-inclusion/v1")
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

/// Decode the wire wrapper `[blockNumber, NonInclusionProof]` (as the HTTP client does).
fn decode_wrapper(wrapper: &[u8]) -> Result<(u64, NonInclusionProof), unicity_token::Error> {
    let d = Decoder::new(wrapper);
    d.finish()?;
    let items = d.array(Some(2))?;
    let block = items[0].uint()?;
    Ok((block, NonInclusionProof::from_cbor(items[1])?))
}

/// The verdict of this SDK for one case, in the corpus' vocabulary.
fn verdict_of(case: &Value, contexts: &Value) -> &'static str {
    let ctx = &contexts[case["context"].as_str().unwrap()];
    let wrapper = hex::decode(case["wrapper"].as_str().unwrap()).unwrap();
    let Ok((_, proof)) = decode_wrapper(&wrapper) else {
        return "malformed";
    };
    let Ok(proof) = proof.for_state(&state_id(case["query"].as_str().unwrap())) else {
        return "malformed";
    };
    let trust_base = RootTrustBase::from_json(
        std::str::from_utf8(&read(ctx["trustBaseJson"].as_str().unwrap())).unwrap(),
    )
    .unwrap();
    let mut context = NonInclusionContext::new(ctx["partition"].as_u64().unwrap() as u32);
    let min_round = num(&ctx["minRootRound"]);
    if min_round > 0 {
        context = context.with_min_root_round(min_round);
    }
    let end = num(&ctx["nextEpochStart"]);
    if end > 0 {
        context = context.with_authority_end_round(end);
    }
    let pin = ctx["shardConfHash"].as_str().unwrap();
    if !pin.is_empty() {
        context = context.with_shard_conf_hash(hex::decode(pin).unwrap().try_into().unwrap());
    }
    match proof.verify_in_context(&trust_base, &context) {
        Ok(()) => "absent",
        Err(VerificationError::StateIncluded) => "state_included",
        Err(VerificationError::NonInclusionCertificateInvalid) => "certificate_invalid",
        Err(VerificationError::SealTooOld) => "stale",
        Err(
            VerificationError::InvalidTrustBase(_)
            | VerificationError::UnsupportedAuthority
            | VerificationError::SealNetworkMismatch
            | VerificationError::SealEpochMismatch
            | VerificationError::SealBeforeEpochStart
            | VerificationError::SealAfterAuthorityEnd
            | VerificationError::SealMalformed
            | VerificationError::QuorumNotMet,
        ) => "authority_rejected",
        Err(
            VerificationError::PartitionMismatch
            | VerificationError::ShardPathInvalid
            | VerificationError::ConfigurationMismatch
            | VerificationError::SealRootMismatch
            | VerificationError::ShardMismatch,
        ) => "uc_invalid",
        Err(other) => panic!("{}: unmapped error {other:?}", case["name"]),
    }
}

#[test]
fn the_vendored_corpus_is_unchanged() {
    let manifest = json("manifest.json");
    let sums = manifest["sha256"].as_object().unwrap();
    assert!(sums.len() >= 75);
    for (path, want) in sums {
        let got = hex::encode(Sha256::digest(read(path)));
        assert_eq!(&got, want.as_str().unwrap(), "{path}");
    }
}

#[test]
fn positive_cases_have_the_exact_verdict_and_round_trip_their_bytes() {
    let contexts = json("contexts.json");
    let cases = files("cases");
    assert!(cases.len() >= 16, "{}", cases.len());
    let mut empty_tree = 0;
    for path in cases {
        let c = json(&path);
        let name = c["name"].as_str().unwrap();
        assert_eq!(
            verdict_of(&c, &contexts),
            c["expected"]["verdict"].as_str().unwrap(),
            "{name}"
        );
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
            empty_tree += 1;
            assert!(
                cert.is_empty(),
                "{name}: the empty tree has the empty certificate"
            );
            // the native empty-tree identity: the UC carries a null hash
            assert!(
                proof.unicity_certificate().input_record.hash.is_none(),
                "{name}"
            );
        } else {
            assert!(
                proof
                    .unicity_certificate()
                    .input_record
                    .hash
                    .as_ref()
                    .is_some_and(|h| h.len() == 32),
                "{name}"
            );
        }
        let decoded = NonInclusionCertificate::decode(&cert).unwrap();
        assert_eq!(decoded.encode(), cert, "{name}: certificate re-encodes");
    }
    assert!(empty_tree >= 1, "the corpus exercises the empty tree");
}

#[test]
fn negative_cases_never_loosen_a_decoder_to_reach_a_later_class() {
    let contexts = json("contexts.json");
    let cases = files("negative");
    assert!(cases.len() >= 40, "{}", cases.len());
    let mut mismatches = Vec::new();
    for path in cases {
        let c = json(&path);
        let name = c["name"].as_str().unwrap();
        let got = verdict_of(&c, &contexts);
        let want = c["expected"]["verdict"].as_str().unwrap();
        if want == "absent" || want == "state_included" {
            assert_eq!(got, want, "{name}");
        } else {
            assert!(got != "absent" && got != "state_included", "{name}: {got}");
            let mut ok = vec![want.to_string()];
            ok.extend(
                c["expected"]["acceptable"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|v| v.as_str().unwrap().to_string()),
            );
            if !ok.iter().any(|o| o == got) {
                mismatches.push(format!("{name}: {got} not in {ok:?}"));
            }
        }
    }
    assert!(mismatches.is_empty(), "{mismatches:#?}");
}

#[test]
fn the_empty_byte_string_root_is_rejected_not_aliased() {
    // the corpus vector for `hash = h''` (40) in place of the native null
    let contexts = json("contexts.json");
    let c = json("negative/uc-empty-root-as-empty-byte-string.json");
    let got = verdict_of(&c, &contexts);
    assert_ne!(got, "absent");
    assert!(
        ["uc_invalid", "malformed", "certificate_invalid"].contains(&got),
        "{got}"
    );
}
