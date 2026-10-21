//! End-to-end cross-SDK verification test.
//!
//! `tests/vectors/transition_flow.json` is produced by the reference
//! TypeScript SDK (`tests/functional/TestAggregatorClient.ts` +
//! `tests/utils/TokenUtils.ts`): a token minted to Alice and transferred
//! Alice -> Bob -> Carol through an in-memory aggregator, with the JS SDK
//! asserting `verify == OK` after every step before export. This test
//! confirms the Rust SDK decodes those exact bytes, round-trips them
//! byte-for-byte, and reaches the same verification decisions (RSMT v6a,
//! big-endian bit order).
//!
//! The Alice/Bob/Carol tokens leave the request deadline to the service, so
//! their `expiresAt` is CBOR null and no client clock is involved.
//! `explicitTimeoutToken` carries a sender-chosen deadline. Both are the same
//! wire version with the same element count, so one vector covers the encoding
//! with and without a value in that slot.

use unicity_token::api::bft::root_trust_base::RootTrustBaseNodeInfo;
use unicity_token::api::bft::RootTrustBase;
use unicity_token::api::{CertificationData, InclusionProofResponse, NetworkId};
use unicity_token::cbor::Decoder;
use unicity_token::crypto::hash::sha256;
use unicity_token::crypto::signature::PublicKey;
use unicity_token::transaction::{CertifiedTransferTransaction, Token, Transaction};
use unicity_token::verify::VerificationError;

const FIXTURE: &str = include_str!("vectors/transition_flow.json");

fn field<'a>(json: &'a str, key: &str) -> &'a str {
    // Tiny extractor to avoid a serde dependency in the test: find "key": "value".
    let needle = alloc_format(key);
    let start = json.find(&needle).expect("key present") + needle.len();
    let rest = &json[start..];
    let q1 = rest.find('"').expect("open quote") + 1;
    let q2 = rest[q1..].find('"').expect("close quote") + q1;
    &rest[q1..q2]
}

fn alloc_format(key: &str) -> String {
    format!("\"{key}\"")
}

fn trust_base() -> RootTrustBase {
    let pk = PublicKey::from_bytes(&hex::decode(field(FIXTURE, "aggregatorPublicKey")).unwrap())
        .unwrap();
    RootTrustBase::new(
        0,
        NetworkId::LOCAL,
        0,
        0,
        vec![RootTrustBaseNodeInfo {
            node_id: "NODE".into(),
            signing_key: pk,
            stake: 1,
        }],
        1,
    )
}

fn token(name: &str) -> (Vec<u8>, Token) {
    let bytes = hex::decode(field(FIXTURE, name)).unwrap();
    let token = Token::from_cbor(&bytes).expect("decode token");
    (bytes, token)
}

#[test]
fn decodes_and_roundtrips_byte_for_byte() {
    for name in [
        "aliceToken",
        "bobToken",
        "carolToken",
        "explicitTimeoutToken",
    ] {
        let (bytes, token) = token(name);
        assert_eq!(token.to_cbor(), bytes, "{name} did not round-trip");
    }
}

/// Both cases cross the SDK boundary: the default flow carries no deadline,
/// and the explicit one carries a deadline the round's reference time
/// is below.
#[test]
fn covers_present_and_absent_deadlines() {
    let tb = trust_base();

    let (_, default_token) = token("aliceToken");
    assert_eq!(default_token.genesis().transaction().expires_at(), None);
    default_token.verify(&tb).expect("absent deadline verifies");

    let (_, explicit_token) = token("explicitTimeoutToken");
    let genesis = explicit_token.genesis();
    let timeout = genesis
        .transaction()
        .expires_at()
        .expect("explicit deadline is present");
    assert!(
        genesis.reference_time() < timeout,
        "certified reference time {} must precede the request deadline {timeout}",
        genesis.reference_time()
    );
    explicit_token
        .verify(&tb)
        .expect("explicit deadline verifies");
}

#[test]
fn verifies_against_trust_base() {
    let tb = trust_base();
    for name in [
        "aliceToken",
        "bobToken",
        "carolToken",
        "explicitTimeoutToken",
    ] {
        let (_, token) = token(name);
        token
            .verify(&tb)
            .unwrap_or_else(|e| panic!("{name} should verify: {e}"));
    }
}

/// The same flow certified under partition 0 by the same trusted key: every signature, seal
/// and path is valid, only the partition is not the aggregation partition.
#[test]
fn rejects_validly_signed_tokens_of_another_partition() {
    const OTHER: &str = include_str!("vectors/transition_flow_partition0.json");
    let pk =
        PublicKey::from_bytes(&hex::decode(field(OTHER, "aggregatorPublicKey")).unwrap()).unwrap();
    let tb = RootTrustBase::new(
        0,
        NetworkId::LOCAL,
        0,
        0,
        vec![RootTrustBaseNodeInfo {
            node_id: "NODE".into(),
            signing_key: pk,
            stake: 1,
        }],
        1,
    );
    for name in [
        "aliceToken",
        "bobToken",
        "carolToken",
        "explicitTimeoutToken",
    ] {
        let token = Token::from_cbor(&hex::decode(field(OTHER, name)).unwrap()).unwrap();
        // the wrapper names the failing transaction; the cause is the partition rule
        let err = token.verify(&tb).expect_err(name);
        assert!(
            format!("{err:?}").contains("PartitionMismatch"),
            "{name}: {err:?}"
        );
    }
}

#[test]
fn rejects_wrong_aggregator_key() {
    // A trust base with a different validator key must fail the quorum check:
    // the seal signature no longer verifies. (secp256k1 generator point as a
    // valid-but-wrong key.)
    let other = PublicKey::from_bytes(
        &hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap(),
    )
    .unwrap();
    let tb = RootTrustBase::new(
        0,
        NetworkId::LOCAL,
        0,
        0,
        vec![RootTrustBaseNodeInfo {
            node_id: "NODE".into(),
            signing_key: other,
            stake: 1,
        }],
        1,
    );
    let (_, token) = token("carolToken");
    let err = token.verify(&tb).unwrap_err();
    assert!(
        matches!(
            err,
            VerificationError::QuorumNotMet
                | VerificationError::Genesis(_)
                | VerificationError::Transfer { .. }
        ),
        "unexpected error: {err}"
    );
}

#[test]
fn rejects_wrong_network() {
    // Genesis network is LOCAL; a MAINNET trust base must be rejected up front.
    let tb_pk = PublicKey::from_bytes(&hex::decode(field(FIXTURE, "aggregatorPublicKey")).unwrap())
        .unwrap();
    let tb = RootTrustBase::new(
        0,
        NetworkId::MAINNET,
        0,
        0,
        vec![RootTrustBaseNodeInfo {
            node_id: "NODE".into(),
            signing_key: tb_pk,
            stake: 1,
        }],
        1,
    );
    let (_, token) = token("aliceToken");
    assert_eq!(token.verify(&tb), Err(VerificationError::NetworkMismatch));
}

#[test]
fn rejects_structurally_unsafe_trust_bases() {
    let (_, token) = token("aliceToken");
    let empty = RootTrustBase::new(1, NetworkId::LOCAL, 1, 1, vec![], 0);
    assert!(matches!(
        token.verify(&empty),
        Err(VerificationError::InvalidTrustBase(_))
    ));

    let key = PublicKey::from_bytes(&hex::decode(field(FIXTURE, "aggregatorPublicKey")).unwrap())
        .unwrap();
    let duplicate_key = RootTrustBase::new(
        1,
        NetworkId::LOCAL,
        1,
        1,
        vec![
            RootTrustBaseNodeInfo {
                node_id: "A".into(),
                signing_key: key.clone(),
                stake: 1,
            },
            RootTrustBaseNodeInfo {
                node_id: "B".into(),
                signing_key: key,
                stake: 1,
            },
        ],
        2,
    );
    assert!(matches!(
        token.verify(&duplicate_key),
        Err(VerificationError::InvalidTrustBase(_))
    ));
}

#[test]
fn rejects_tampered_recipient() {
    // Flip a byte inside the Carol token and require that it no longer both
    // decodes-and-verifies. (Most single-byte flips break CBOR or a hash.)
    let (mut bytes, _) = token("carolToken");
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xff;
    let verified = Token::from_cbor(&bytes)
        .map(|t| t.verify(&trust_base()).is_ok())
        .unwrap_or(false);
    assert!(!verified, "tampered token must not verify");
}

#[test]
fn rejects_trailing_and_non_minimal_token_encodings() {
    let (mut trailing, _) = token("aliceToken");
    trailing.push(0xff);
    assert!(Token::from_cbor(&trailing).is_err());

    let (canonical, _) = token("aliceToken");
    // The token tag is three bytes and the following array header is one byte;
    // replace the canonical version with its non-minimal two-byte form.
    assert_eq!(canonical[4], 0x02);
    let mut non_minimal = canonical[..4].to_vec();
    non_minimal.extend_from_slice(&[0x18, 0x02]);
    non_minimal.extend_from_slice(&canonical[5..]);
    assert!(Token::from_cbor(&non_minimal).is_err());
}

#[test]
fn rejects_mismatched_transfer_certification_state() {
    let (_, token) = token("bobToken");
    let certified = &token.transactions()[0];
    let mut proof = certified.inclusion_proof().clone();
    let data = proof.certification_data.clone();
    // Rebuild with the same fields, so only the substituted source state differs.
    proof.certification_data = CertificationData::new(
        data.lock_script().clone(),
        sha256(b"unrelated source state"),
        data.transaction_hash().clone(),
        data.unlock_script().to_vec(),
        data.expires_at(),
    );

    let forged = Token::new(
        token.genesis().clone(),
        vec![CertifiedTransferTransaction::new(
            certified.transaction().clone(),
            proof,
        )],
    );
    assert!(matches!(
        forged.verify(&trust_base()),
        Err(VerificationError::Transfer { source, .. })
            if matches!(*source, VerificationError::CertificationDataMismatch)
    ));
}

/// The aggregator's answer round-trips in both of the shapes the wire admits,
/// and only the certified one yields a proof.
#[test]
fn inclusion_proof_response_round_trips_both_shapes() {
    let (_, token) = token("carolToken");
    let proof = token.transactions()[0].inclusion_proof().clone();

    let certified = InclusionProofResponse::Certified {
        block_number: 7,
        proof: proof.clone(),
    };
    let bytes = certified.to_cbor();
    let decoded = InclusionProofResponse::from_cbor(Decoder::new(&bytes)).expect("certified");
    assert_eq!(decoded, certified);
    assert_eq!(decoded.block_number(), 7);
    assert_eq!(decoded.inclusion_proof(), Some(&proof));
    assert_eq!(decoded.unicity_certificate(), &proof.unicity_certificate);

    let not_certified = InclusionProofResponse::NotCertified {
        block_number: 9,
        unicity_certificate: proof.unicity_certificate.clone(),
    };
    let bytes = not_certified.to_cbor();
    let decoded = InclusionProofResponse::from_cbor(Decoder::new(&bytes)).expect("not certified");
    assert_eq!(decoded, not_certified);
    assert_eq!(decoded.block_number(), 9);
    assert_eq!(decoded.inclusion_proof(), None);
    assert_eq!(decoded.unicity_certificate(), &proof.unicity_certificate);

    // The uncertified body is not an InclusionProof, and says so rather than
    // decoding into one with empty fields.
    let items = Decoder::new(&bytes).array(Some(2)).unwrap();
    assert!(unicity_token::api::InclusionProof::from_cbor(items[1]).is_err());
}

/// Verification authenticates each distinct seal once per operation: the
/// number of quorum-signature checks equals the number of distinct complete
/// seals among the token's proofs, however many proofs share them.
#[test]
fn verification_checks_each_distinct_seal_once() {
    use std::collections::BTreeSet;
    use unicity_token::verify::{
        verify_token_with_seal_stats, MintJustificationRegistry, VerificationPolicy,
    };

    let tb = trust_base();
    for name in ["aliceToken", "bobToken", "carolToken"] {
        let (_, token) = token(name);
        let mut seals = vec![token
            .genesis()
            .inclusion_proof()
            .unicity_certificate
            .unicity_seal
            .to_cbor()];
        for t in token.transactions() {
            seals.push(
                t.inclusion_proof()
                    .unicity_certificate
                    .unicity_seal
                    .to_cbor(),
            );
        }
        let distinct: BTreeSet<_> = seals.iter().collect();

        let (result, stats) = verify_token_with_seal_stats(
            &token,
            &tb,
            &MintJustificationRegistry::new(),
            VerificationPolicy::default(),
        );
        result.unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(stats.quorum_checks as usize, distinct.len(), "{name}");
        assert_eq!(
            (stats.quorum_checks + stats.memo_hits) as usize,
            seals.len(),
            "{name}"
        );
    }
}
