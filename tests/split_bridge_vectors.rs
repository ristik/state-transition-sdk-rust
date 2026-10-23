//! Cross-SDK vectors for the native bridge's split tokens
//! (`tests/vectors/bridge-split/bridge_split.json`, see its README): the payment data is the
//! bridge's wallet value envelope `tag(39050, [1, [[b(aid32), b(amount)]], null])`, a source of
//! 100 is split into 40 + 60 and the minted 40 is split again into 15 + 25. Rust must rebuild
//! both splits byte for byte from the recorded sources, and the minted second-generation tokens
//! must verify with their whole ancestry.
#![cfg(all(feature = "std", feature = "client"))]

mod trust_support;

use num_bigint::BigUint;
use unicity_token::api::bft::TrustBaseHistory;
use unicity_token::api::NetworkId;
use unicity_token::cbor::{
    encode_array, encode_byte_string, encode_null, encode_tag, encode_uint, Decoder,
};
use unicity_token::crypto::signer::{Secp256k1Signer, Signer};
use unicity_token::error::Error;
use unicity_token::payment::{
    split_output_commitment, verify_payment_token, Asset, AssetId, PaymentAssetCollection,
    PaymentDataVerifier, SplitError, SplitMintJustificationVerifier, SplitOutputPayload,
    SplitTokenRequest, TokenSplit, SPLIT_MINT_JUSTIFICATION_TAG,
};
use unicity_token::predicate::builtin::SignaturePredicate;
use unicity_token::predicate::EncodedPredicate;
use unicity_token::transaction::ids::{TokenId, TokenSalt};
use unicity_token::transaction::{CertifiedMintTransaction, Token, TokenType, Transaction};
use unicity_token::verify::{MintJustificationRegistry, VerificationError};

const VECTORS: &str = include_str!("vectors/bridge-split/bridge_split.json");
const WALLET_VALUE_TAG: u64 = 39050;
/// The recorded source's salt: the only issuance without a split justification (the lock-backed
/// root, in the bridge).
const ROOT_SALT: [u8; 32] = [0x01; 32];

/// The wallet value envelope of one asset, built field by field, independently of the SDK's
/// asset collection encoding.
fn envelope(aid: &[u8], amount: &BigUint) -> Vec<u8> {
    let entry = encode_array(&[
        &encode_byte_string(aid),
        &encode_byte_string(&amount.to_bytes_be()),
    ]);
    encode_tag(
        WALLET_VALUE_TAG,
        &encode_array(&[&encode_uint(1), &encode_array(&[&entry]), &encode_null()]),
    )
}

/// The strict decoder: the envelope, one asset, no memo.
fn wallet_value(bytes: &[u8]) -> Result<PaymentAssetCollection, Error> {
    let d = Decoder::new(bytes);
    d.finish()?;
    let items = d.expect_tag(WALLET_VALUE_TAG)?.array(Some(3))?;
    if items[0].uint()? != 1 || !items[2].is_null() {
        return Err(Error::UnexpectedValue(
            "not a version-1 wallet value without memo",
        ));
    }
    let assets = PaymentAssetCollection::from_cbor_bytes(items[1].bytes())?;
    if assets.len() != 1 {
        return Err(Error::UnexpectedValue("a wallet value carries one asset"));
    }
    Ok(assets)
}

/// Fail closed: a split output, or the recorded root.
fn issuance(
    genesis: &CertifiedMintTransaction,
    _: &PaymentAssetCollection,
) -> Result<(), VerificationError> {
    let mint = genesis.transaction();
    let split = mint.justification().is_some_and(|j| {
        Decoder::new(j)
            .expect_tag(SPLIT_MINT_JUSTIFICATION_TAG)
            .is_ok()
    });
    if split || mint.justification().is_none() && *mint.salt().bytes() == ROOT_SALT {
        Ok(())
    } else {
        Err(VerificationError::PaymentIssuanceRejected)
    }
}

/// Refuses every issuance that is not a split output.
fn splits_only(
    genesis: &CertifiedMintTransaction,
    a: &PaymentAssetCollection,
) -> Result<(), VerificationError> {
    match genesis.transaction().justification() {
        Some(_) => issuance(genesis, a),
        None => Err(VerificationError::PaymentIssuanceRejected),
    }
}

fn registry(
    token_type: &TokenType,
    policy: unicity_token::payment::PaymentIssuancePolicy,
) -> MintJustificationRegistry {
    let mut r = MintJustificationRegistry::new();
    r.register(Box::new(
        SplitMintJustificationVerifier::with_payment_decoder(wallet_value),
    ))
    .unwrap();
    r.register_token_data(Box::new(PaymentDataVerifier::with_payment_decoder(
        token_type.clone(),
        wallet_value,
        policy,
    )))
    .unwrap();
    r
}

fn key(n: u64) -> Secp256k1Signer {
    let mut k = [0u8; 32];
    k[31] = n as u8;
    Secp256k1Signer::from_bytes(&k).unwrap()
}

fn unhex(v: &serde_json::Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

struct Vectors {
    json: serde_json::Value,
    history: TrustBaseHistory,
    token_type: TokenType,
    aid: Vec<u8>,
}

fn vectors() -> Vectors {
    let json: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    // the JS test authority: network LOCAL, epoch 1 from round 0, node NODE of weight 1
    assert_eq!(json["networkId"], NetworkId::LOCAL.id());
    let history = trust_support::history(
        NetworkId::LOCAL,
        1,
        0,
        vec![(
            "NODE",
            key(json["aggregatorKey"].as_u64().unwrap()).public_key(),
            1,
        )],
    );
    Vectors {
        token_type: TokenType::new(unhex(&json["tokenType"])),
        aid: unhex(&json["aid"]),
        history,
        json,
    }
}

fn request(v: &Vectors, out: &serde_json::Value) -> SplitTokenRequest {
    let amount: BigUint = out["amount"].as_str().unwrap().parse().unwrap();
    let assets =
        PaymentAssetCollection::create([Asset::new(AssetId::new(v.aid.clone()), amount.clone())])
            .unwrap();
    let payload = SplitOutputPayload::new(assets, envelope(&v.aid, &amount), wallet_value).unwrap();
    let recipient: EncodedPredicate =
        SignaturePredicate::new(key(out["recipientKey"].as_u64().unwrap()).public_key())
            .to_encoded();
    let salt: [u8; 32] = unhex(&out["salt"]).try_into().unwrap();
    SplitTokenRequest::create_with_payload(
        recipient,
        payload,
        v.token_type.clone(),
        TokenSalt::from_bytes(salt),
    )
}

#[test]
fn splits_match_typescript_byte_for_byte() {
    let v = vectors();
    let registry = registry(&v.token_type, issuance);
    let splits = v.json["splits"].as_array().unwrap();
    assert_eq!(splits.len(), 2);

    for (i, case) in splits.iter().enumerate() {
        let name = case["name"].as_str().unwrap();
        let source = Token::from_cbor(&unhex(&case["sourceToken"])).unwrap();
        if i == 1 {
            // the second split divides the first split's first output
            assert_eq!(
                source.id().bytes().as_slice(),
                unhex(&splits[0]["outputs"][0]["tokenId"]).as_slice()
            );
        }
        let outputs = case["outputs"].as_array().unwrap();
        let mask: [u8; 32] = unhex(&case["burnStateMask"]).try_into().unwrap();
        // the verifying split: the recorded source (with its ancestry) verifies first
        let split = TokenSplit::split(
            &source,
            &v.history,
            &registry,
            wallet_value,
            outputs.iter().map(|o| request(&v, o)).collect(),
            Some(mask),
            Some(case["burnExpiresAt"].as_u64().unwrap()),
        )
        .unwrap();

        assert_eq!(
            split.burn.manifest,
            unhex(&case["manifest"]),
            "{name}: manifest"
        );
        assert_eq!(
            split.burn.transaction.to_cbor(),
            unhex(&case["burnTransaction"]),
            "{name}: burn transaction"
        );
        let network_id = source.genesis().transaction().network_id();
        assert_eq!(split.tokens.len(), outputs.len());
        for (out, expected) in split.tokens.iter().zip(outputs) {
            let amount: BigUint = expected["amount"].as_str().unwrap().parse().unwrap();
            assert_eq!(out.payload, envelope(&v.aid, &amount), "{name}: envelope");
            assert_eq!(out.payload, unhex(&expected["payload"]), "{name}: payload");
            let id = TokenId::derive(network_id, &out.salt);
            assert_eq!(
                id.bytes().as_slice(),
                unhex(&expected["tokenId"]).as_slice(),
                "{name}: token id"
            );
            let commitment = split_output_commitment(
                source.id(),
                network_id,
                &out.recipient,
                &out.salt,
                &id,
                &out.token_type,
                &out.payload,
            );
            assert_eq!(
                commitment.as_slice(),
                unhex(&expected["commitment"]).as_slice(),
                "{name}: commitment"
            );
            let proofs: Vec<Vec<u8>> = out.proofs.iter().map(|p| p.to_cbor()).collect();
            let expected_proofs: Vec<Vec<u8>> = expected["proofs"]
                .as_array()
                .unwrap()
                .iter()
                .map(unhex)
                .collect();
            assert_eq!(proofs, expected_proofs, "{name}: allocation proofs");
        }
    }
}

#[test]
fn second_generation_verifies_with_its_ancestry() {
    let v = vectors();
    let registry = registry(&v.token_type, issuance);
    let leaves = v.json["leaves"].as_array().unwrap();
    let outputs = v.json["splits"][1]["outputs"].as_array().unwrap();
    assert_eq!(leaves.len(), 2);
    for (leaf, expected) in leaves.iter().zip(outputs) {
        let token = Token::from_cbor(&unhex(leaf)).unwrap();
        assert_eq!(
            token.id().bytes().as_slice(),
            unhex(&expected["tokenId"]).as_slice()
        );
        let assets = verify_payment_token(&token, &v.history, &registry, wallet_value).unwrap();
        let amount: BigUint = expected["amount"].as_str().unwrap().parse().unwrap();
        assert_eq!(
            assets,
            PaymentAssetCollection::create([Asset::new(AssetId::new(v.aid.clone()), amount)])
                .unwrap()
        );
    }
}

#[test]
fn refusals() {
    let v = vectors();
    let leaf = Token::from_cbor(&unhex(&v.json["leaves"][0])).unwrap();

    // the issuance policy is applied to every ancestor: refusing the root refuses the leaf
    let strict = registry(&v.token_type, splits_only);
    let refused = verify_payment_token(&leaf, &v.history, &strict, wallet_value);
    // the leaf is two splits below the root: the root's refusal surfaces through each burned ancestor
    let burned = |e| VerificationError::BurnTokenVerificationFailed(Box::new(e));
    assert_eq!(
        refused,
        Err(burned(burned(VerificationError::PaymentIssuanceRejected)))
    );
    // and the same leaf verifies once the root is admitted (the refusal above is the root's)
    let admitted = registry(&v.token_type, issuance);
    assert_eq!(
        verify_payment_token(&leaf, &v.history, &admitted, wallet_value).map(|_| ()),
        Ok(())
    );

    // without a split verifier the split justification is not accepted
    let mut bare = MintJustificationRegistry::new();
    bare.register_token_data(Box::new(PaymentDataVerifier::with_payment_decoder(
        v.token_type.clone(),
        wallet_value,
        issuance,
    )))
    .unwrap();
    assert_eq!(
        verify_payment_token(&leaf, &v.history, &bare, wallet_value),
        Err(VerificationError::UnsupportedMintJustification)
    );

    // a split that does not preserve the source amount is refused before anything is signed
    let case = &v.json["splits"][1];
    let source = Token::from_cbor(&unhex(&case["sourceToken"])).unwrap();
    let mut outputs: Vec<serde_json::Value> = case["outputs"].as_array().unwrap().clone();
    outputs[1]["amount"] = serde_json::Value::String("25000000000000001".into());
    let r = TokenSplit::split(
        &source,
        &v.history,
        &admitted,
        wallet_value,
        outputs.iter().map(|o| request(&v, o)).collect(),
        None,
        None,
    );
    assert!(
        matches!(
            r,
            Err(SplitError::Build(Error::UnexpectedValue(
                "split asset total does not match source amount"
            )))
        ),
        "{r:?}"
    );

    // an envelope with a memo is not a wallet value
    let amount = BigUint::from(1u8);
    let assets =
        PaymentAssetCollection::create([Asset::new(AssetId::new(v.aid.clone()), amount)]).unwrap();
    let with_memo = encode_tag(
        WALLET_VALUE_TAG,
        &encode_array(&[
            &encode_uint(1),
            &assets.to_cbor(),
            &encode_byte_string(b"memo"),
        ]),
    );
    assert!(SplitOutputPayload::new(assets, with_memo, wallet_value).is_err());
}
