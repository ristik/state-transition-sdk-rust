//! Cross-SDK check for split output payloads: the Rust splitter must produce the
//! same burn transaction, manifest, output commitments and allocation proofs as
//! the TypeScript SDK for the fixed inputs in
//! `tests/vectors/split-payload/split_payload.json` (see its README).
#![cfg(all(feature = "std", feature = "client"))]

use num_bigint::BigUint;
use unicity_token::cbor::{encode_array, encode_tag, encode_uint, Decoder};
use unicity_token::crypto::signer::{Secp256k1Signer, Signer};
use unicity_token::error::Error;
use unicity_token::payment::{
    split_output_commitment, Asset, AssetId, PaymentAssetCollection, PaymentDataDecoder,
    SplitOutputPayload, SplitTokenRequest, TokenSplit,
};
use unicity_token::predicate::builtin::SignaturePredicate;
use unicity_token::predicate::EncodedPredicate;
use unicity_token::transaction::ids::{TokenId, TokenSalt};
use unicity_token::transaction::{Token, Transaction};

const VECTORS: &str = include_str!("vectors/split-payload/split_payload.json");

/// Application envelope `tag(39050, [1, assets, null])`; defined by the test,
/// not by the SDK.
fn wrap(assets: &PaymentAssetCollection) -> Vec<u8> {
    encode_tag(
        39050,
        &encode_array(&[&encode_uint(1), &assets.to_cbor(), &[0xf6]]),
    )
}

fn unwrap(bytes: &[u8]) -> Result<PaymentAssetCollection, Error> {
    let d = Decoder::new(bytes);
    d.finish()?;
    let items = d.expect_tag(39050)?.array(Some(3))?;
    if items[0].uint()? != 1 || !items[2].is_null() {
        return Err(Error::UnexpectedValue("bad envelope"));
    }
    PaymentAssetCollection::from_cbor_bytes(items[1].bytes())
}

fn key(n: u8) -> Secp256k1Signer {
    let mut k = [0u8; 32];
    k[31] = n;
    Secp256k1Signer::from_bytes(&k).unwrap()
}

fn unhex(v: &serde_json::Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn assets_of(v: &serde_json::Value) -> PaymentAssetCollection {
    PaymentAssetCollection::create(v.as_array().unwrap().iter().map(|a| {
        Asset::new(
            AssetId::new(unhex(&a["id"])),
            a["value"].as_str().unwrap().parse::<BigUint>().unwrap(),
        )
    }))
    .unwrap()
}

#[test]
fn split_matches_typescript_byte_for_byte() {
    let vectors: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    let cases = vectors["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 2);

    for case in cases {
        let name = case["name"].as_str().unwrap();
        let wrapped = case["wrapped"].as_bool().unwrap();
        let decoder: PaymentDataDecoder = if wrapped {
            unwrap
        } else {
            PaymentAssetCollection::from_cbor_bytes
        };
        let encode = |a: &PaymentAssetCollection| if wrapped { wrap(a) } else { a.to_cbor() };

        let source = Token::from_cbor(&unhex(&case["sourceToken"])).unwrap();
        let source_assets = assets_of(&case["sourceAssets"]);
        assert_eq!(
            source.genesis().transaction().data().unwrap(),
            encode(&source_assets).as_slice(),
            "{name}: source payload"
        );

        let outputs = case["tokens"].as_array().unwrap();
        let requests: Vec<_> = outputs
            .iter()
            .map(|o| {
                let assets = assets_of(&o["assets"]);
                let payload =
                    SplitOutputPayload::new(assets, encode(&assets_of(&o["assets"])), decoder)
                        .unwrap();
                let recipient: EncodedPredicate = SignaturePredicate::new(
                    key(o["recipientKey"].as_u64().unwrap() as u8).public_key(),
                )
                .to_encoded();
                let salt: [u8; 32] = unhex(&o["salt"]).try_into().unwrap();
                SplitTokenRequest::create_with_payload(
                    recipient,
                    payload,
                    source.token_type().clone(),
                    TokenSalt::from_bytes(salt),
                )
            })
            .collect();

        let mask: [u8; 32] = unhex(&case["burnStateMask"]).try_into().unwrap();
        let split = TokenSplit::split_unchecked(
            &source,
            decoder,
            requests,
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
            assert_eq!(out.payload, unhex(&expected["payload"]), "{name}: payload");
            assert_eq!(
                TokenId::derive(network_id, &out.salt).bytes().as_slice(),
                unhex(&expected["tokenId"]).as_slice(),
                "{name}: token id"
            );
            let commitment = split_output_commitment(
                source.id(),
                network_id,
                &out.recipient,
                &out.salt,
                &TokenId::derive(network_id, &out.salt),
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
