//! SP1 guest: verifies, from scratch and with a local seal session, either
//!
//! * mode 0 - a complete token (UC quorum signatures, inclusion paths, unlock-script
//!   signatures, SHA-256), or
//! * mode 1 - a native unicity certificate: tree path to the seal hash plus the
//!   strict seal authentication (network, epoch, quorum signatures).
//!
//! Signature verification is `Signature::verify`: the O3 strict rule (65 bytes, low-S,
//! key recovered with `v` equals the trusted key) implemented with `k256` entry points
//! only (`VerifyingKey::recover_from_prehash`), which the SP1 k256 patch accelerates.
#![no_main]
sp1_zkvm::entrypoint!(main);

use serde::{Deserialize, Serialize};
use unicity_token::api::bft::root_trust_base::RootTrustBaseNodeInfo;
use unicity_token::api::bft::{RootTrustBase, UnicityCertificate};
use unicity_token::api::NetworkId;
use unicity_token::cbor::Decoder;
use unicity_token::crypto::signature::PublicKey;
use unicity_token::transaction::Token;
use unicity_token::verify::{SealAuthenticator, SealSession};

#[derive(Serialize, Deserialize)]
pub struct Input {
    pub mode: u8,
    pub version: u64,
    pub network: u16,
    pub epoch: u64,
    pub epoch_start_round: u64,
    pub threshold: u64,
    /// (node id, 33-byte compressed key, stake)
    pub nodes: Vec<(String, Vec<u8>, u64)>,
    pub payload: Vec<u8>,
}

fn main() {
    let input = sp1_zkvm::io::read::<Input>();
    let nodes = input
        .nodes
        .iter()
        .map(|(id, key, stake)| RootTrustBaseNodeInfo {
            node_id: id.clone(),
            signing_key: PublicKey::from_bytes(key).expect("trust base key"),
            stake: *stake,
        })
        .collect();
    let trust_base = RootTrustBase::try_new(
        input.version,
        NetworkId::new(input.network).expect("network"),
        input.epoch,
        input.epoch_start_round,
        nodes,
        input.threshold,
    )
    .expect("trust base");

    let ok = match input.mode {
        0 => Token::from_cbor(&input.payload)
            .map(|token| token.verify(&trust_base).is_ok())
            .unwrap_or(false),
        1 => {
            let uc = UnicityCertificate::from_cbor(Decoder::new(&input.payload)).expect("uc");
            let mut session = SealSession::new(&trust_base);
            uc.computed_seal_hash()
                .is_ok_and(|h| h.data() == uc.unicity_seal.hash.as_slice())
                && session.authenticate_seal(&uc.unicity_seal).is_ok()
        }
        _ => false,
    };
    sp1_zkvm::io::commit(&ok);
}
