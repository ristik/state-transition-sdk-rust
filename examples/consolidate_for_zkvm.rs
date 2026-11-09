//! Host-side preparation for zkVM verification.
//!
//! The *host* may use the network to consolidate a token explicitly; the *guest*
//! (SP1/RISC0/...) receives only the serialized ordinary token plus its own
//! trusted inputs and verifies it from scratch with a local seal session. The
//! guest must authenticate the seal itself: a verdict, cache entry or counter
//! produced on the host is not evidence inside the proof.
//!
//! `guest_verify` below is the entire guest-side logic and is `no_std + alloc`
//! compatible (`--no-default-features --features alloc`).
//!
//! Run with:
//!   cargo run --example consolidate_for_zkvm --features http -- token.hex

#[path = "common/consolidation.rs"]
mod common;

use unicity_token::api::bft::RootTrustBase;
use unicity_token::client::{ConsolidateOptions, ConsolidationOutcome};
use unicity_token::transaction::Token;
use unicity_token::verify::{
    verify_token_with_seal_stats, MintJustificationRegistry, VerificationPolicy,
};

/// Everything the guest does: decode, verify with an operation-scoped session
/// (repeated seals are authenticated once *inside the guest*), commit the result.
fn guest_verify(token_bytes: &[u8], trust_base: &RootTrustBase) -> bool {
    let Ok(token) = Token::from_cbor(token_bytes) else {
        return false;
    };
    let (result, stats) = verify_token_with_seal_stats(
        &token,
        trust_base,
        &MintJustificationRegistry::new(),
        VerificationPolicy::default(),
    );
    println!("guest: {} quorum checks", stats.quorum_checks);
    result.is_ok()
}

fn main() {
    let input = std::env::args().nth(1).expect("input token hex file");
    let (trust_base, proofs) = common::load();
    let token = Token::from_cbor(
        &hex::decode(std::fs::read_to_string(&input).expect("read token").trim())
            .expect("token hex"),
    )
    .expect("decode token");

    // Host: optional, explicit, bounded by one deadline. Falling back to the original
    // token is the caller's policy decision (it may exceed the guest's cycle budget).
    let to_prove = match proofs.consolidate(&token, &ConsolidateOptions::default()) {
        Ok(ConsolidationOutcome::Consolidated { token, .. }) => token,
        Ok(ConsolidationOutcome::Unavailable { reason, .. }) => {
            println!("unavailable ({reason:?}); proving the original token");
            token
        }
        Err(e) => panic!("consolidation failed: {e}"),
    };

    // Guest input: the serialized ordinary token and the guest's own trusted trust base.
    let ok = guest_verify(&to_prove.to_cbor(), &trust_base);
    println!("guest accepted: {ok}");
}
