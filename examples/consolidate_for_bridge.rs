//! Explicit proof consolidation before EVM verification / internal bridge back.
//!
//! An application that is about to hand a token to an EVM verifier (or to the
//! bridge-back path) can first ask for a token whose outer-history proofs share
//! one unicity seal, so a verifier that reuses a successful quorum check pays
//! for the signatures once. This is **opt-in and never automatic**: nothing in
//! mint, transfer, receive, import, serialization or `Token::verify` calls it.
//! It needs no signing key and submits nothing.
//!
//! The consolidated token is an ordinary token (same format, same size). The
//! EVM verifier must still reuse the authentication within its own session and
//! enforce its own admission limits; this call does not promise either.
//!
//! Run with:
//!   cargo run --example consolidate_for_bridge --features http -- token.hex out.hex
//! (see `examples/common/consolidation.rs` for the environment)

#[path = "common/consolidation.rs"]
mod common;

use unicity_token::client::{CancelToken, ConsolidateOptions, ConsolidationOutcome};
use unicity_token::transaction::Token;

fn main() {
    let mut args = std::env::args().skip(1);
    let input = args.next().expect("input token hex file");
    let output = args.next().expect("output token hex file");

    let (_trust_base, proofs) = common::load();
    let token = Token::from_cbor(
        &hex::decode(std::fs::read_to_string(&input).expect("read token").trim())
            .expect("token hex"),
    )
    .expect("decode token");

    // One total deadline for the whole attempt, and a host-controlled cancel flag
    // (here: an overall watchdog; an application would tie it to its own shutdown).
    let cancel = CancelToken::new();
    let watchdog = cancel.clone();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(30));
        watchdog.cancel();
    });
    let options = ConsolidateOptions {
        timeout_ms: 10_000,
        cancel,
        master: None,
    };

    match proofs.consolidate(&token, &options) {
        Ok(ConsolidationOutcome::Consolidated { token, summary }) => {
            println!(
                "consolidated: outer seals {} -> {}, {} requests, master round {:?}",
                summary.outer_seals_before,
                summary.outer_seals_after,
                summary.requests,
                summary.master_round,
            );
            // Nested proofs inside signed mint justifications keep their own seals, so the
            // whole recursive verification may still need more than one quorum check:
            println!(
                "whole-verification quorum checks: {}",
                summary.verification_quorum_checks
            );
            // Hand this to the application's EVM / bridge-back adapter.
            std::fs::write(&output, hex::encode(token.to_cbor())).expect("write token");
        }
        Ok(ConsolidationOutcome::Unavailable { reason, retryable }) => {
            // The original token is untouched and was not certified by this call: retry
            // later (if `retryable`) or check it against the target verifier's limits as is.
            println!("consolidation unavailable: {reason:?} (retryable: {retryable})");
        }
        // Integrity failures, server/transport failures, timeouts and cancellation are errors,
        // never disguised as "unavailable".
        Err(e) => {
            eprintln!("consolidation failed: {e}");
            std::process::exit(1);
        }
    }
}
