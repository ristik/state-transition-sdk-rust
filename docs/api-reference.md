# Unicity State Transition SDK for Rust: API Reference

This document describes SDK behaviour that the README only summarizes. The rustdoc comments in the source are authoritative.

## 1. Waiting for Inclusion Proofs

### Status hints

`HttpAggregatorClient` asks the aggregator for a status hint (`includeStatus` on `get_inclusion_proof.v2`). While waiting for a proof:

- `pending`: polling continues at the configured interval.
- `expired`: the wait stops at once with `HttpError::StateExpired`. The same signed request may be resubmitted.
- `unknown`: the wait stops with `HttpError::StateUnknown` after a grace period (`with_unknown_grace`, default two answers). Right after a submission, another aggregator instance may not have seen the request yet.

`lookup_inclusion_proof` returns the hint together with the response, without waiting. Servers without the feature answer with a plain string and the client behaves as before; the same applies to status values this version does not know.

The hint is unauthenticated and is used only for control flow and user feedback. `unknown` does not show that a state was never certified or is unspent, and `expired` does not show that it is unspent. An `included` hint has no value without a proof that verifies. A certified proof is returned regardless of the hint, and no token, proof or certificate verification depends on it.

With several aggregator instances behind a load balancer, an instance that did not admit the request may answer `unknown`. After a restart, the in-memory status is empty, so queued requests answer `unknown` until a round picks them up.

### Long polling

`client::mint` and `client::transfer` wait for the proof through `HttpAggregatorClient::get_inclusion_proof`, which by default asks the aggregator to hold each request while the state is pending (`waitMs`). This reduces the number of requests and returns the proof soon after certification. With long polling on, `with_polling(interval, attempts)` sets the polling interval and a total time budget of `interval * attempts` (default 1 s × 15 = 15 s, for both the long-poll and the attempts-loop path). `HttpAggregatorClient::with_long_poll(false)` restores the attempt-based loop, which sends no `waitMs`. The same wait is available directly as `wait_for_inclusion_proof(&state_id, &WaitOptions::new(total))`, with these options:

- The wait never exceeds `total`. Each request asks for at most the preferred wait (`with_preferred_wait`, default 20 s) and leaves a response margin (`with_margin`, default 2 s) within the remaining time and the per-call limit (`with_max_request_timeout`, default 30 s).
- `WaitOptions::with_long_poll(false)` sends no `waitMs` and polls at the interval (`with_poll_interval`, default the client's interval).
- An answer without the `waitedMs` echo to a request that asked for a wait means the server does not support long polling; the rest of that call polls at the interval. Nothing is remembered across calls.
- The echo is unauthenticated and never extends the deadline. The returned proof is unverified, as with `get_inclusion_proof`.
- `with_unknown_grace` overrides the client's `unknown` grace for this wait. `with_cancel` is checked before every call and during pauses; a call already in flight ends at its own timeout, because a blocking transport cannot be interrupted.
- A transport-level failure of a proof read inside a wait (refused or reset connection, stale pooled connection, one call timing out inside the budget, truncated response, an interrupted 502/503/504 body) is inconclusive too: plain reads at the interval within the original budget; TLS certificate/hostname failures, invalid URLs and cancellation stay terminal, submissions are never replayed and one-shot calls surface the error. HTTP 502 and 504 inside a wait are inconclusive like an overload (plain reads for the rest of the wait, original budget, no resubmission); the status counts even when the body is not JSON or exceeds the error-body limit, and one-shot calls still return the error. `Retry-After` accepts delay-seconds and HTTP-date, capped at 60 s. A gateway's HTTP 400 for a batch spanning shards keeps its `-32602` classification (not the retry-without-`waitMs` case).
- An overload answer (HTTP 503 or 429, JSON-RPC `-32006`, or `data.retryable: true`) is not a failure: the wait pauses the larger of the interval and `Retry-After` (at most 60 s) and then sends plain reads without `waitMs`, or fails at once with `HttpError::OverloadTimeout` (the overload as `source`) when that pause does not fit the time left. The same holds for the attempts loop.
- `wait_for_inclusion_proof_with_stats` also returns request counts (`WaitStats`).

For batches, `BatchAggregatorClient::get_inclusion_proofs_with_wait(&request, &options, &WaitRequest::new(wait_ms))` applies the wait to a latest-root request; it is never sent for an exact root. `get_latest_negotiating_wait` repeats the request once without `waitMs` when a server rejects the unknown field as `malformed_params`. Consolidation waits only when enabled with `ProofClient::with_master_long_poll(MasterLongPoll::default())`, and then only on the master's latest request.

### Resubmission

A certification request is signed and deterministic, so sending it again is the same request; the aggregator never creates a second leaf for it.

`resubmit_certification_request` is the idempotent form of submission. It returns `SubmitOutcome::AlreadySubmitted` instead of an error when the aggregator already holds a record for the state ID. The server reports this in two ways:

- A MongoDB-backed queue rejects a copy of a still-pending request with an internal error (code `-32603`) whose data names a duplicate key. The client recognizes it by that text, since the server has no dedicated code for it. A Redis-backed queue accepts and drops the copy.
- `STATE_ID_EXISTS` when the state is already certified.

Both reports are by state ID only, so a different request for the same state, such as a conflicting spend, is reported the same way. Every other rejection, such as `REQUEST_EXPIRED`, remains an error. The plain `submit_certification_request` reports both duplicate responses as errors.

`submit_and_wait(data, max_resubmits)` combines submission, waiting, and at most `max_resubmits` resubmissions after `StateUnknown` or `StateExpired`. It requires the proof to certify exactly the submitted data. If the state ID was certified with another request, it fails with `HttpError::ProofOfOtherData` (based on unauthenticated data; no resubmission) instead of returning the other transaction's proof. `submit_and_wait_verified(data, max_resubmits, &trust_base)` authenticates that proof first and reports `HttpError::StateCertifiedWithOtherData` only if it verifies.

## 2. Aggregation Partition

All Unicity networks use one aggregation partition, exported as `unicity_token::AGGREGATION_PARTITION_ID` (`u32`, value `7`; also `unicity_token::api::AGGREGATION_PARTITION_ID`). It is a protocol constant: there is no environment, constructor or per-network override, and a proof never selects its own expected partition. Network authentication remains mandatory; the trust base fixes the network, authority and epoch.

Every application verification path requires the authenticated unicity certificate to be of this partition and otherwise fails with `VerificationError::PartitionMismatch`. This covers inclusion verification, token verification (genesis, transfers and nested source tokens), non-inclusion verification, and consolidation (input proofs, partition views, enclosing certificates and the unsharded direct target). The check runs before the seal memo is consulted, so a cached seal cannot carry a certificate of another partition. Generic codecs (`UnicityTreeCertificate`, `PartitionView::from_cbor`) are partition-agnostic and do not by themselves establish validity.

## 3. Partition Views and Seal Reuse

`unicity_token::consolidation` (`no_std + alloc`, no network access) decodes a `PartitionViewV1`, the complete shard-leaf vector of a partition under one unicity seal, as an untrusted candidate. `PartitionView::authenticate`:

1. validates its structure;
2. rebuilds the shard tree;
3. follows the enclosing certificate's partition path to the seal hash and matches the enclosing leaf exactly;
4. authenticates the complete seal under the entry of the seal's epoch in the caller's `TrustBaseHistory` (network, the epoch's round interval, the strict weighted quorum).

Only then does it return an immutable `AuthenticatedView`, the only input accepted by `certificates()`, which yields ordinary unicity certificates for every shard, all carrying the same seal. No peer configuration list is needed, because the seal commits to every leaf's configuration hash. Independently pinned shard configuration hashes (`Some(&PartitionTopology)`) are an optional stricter policy and are part of `AuthenticatedView::identity()`. The authority is never taken from a response.

Token verification authenticates each distinct seal once per operation (`verify::SealSession`, a bounded memo of successful quorum checks bound to one trust base history entry per seal). Only the quorum signature check is reused; paths, reference times, predicates and application rules are checked for every proof. `verify::verify_token_with_seal_stats` reports the signature work performed. Seal reuse does not change token size or format, and nested proofs that carry other seals still need their own check.

## 4. Proof Consolidation

With the `client` feature, `client::ProofClient::consolidate(&token, &options)` returns a new, fully verified token whose replaceable outer-history proofs share one unicity seal. This reduces verification cost where a verifier reuses a successful quorum check, for example in a smart contract or a zkVM guest.

Properties:

- It is only called explicitly. Mint, transfer, receive, import, serialization and `Token::verify` do not call it.
- It needs no signing key and never submits or resubmits a transaction.
- Token format and size do not change. Proofs nested in signed mint justifications or split and burn dependencies stay byte-identical and may still need their own seals; the summary reports outer-history and whole-verification quorum checks separately.

An attempt asks the master shard (the one with the newest authenticated evidence) for its latest batch and partition view, authenticates it under the caller's trust base and configured topology, then fetches the exact roots named by the authenticated view from the other participating shards (in bounded parallel on a host). All requests run under one deadline and one `CancelToken`. The batch call is the optional `client::BatchAggregatorClient` capability (`get_inclusion_proofs.v1`), implemented by `HttpAggregatorClient`; it is never emulated with single-proof calls.

Results:

- `Consolidated` with the new token.
- `Unavailable { reason, retryable }` for a missing capability, a view that is not retained or not yet published, or a busy service. The original token is unchanged.
- An error for integrity failures, transport and server failures, timeouts and cancellation.

Status details from the shards map to `UnavailableReason::StatePending` (retryable), `StateExpired`, `StateUnknown` and `StateNotInRoot` (not retryable).

Examples: `examples/consolidate_for_bridge.rs` and `examples/consolidate_for_zkvm.rs`. Planning and checked reconstruction (`consolidation::{ShardRouter, outer_proofs, rebuild_token, ..}`) are `no_std + alloc`.

## 5. Non-inclusion Proofs

> Non-inclusion proves absence only at the authenticated snapshot returned by verification. It does not prove absence now, continuous absence, or that a token can be spent. Compare the snapshot’s network and root round (or its certified seal timestamp under your application’s time policy) with an independently trusted requirement. The seal timestamp is a consensus-certified time, not proof of real-time freshness. Do not use unverified response metadata for this check.

`AggregatorClient::get_non_inclusion_proof(&state_id)` fetches a proof; it is unverified.

`NonInclusionProof::verify_at_snapshot(&trust_base, &context)` (also `verify_for_at_snapshot` for a directly decoded proof, and `verify::verify_non_inclusion_at_snapshot` / `verify_non_inclusion_in` for explicit sessions) authenticates the unicity certificate before it returns anything: shape, trusted network, the authority of the seal's epoch and its round interval, quorum, the aggregation partition, the shard and partition commitments together with the optional pins of the `NonInclusionContext`, the query binding and the full state-tree relation. The result is:

- `Ok(NonInclusionOutcome::AbsentAtSnapshot { state_id, snapshot })`: the path proves the key absent.
- `Ok(NonInclusionOutcome::IncludedAtSnapshot { state_id, snapshot })`: the path proves that exact key present.
- `Err(VerificationError)`: rejected; no snapshot metadata.

`NonInclusionSnapshot` exposes `network_id`, `partition_id`, `shard_id`, `root_round`, `seal_timestamp_seconds` (Unix seconds), `root_epoch`, `shard_round`, `shard_epoch` and `state_root` (`None` for the certified empty tree). All values are read from the authenticated certificate, not from the RPC block number or the time of receipt. The snapshot owns copies of its data.

There is no freshness option. Freshness is the application's decision on the returned snapshot, against a checkpoint obtained independently of the proof and the server response:

```rust
// `checkpoint` is obtained independently of the proof and of the server response.
let outcome = proof.verify_at_snapshot(&trust_base, &NonInclusionContext::new())?;
let NonInclusionOutcome::AbsentAtSnapshot { snapshot, .. } = outcome else {
    return Err("no verified absence".into());
};
if snapshot.network_id().id() != checkpoint.network_id
    || snapshot.root_round() < checkpoint.required_root_round
{
    return Err("snapshot does not meet application policy".into());
}
// Absence at `snapshot` only; any spend or finality decision needs its own policy.
```

`NonInclusionContext::new()` expects the unsharded partition, where the certificate's shard is the empty shard; this matches the Go verifier with an empty `Shard`. For a sharded partition, pin the served shard with `NonInclusionContext::new().with_shard(shard)`. The certificate's shard ID and complete shard path must then be that shard's, and the query and terminal must belong to it. Because the certificate is authenticated first, a rejection reflects the certificate before the path is examined.

`NonInclusionProof::for_state` only records which state ID a proof was requested for. It is request bookkeeping, not evidence.

`HttpError::StateIncluded` reports the server's claim that the state is included. The claim is unauthenticated; request an inclusion proof and verify it.

## 6. Unicity Trust Base History

`api::bft::TrustBaseEntry` is one signed epoch record (record version 2, CBOR tag 39000, byte-compatible with bft-go-base `RootTrustBaseV2`). `api::bft::TrustBaseHistory` holds the chain of entries a verifier knows.

- **Absent hashes.** `stateHash` and `changeRecordHash` are `null` when absent, otherwise exactly 32 bytes; the empty byte string is refused (one byte form, one identity).
- **Identity.** `entry_id()` is the SHA-256 of the entry with its signature field encoded as `null` (`sig_bytes()`); valid signature sets of the same entry share it. A successor links to its predecessor's identity.
- **Quorum.** Member weights are positive and bounded; the threshold is exactly `floor(2W/3)+1` of the total weight `W`. Signatures are the predecessor members' 65-byte recoverable signatures over `SHA-256(sig_bytes)`; the check is strict (an unknown member or any invalid signature fails the entry), the 64-byte compact form is not accepted.
- **Append-only.** `append` verifies an entry from the latest held entry (epoch + 1, same network, later start, predecessor identity, quorum) and adds it. The same entry again (same identity) is a no-op only if its witness is valid, and the first witness stays; another entry of a held epoch is `HistoryError::Conflict`; an entry beyond the next epoch is a `Gap`. The latest held entry is effectively the pin.
- **Bundles.** A release ships the whole known history as one tag-39015 `GetTrustBase` response (`to_bundle`, `from_bundle`); `install_bundle` merges one into a history, all or nothing.
- **Genesis.** Load it from CBOR, or from the V2 JSON form with `TrustBaseEntry::from_json` (host only; compare the identity with the deployment pin via `TrustBaseHistory::from_genesis(entry, Some(pin))`).

- **Verification.** Every verification entry point (`Token::verify`, `verify::verify_token*`, `InclusionProof::verify*`, `NonInclusionProof::verify_at_snapshot`, `client::mint`/`transfer`) takes the history. A seal is judged by the entry of **its own epoch**; there is no age limit and no freshness rule. The newest epoch is open-ended until its successor is held; an older epoch ends at the successor's start round. Seal signatures follow the native rule: every signature is checked (no early exit), an unknown signer or a bad signature fails the seal, a signature is 64 bytes or 65 with recovery byte 0/1, and the signed weight has to reach the entry's threshold.
- **Errors.** A seal of an epoch newer than the latest held entry is `VerificationError::UnknownTrustEpoch { epoch }` (`unknown_trust_epoch()` finds it inside nested errors): retryable, fetch the missing entries, `append` them and verify again. An epoch older than the first entry is `EpochBeforeGenesis`; `SealBeforeEpochStart`, `SealAfterAuthorityEnd`, `SealSignerInvalid` and `QuorumNotMet` complete the seal outcomes.
- **Trusted chains.** `TrustBaseHistory::from_trusted_chain` builds a history from entries the caller already trusts (their signatures are not verified; epoch 0 is admitted for fixtures). Peer-supplied entries go through `append`/`install_bundle`.

## 7. Keeping the history current (verify, update, retry)

A token whose certificate names an epoch the history does not hold fails with `VerificationError::UnknownTrustEpoch { epoch }`. The history is brought up to date from the aggregator, then verification is retried:

- `client::TrustBaseSource` is the capability to ask for a page of entries (`GetTrustBase`). `HttpAggregatorClient` implements it: `GET <origin>/api/v1/trustbases?from=E[&to=E][&snapshotEnd=E&snapshotEntryId=0x..][&maxEntries=N]`, `Accept: application/cbor`, the raw tag-39015 response as body (status inside the body; pages of at most 64 entries and 1 MiB). The source is trusted for nothing: every entry is verified from the history's own latest entry (`append`).
- `client::update_trust_base(&mut history, &source, want, &limits)` is the clock-free step (`alloc` only): always asks from `held + 1`, follows the pagination snapshot, stops at `want`, at the end of the source, or after `limits.total_entries` entries (default 1024). `UpdateOutcome::NotYetAvailable` means the source does not have the epoch (yet); a status other than OK/NotYetAvailable, a protocol contradiction or an entry that does not extend the history is an `UpdateError` (an alarm; never retried).
- `client::verify_token_updating(&token, &mut history, &source, &policy)` (host, `std`) is the loop: verify; on a missing epoch update and verify again; if the source does not have the epoch, wait `policy.interval` (default 2 s) and ask again, at most `policy.attempts` (5) times within `policy.deadline` (10 s), then `VerifyUpdateError::EpochUnavailable { held, wanted, attempts }`. Any other verification failure returns at once. The history is updated **in place** (append-only).
- `client::mint_updating` / `client::transfer_updating` do the same for a freshly certified proof (or an input token) from an epoch newer than the history: the plain `mint`/`transfer` fail with `UnknownTrustEpoch`, the `_updating` variants fetch and retry (`ClientError::EpochUnavailable`, `ClientError::TrustBaseUpdate`).
- Pure verification never sleeps or fetches; zkVM and `no_std` guests use `verify_token` and do the updating on the host.
