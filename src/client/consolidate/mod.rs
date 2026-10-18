//! Explicit, opt-in proof consolidation (`client` feature).
//!
//! [`ProofClient::consolidate`] takes an existing, verifiable [`Token`] and
//! returns a *new* verified token whose replaceable outer-history proofs share
//! one unicity seal, so a verifier that reuses a successful quorum check pays
//! for the signatures once (EVM/bridge-back and zkVM preparation). It is never
//! called by ordinary mint, transfer, receive, import, serialization or
//! verification, needs no signing key and never submits or resubmits anything.
//!
//! One attempt = one *master* wave (the shard of the newest authenticated
//! evidence, asked for its latest batch and partition view), then one exact-root
//! wave for the other participating shards run through a [`WaveExecutor`] (bounded
//! parallel on a host), all under one total deadline and one [`CancelToken`].
//! There is no retry, no chunking and no chasing of a moving "latest".
//!
//! An **unsharded** partition (empty shard id, no shard-tree siblings) needs no
//! partition view: its ordinary certificate already commits to everything a one-leaf
//! view would repeat, so the batch's common certificate is authenticated directly
//! (strictly, under the configured partition and pins) and is the target of one
//! latest request. A sharded partition without its view is still unavailable, and a
//! malformed or unauthenticated certificate or sidecar is an integrity error, never a
//! reason to fall back.
//!
//! Only the outer-history proofs are replaced. Proofs embedded in signed mint
//! justifications, split/burn dependencies or predicate data stay byte-identical
//! and may still need their own seals: the summary reports outer-history and
//! whole-verification seal work separately. The token format and its size are
//! unchanged.

// Errors carry typed context and sit on the cold path; boxing them would only
// obscure the public error enum that callers match on.
#![allow(clippy::result_large_err)]

mod direct;
mod error;
mod run;
#[cfg(all(test, feature = "std"))]
mod tests;

pub use error::{
    AdmissionWork, ConsolidationError, ConsolidationOutcome, ConsolidationSummary, IntegrityError,
    UnavailableReason,
};
pub use run::{CancelToken, Clock, SequentialExecutor, WaveExecutor};
#[cfg(feature = "std")]
pub use run::{SystemClock, ThreadedExecutor};

use alloc::collections::BTreeMap;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use super::batch::{
    detail, rpc_code, BatchAggregatorClient, BatchFailure, BatchRequest, InclusionProofBatch,
    RequestOptions, StateRoot, MAX_BATCH_STATE_IDS,
};
use crate::api::bft::{RootTrustBase, ShardId};
use crate::api::inclusion_proof::InclusionProof;
use crate::api::StateId;
use crate::consolidation::{
    distinct_seals, outer_proofs, rebuild_token, replacement_proof, view_policy, PartitionTopology,
    RootRoundBound, ShardRouter,
};
use crate::transaction::Token;
use crate::verify::{
    verify_membership_in, verify_membership_under, verify_token_in_session,
    verify_token_with_seal_stats, MintJustificationRegistry, SealAuthenticator, SealSession,
    VerificationPolicy,
};
use direct::DirectTarget;

/// Default total deadline of one attempt.
pub const DEFAULT_TIMEOUT_MS: u64 = 10_000;

/// Trusted routing configuration, fixed once.
#[derive(Debug, Clone)]
pub struct ProofClientConfig {
    /// The partition all tokens of this client belong to.
    pub partition_id: u32,
    /// The trusted sharding scheme (empty = one shard). Admitted shard
    /// configuration hashes in it are enforced as pins; with none, the seal is
    /// the authority for every leaf's hash. It is never learned from a response.
    pub topology: PartitionTopology,
}

/// Per-call options.
#[derive(Debug, Clone)]
pub struct ConsolidateOptions {
    /// The one total deadline of the attempt, in milliseconds.
    pub timeout_ms: u64,
    /// Cancellation, observed before every request and after every wave.
    pub cancel: CancelToken,
    /// Override the master shard (it must participate). By default the shard of
    /// the newest authenticated evidence.
    pub master: Option<ShardId>,
}

impl Default for ConsolidateOptions {
    fn default() -> Self {
        Self {
            timeout_ms: DEFAULT_TIMEOUT_MS,
            cancel: CancelToken::new(),
            master: None,
        }
    }
}

/// An original certified state: the input of a proof-bundle consolidation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofItem {
    /// The certified state.
    pub state_id: StateId,
    /// Its original proof.
    pub proof: InclusionProof,
}

/// Replacement proofs, in input order, all under one seal, with their summary.
/// This is a proof bundle: complete token semantics are checked by
/// [`ProofClient::consolidate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofBundle {
    /// One verified replacement per input item.
    pub proofs: Vec<InclusionProof>,
    /// Instrumentation.
    pub summary: ConsolidationSummary,
}

/// Result of a proof-bundle consolidation that did not fail.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum BundleOutcome {
    /// The replacement proofs.
    Consolidated(ProofBundle),
    /// Unavailable now; the inputs are unchanged.
    Unavailable {
        /// Why.
        reason: UnavailableReason,
        /// Whether a new attempt may succeed.
        retryable: bool,
    },
}

/// Why an attempt stopped: unavailable (a normal outcome) or an error.
enum Stop {
    Unavailable(UnavailableReason, bool),
    Error(ConsolidationError),
}

impl From<ConsolidationError> for Stop {
    fn from(e: ConsolidationError) -> Self {
        Stop::Error(e)
    }
}

type Res<T> = Result<T, Stop>;

/// The one deadline plus cancellation of an attempt.
struct Budget<'a, K: Clock> {
    clock: &'a K,
    deadline_ms: u64,
    cancel: &'a CancelToken,
    abort: CancelToken,
}

impl<K: Clock> Budget<'_, K> {
    /// Remaining milliseconds, or the typed reason the attempt must stop.
    fn check(&self) -> Res<u64> {
        if self.cancel.is_cancelled() || self.abort.is_cancelled() {
            return Err(ConsolidationError::Cancelled.into());
        }
        let remaining = self.deadline_ms.saturating_sub(self.clock.now_ms());
        if remaining == 0 {
            return Err(ConsolidationError::Timeout.into());
        }
        Ok(remaining)
    }
}

/// One shard that participates in this consolidation.
struct Group {
    endpoint: usize,
    shard: ShardId,
    /// Indexes into the input items.
    items: Vec<usize>,
    ids: Vec<StateId>,
}

/// Explicit consolidation service, constructed once with the trusted routing
/// and verification context. It is stateless between calls.
pub struct ProofClient<C, K, X> {
    config: ProofClientConfig,
    router: ShardRouter,
    trust_base: RootTrustBase,
    registry: MintJustificationRegistry,
    policy: VerificationPolicy,
    endpoints: Vec<(ShardId, C)>,
    /// Index into `endpoints` of each shard (canonical order), `None` if unconfigured.
    endpoint_by_shard: Vec<Option<usize>>,
    clock: K,
    executor: X,
}

impl<C, K, X> core::fmt::Debug for ProofClient<C, K, X> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProofClient")
            .field("partition_id", &self.config.partition_id)
            .field("shards", &self.router.shards().len())
            .field("endpoints", &self.endpoints.len())
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "std")]
impl<C: BatchAggregatorClient + Sync> ProofClient<C, SystemClock, ThreadedExecutor> {
    /// A client with the host clock and at most `max_parallel` concurrent
    /// requests in the exact-root wave.
    pub fn with_host_defaults(
        config: ProofClientConfig,
        endpoints: Vec<(ShardId, C)>,
        trust_base: RootTrustBase,
        max_parallel: usize,
    ) -> Result<Self, ConsolidationError> {
        Self::new(
            config,
            endpoints,
            trust_base,
            SystemClock::new(),
            ThreadedExecutor::new(max_parallel),
        )
    }
}

impl<C: BatchAggregatorClient + Sync, K: Clock, X: WaveExecutor> ProofClient<C, K, X> {
    /// Create a client. `endpoints` maps shards of the trusted topology to their
    /// configured (never token- or response-supplied) aggregators; shards
    /// without an endpoint can not be consolidated.
    pub fn new(
        config: ProofClientConfig,
        endpoints: Vec<(ShardId, C)>,
        trust_base: RootTrustBase,
        clock: K,
        executor: X,
    ) -> Result<Self, ConsolidationError> {
        let cfg = |m: &str| ConsolidationError::Configuration(m.to_string());
        trust_base
            .validate()
            .map_err(|_| cfg("invalid trust base"))?;
        if config.partition_id == 0 {
            return Err(cfg("partition id is zero"));
        }
        let router = ShardRouter::new(&config.topology)
            .map_err(|e| ConsolidationError::Configuration(e.to_string()))?;
        for (i, (shard, _)) in endpoints.iter().enumerate() {
            if !router.shards().contains(shard) {
                return Err(cfg("endpoint shard is not in the topology"));
            }
            if endpoints[..i].iter().any(|(s, _)| s == shard) {
                return Err(cfg("duplicate endpoint for a shard"));
            }
        }
        let endpoint_by_shard = router
            .shards()
            .iter()
            .map(|s| endpoints.iter().position(|(e, _)| e == s))
            .collect();
        Ok(Self {
            config,
            router,
            trust_base,
            registry: MintJustificationRegistry::new(),
            policy: VerificationPolicy::default(),
            endpoints,
            endpoint_by_shard,
            clock,
            executor,
        })
    }

    /// Use `registry` and `policy` for the complete verification of the input
    /// and output tokens (for example payment or split justification verifiers).
    pub fn with_verification(
        mut self,
        registry: MintJustificationRegistry,
        policy: VerificationPolicy,
    ) -> Self {
        self.registry = registry;
        self.policy = policy;
        self
    }

    /// Consolidate `token`'s outer-history proofs under one seal.
    ///
    /// The input is borrowed and never modified; success returns an owned token
    /// that passed complete verification. Failure and unavailability leave the
    /// caller with its original token, which this call does not vouch for
    /// beyond having verified it first.
    pub fn consolidate(
        &self,
        token: &Token,
        options: &ConsolidateOptions,
    ) -> Result<ConsolidationOutcome, ConsolidationError> {
        let budget = Budget {
            clock: &self.clock,
            deadline_ms: self.clock.now_ms().saturating_add(options.timeout_ms),
            cancel: &options.cancel,
            abort: CancelToken::new(),
        };
        // a cancelled or already-expired attempt must not pay for the input verification
        budget.check().map_err(stop_error)?;
        // one operation, one seal session: what the input verification authenticated is
        // not authenticated again by the consolidation steps
        let (input_check, mut session) = verify_token_in_session(
            token,
            SealSession::new(&self.trust_base),
            &self.registry,
            self.policy,
        );
        input_check.map_err(ConsolidationError::InvalidToken)?;
        let input_quorum_checks = session.stats().quorum_checks;

        let outer = outer_proofs(token);
        let items: Vec<ProofItem> = outer
            .iter()
            .map(|o| ProofItem {
                state_id: o.state_id.clone(),
                proof: o.proof.clone(),
            })
            .collect();
        let bundle = match self.run(&items, options.master.as_ref(), &budget, &mut session, true) {
            Ok(b) => b,
            Err(Stop::Unavailable(reason, retryable)) => {
                return Ok(ConsolidationOutcome::Unavailable { reason, retryable })
            }
            Err(Stop::Error(e)) => return Err(e),
        };

        let mut summary = bundle.summary;
        summary.input_quorum_checks = input_quorum_checks;
        if summary.already_shared {
            summary.verification_quorum_checks = input_quorum_checks;
            return Ok(ConsolidationOutcome::Consolidated {
                token: token.clone(),
                summary,
            });
        }
        let rebuilt = rebuild_token(token, bundle.proofs)
            .map_err(|m| ConsolidationError::Configuration(m.to_string()))?;
        let (check, stats) =
            verify_token_with_seal_stats(&rebuilt, &self.trust_base, &self.registry, self.policy);
        check.map_err(|e| ConsolidationError::Integrity(IntegrityError::Verification(e)))?;
        // never publish success for an attempt that is already over
        budget.check().map_err(stop_error)?;
        summary.verification_quorum_checks = stats.quorum_checks;
        Ok(ConsolidationOutcome::Consolidated {
            token: rebuilt,
            summary,
        })
    }

    /// Consolidate loose `(state, original proof)` pairs into a proof bundle
    /// (the Go reference's output semantics: authenticated replacement proofs,
    /// not a verified token). Prefer [`consolidate`](Self::consolidate).
    pub fn consolidate_proofs(
        &self,
        items: &[ProofItem],
        options: &ConsolidateOptions,
    ) -> Result<BundleOutcome, ConsolidationError> {
        let budget = Budget {
            clock: &self.clock,
            deadline_ms: self.clock.now_ms().saturating_add(options.timeout_ms),
            cancel: &options.cancel,
            abort: CancelToken::new(),
        };
        let mut session = SealSession::new(&self.trust_base);
        match self.run(items, options.master.as_ref(), &budget, &mut session, false) {
            Ok(bundle) => Ok(BundleOutcome::Consolidated(bundle)),
            Err(Stop::Unavailable(reason, retryable)) => {
                Ok(BundleOutcome::Unavailable { reason, retryable })
            }
            Err(Stop::Error(e)) => Err(e),
        }
    }

    /// Admit the input: bound it, route every input once (binary search over the
    /// sorted scheme), deduplicate state ids through an ordered index (O(L log L),
    /// not a rescan per item), group distinct states by shard index and enforce the
    /// per-shard limit as soon as it is exceeded, with periodic deadline and
    /// cancellation checks. Returns the participating groups (canonical shard
    /// order, distinct states only), for every input the index of the first input
    /// with the same state id, and for every input its shard index.
    fn group(
        &self,
        items: &[ProofItem],
        budget: &Budget<'_, K>,
        work: &mut AdmissionWork,
    ) -> Res<(Vec<Group>, Vec<usize>, Vec<usize>)> {
        let cfg = |m: &str| Stop::Error(ConsolidationError::Configuration(m.to_string()));
        if items.is_empty() {
            return Err(cfg("nothing to consolidate"));
        }
        // more distinct states than every endpoint's batches could carry (duplicates are
        // sent once, so they do not count)
        let cap = self.endpoints.len().saturating_mul(MAX_BATCH_STATE_IDS);
        let mut seen: BTreeMap<[u8; 32], usize> = BTreeMap::new();
        let mut first_of = Vec::with_capacity(items.len());
        let mut shard_of = Vec::with_capacity(items.len());
        let mut slots: Vec<Option<Group>> = (0..self.router.shards().len()).map(|_| None).collect();
        for (i, item) in items.iter().enumerate() {
            if i % 64 == 0 {
                budget.check()?;
            }
            work.steps += 1;
            let si = self
                .router
                .route_index_counted(&item.state_id, &mut work.route_comparisons);
            shard_of.push(si);
            if let Some(&first) = seen.get(item.state_id.bytes()) {
                let o = &items[first].proof;
                if o.certification_data != item.proof.certification_data
                    || o.reference_time != item.proof.reference_time
                {
                    return Err(cfg("conflicting inputs for one state id"));
                }
                first_of.push(first);
                continue;
            }
            seen.insert(*item.state_id.bytes(), i);
            if seen.len() > cap {
                return Err(Stop::Error(ConsolidationError::TooManyStates {
                    shard: self.router.shards()[si].clone(),
                    count: seen.len(),
                    limit: cap,
                }));
            }
            first_of.push(i);
            work.group_lookups += 1; // one array index per distinct state
            if slots[si].is_none() {
                let endpoint = self.endpoint_by_shard[si]
                    .ok_or_else(|| cfg("no configured endpoint serves a state of the token"))?;
                slots[si] = Some(Group {
                    endpoint,
                    shard: self.router.shards()[si].clone(),
                    items: Vec::new(),
                    ids: Vec::new(),
                });
            }
            let g = slots[si].as_mut().expect("just ensured");
            g.items.push(i);
            g.ids.push(item.state_id.clone());
            if g.ids.len() > MAX_BATCH_STATE_IDS {
                return Err(Stop::Error(ConsolidationError::TooManyStates {
                    shard: g.shard.clone(),
                    count: g.ids.len(),
                    limit: MAX_BATCH_STATE_IDS,
                }));
            }
        }
        // shard indexes are canonical order already
        Ok((slots.into_iter().flatten().collect(), first_of, shard_of))
    }

    fn fetch(
        endpoints: &[(ShardId, C)],
        group: &Group,
        root: StateRoot,
        budget: &Budget<'_, K>,
        requests: &AtomicUsize,
    ) -> Res<InclusionProofBatch> {
        let remaining = budget.check()?;
        let (shard, client) = &endpoints[group.endpoint];
        requests.fetch_add(1, Ordering::SeqCst);
        let result = client.get_inclusion_proofs(
            &BatchRequest {
                state_ids: &group.ids,
                state_root: root,
            },
            &RequestOptions {
                timeout_ms: remaining,
            },
        );
        // a done attempt never turns a late response into success or a
        // misleading transport error
        let after = budget.check();
        match result {
            Ok(batch) => {
                after?;
                Ok(batch)
            }
            Err(failure) => {
                after?;
                Err(classify(shard, failure))
            }
        }
    }

    /// Checks of a batch response against the original inputs of its shard.
    fn check_batch(
        group: &Group,
        items: &[ProofItem],
        batch: &InclusionProofBatch,
        exact: Option<&[u8; 32]>,
    ) -> Res<()> {
        let bad = |what| {
            Stop::Error(ConsolidationError::InvalidResponse {
                shard: group.shard.clone(),
                what,
            })
        };
        if batch.proofs.len() != group.items.len() {
            return Err(bad("proof count differs from the request"));
        }
        if exact.is_some() && batch.partition_view.is_some() {
            return Err(bad("exact-root response carries a partition view"));
        }
        let first = &batch.proofs[0].proof.unicity_certificate;
        for (k, (&idx, served)) in group.items.iter().zip(&batch.proofs).enumerate() {
            let original = &items[idx].proof;
            let binding = |what| {
                Stop::Error(ConsolidationError::Integrity(IntegrityError::Binding {
                    shard: group.shard.clone(),
                    index: k,
                    what,
                }))
            };
            if served.proof.certification_data != original.certification_data {
                return Err(binding("certification data differs from the original"));
            }
            if served.proof.reference_time != original.reference_time {
                return Err(binding("reference time differs from the original"));
            }
            if &served.proof.unicity_certificate != first {
                return Err(bad("proofs of one batch carry different certificates"));
            }
        }
        if let Some(root) = exact {
            if first.input_record.hash.as_deref() != Some(root.as_slice()) {
                return Err(Stop::Error(ConsolidationError::Integrity(
                    IntegrityError::RootSubstitution {
                        shard: group.shard.clone(),
                    },
                )));
            }
        }
        Ok(())
    }

    fn run(
        &self,
        items: &[ProofItem],
        master: Option<&ShardId>,
        budget: &Budget<'_, K>,
        session: &mut SealSession<'_>,
        verified: bool,
    ) -> Res<ProofBundle> {
        let cfg = |m: &str| Stop::Error(ConsolidationError::Configuration(m.to_string()));
        let base_quorum = session.stats().quorum_checks;
        let mut work = AdmissionWork::default();
        let (groups, first_of, shard_of) = self.group(items, budget, &mut work)?;
        budget.check()?;

        // the evidence must belong to the configured partition and shards (and match the
        // optional pins) before it can bound anything or be reused
        let context = |what| {
            Stop::Error(ConsolidationError::Integrity(IntegrityError::Context {
                what,
            }))
        };
        for (item, &si) in items.iter().zip(&shard_of) {
            let uc = &item.proof.unicity_certificate;
            if uc.unicity_tree_certificate.partition_identifier != self.config.partition_id {
                return Err(context("proof is of another partition"));
            }
            let shard = &uc.shard_tree_certificate.shard;
            if shard != &self.router.shards()[si] {
                return Err(context(
                    "proof is of another shard than the state routes to",
                ));
            }
            if self
                .config
                .topology
                .shard_conf_hash(shard)
                .is_some_and(|pin| pin.as_slice() != uc.shard_configuration_hash.as_slice())
            {
                return Err(context("proof's shard configuration differs from the pin"));
            }
        }

        // the original evidence, authenticated: the only source of the bound
        let routed: Vec<(&InclusionProof, usize)> = items
            .iter()
            .map(|i| &i.proof)
            .zip(shard_of.iter().copied())
            .collect();
        if !verified {
            for item in items {
                verify_membership_in(
                    session,
                    &item.proof,
                    &item.state_id,
                    item.proof.reference_time,
                )
                .map_err(|e| {
                    Stop::Error(ConsolidationError::Integrity(IntegrityError::Evidence(e)))
                })?;
            }
        }
        // (a verified token's proofs were authenticated by its complete verification)
        let bound = RootRoundBound::from_routed(&self.router, &routed)
            .map_err(|e| Stop::Error(ConsolidationError::Integrity(IntegrityError::Evidence(e))))?;
        budget.check()?;

        let before = distinct_seals(items.iter().map(|i| &i.proof));
        let mut summary = ConsolidationSummary {
            outer_proofs: items.len(),
            outer_seals_before: before,
            outer_seals_after: before,
            already_shared: false,
            shards: groups.len(),
            requests: 0,
            master: None,
            master_round: None,
            required_round: bound.round(),
            consolidation_quorum_checks: session.stats().quorum_checks - base_quorum,
            input_quorum_checks: 0,
            verification_quorum_checks: 0,
            certificates_derived: 0,
            admission: work,
        };
        if before == 1 {
            // Already under one seal. Reuse is only sound when that shared seal is also
            // acceptable *as a consolidation target*: the fixed authority's network, exact
            // epoch and start, and the configured policy. Otherwise fall through to fetch
            // a target that is.
            let policy = view_policy(self.config.partition_id, Some(&self.config.topology));
            let seal = &items[0].proof.unicity_certificate.unicity_seal;
            if session.authenticate_seal_under(seal, &policy).is_ok() {
                summary.already_shared = true;
                summary.consolidation_quorum_checks = session.stats().quorum_checks - base_quorum;
                return Ok(ProofBundle {
                    proofs: items.iter().map(|i| i.proof.clone()).collect(),
                    summary,
                });
            }
        }

        let master_shard = master.unwrap_or_else(|| bound.shard());
        let mi = groups
            .iter()
            .position(|g| &g.shard == master_shard)
            .ok_or_else(|| cfg("the master shard does not participate"))?;
        let requests = AtomicUsize::new(0);

        // wave 1: the master's latest batch and partition view
        let mg = &groups[mi];
        let mbatch = Self::fetch(&self.endpoints, mg, StateRoot::Latest, budget, &requests)?;
        Self::check_batch(mg, items, &mbatch, None)?;
        let enclosing = &mbatch.proofs[0].proof.unicity_certificate;
        let Some(view) = &mbatch.partition_view else {
            // No view. Only an unsharded certificate (empty shard id) needs none; a
            // sharded partition without its view stays unavailable.
            if enclosing.shard_tree_certificate.shard.length() != 0 {
                return Err(Stop::Unavailable(
                    UnavailableReason::PartitionViewUnavailable,
                    true,
                ));
            }
            return self.run_direct(
                items,
                &groups,
                mi,
                &first_of,
                &mbatch,
                &bound,
                budget,
                session,
                summary,
                &requests,
                base_quorum,
            );
        };
        let authenticated = view
            .authenticate(
                enclosing,
                self.config.partition_id,
                Some(&self.config.topology),
                session,
            )
            .map_err(|e| Stop::Error(ConsolidationError::Integrity(IntegrityError::View(e))))?;
        let master_round = authenticated.seal().root_chain_round_number;
        if master_round < bound.round() {
            // a genuinely signed older snapshot: publication lag, not forgery
            return Err(Stop::Unavailable(
                UnavailableReason::TargetNotYetAvailable,
                true,
            ));
        }
        budget.check()?;

        // master first: its own leaves are verified against the authenticated target
        // before any peer is contacted, so a bad master proof is an integrity error
        // and can never hide behind a peer's unavailability
        let mut replaced: Vec<Option<InclusionProof>> = alloc::vec![None; items.len()];
        // only the participating shards' certificates are derived (m of S, lazily)
        let mut derived = 0usize;
        let mut place =
            |g: &Group, batch: &InclusionProofBatch, session: &mut SealSession<'_>| -> Res<()> {
                derived += 1;
                let shard_cert = authenticated.certificate_of(&g.shard).map_err(|e| {
                    Stop::Error(ConsolidationError::Integrity(IntegrityError::View(e)))
                })?;
                let cert = shard_cert.certificate.as_ref().ok_or(Stop::Error(
                    ConsolidationError::Integrity(IntegrityError::Certificate {
                        shard: g.shard.clone(),
                        what: "no ordinary certificate for a shard holding proofs",
                    }),
                ))?;
                for (k, (&idx, served)) in g.items.iter().zip(&batch.proofs).enumerate() {
                    let p = replacement_proof(&items[idx].proof, &served.proof, cert).map_err(
                        |what| {
                            Stop::Error(ConsolidationError::Integrity(IntegrityError::Binding {
                                shard: g.shard.clone(),
                                index: k,
                                what,
                            }))
                        },
                    )?;
                    verify_membership_under(
                        session,
                        &p,
                        &items[idx].state_id,
                        p.reference_time,
                        authenticated.policy(),
                    )
                    .map_err(|e| {
                        Stop::Error(ConsolidationError::Integrity(IntegrityError::Verification(
                            e,
                        )))
                    })?;
                    replaced[idx] = Some(p);
                }
                Ok(())
            };
        place(mg, &mbatch, session)?;

        // wave 2: the exact roots the authenticated view names, bounded parallel
        struct Job<'g> {
            group: &'g Group,
            root: [u8; 32],
        }
        let mut jobs = Vec::new();
        for (gi, g) in groups.iter().enumerate() {
            if gi == mi {
                continue;
            }
            let leaf = authenticated
                .leaf_of(&g.shard)
                .ok_or_else(|| cfg("the authenticated view lacks a participating shard"))?;
            let root: [u8; 32] = leaf
                .input_record
                .hash
                .as_deref()
                .and_then(|h| h.try_into().ok())
                .ok_or(Stop::Error(ConsolidationError::Integrity(
                    IntegrityError::Certificate {
                        shard: g.shard.clone(),
                        what: "participating shard has no certified state root in the view",
                    },
                )))?;
            jobs.push(Job { group: g, root });
        }
        let endpoints = &self.endpoints[..];
        let wave: Vec<Res<InclusionProofBatch>> = self.executor.run(&jobs, &|job: &Job<'_>| {
            let r = Self::fetch(
                endpoints,
                job.group,
                StateRoot::Exact(job.root),
                budget,
                &requests,
            );
            if r.is_err() {
                budget.abort.cancel();
            }
            r
        });
        // a caller-implemented executor must return exactly one result per job
        if wave.len() != jobs.len() {
            return Err(Stop::Error(ConsolidationError::Configuration(
                "the wave executor returned a different number of results than jobs".to_string(),
            )));
        }
        // report the originating failure rather than the cancellations it caused
        let mut batches = Vec::with_capacity(wave.len());
        let mut first_stop: Option<Stop> = None;
        for r in wave {
            match r {
                Ok(b) => batches.push(b),
                Err(stop) => {
                    let is_cancel = matches!(
                        &stop,
                        Stop::Error(ConsolidationError::Cancelled | ConsolidationError::Timeout)
                    );
                    match &first_stop {
                        None => first_stop = Some(stop),
                        Some(Stop::Error(
                            ConsolidationError::Cancelled | ConsolidationError::Timeout,
                        )) if !is_cancel => first_stop = Some(stop),
                        _ => {}
                    }
                }
            }
        }
        if let Some(stop) = first_stop {
            // a caller cancellation still wins over what it interrupted
            if options_cancelled(budget) {
                return Err(ConsolidationError::Cancelled.into());
            }
            return Err(stop);
        }
        budget.check()?;

        // the peers' proofs are verified against the authenticated target as they are placed
        for (job, batch) in jobs.iter().zip(&batches) {
            Self::check_batch(job.group, items, batch, Some(&job.root))?;
            place(job.group, batch, session)?;
        }
        // every input gets the replacement of its (first) state
        let proofs: Vec<InclusionProof> = first_of
            .iter()
            .map(|&f| {
                replaced[f]
                    .clone()
                    .expect("every state belongs to exactly one participating shard")
            })
            .collect();
        budget.check()?;

        summary.outer_seals_after = distinct_seals(&proofs);
        summary.requests = requests.load(Ordering::SeqCst);
        summary.certificates_derived = derived;
        summary.master = Some(mg.shard.clone());
        summary.master_round = Some(master_round);
        summary.consolidation_quorum_checks = session.stats().quorum_checks - base_quorum;
        Ok(ProofBundle { proofs, summary })
    }

    /// The unsharded latest batch without a view: the batch's common certificate
    /// is the target (see [`DirectTarget`]). One request, no peers, no derivation.
    #[allow(clippy::too_many_arguments)]
    fn run_direct(
        &self,
        items: &[ProofItem],
        groups: &[Group],
        mi: usize,
        first_of: &[usize],
        mbatch: &InclusionProofBatch,
        bound: &RootRoundBound,
        budget: &Budget<'_, K>,
        session: &mut SealSession<'_>,
        mut summary: ConsolidationSummary,
        requests: &AtomicUsize,
        base_quorum: u64,
    ) -> Res<ProofBundle> {
        let mg = &groups[mi];
        let context = |what| {
            Stop::Error(ConsolidationError::Integrity(IntegrityError::Context {
                what,
            }))
        };
        // an unsharded certificate is only meaningful for an unsharded configuration
        // routed to one group; anything else contradicts the trusted topology
        if self.router.shards().len() != 1 || mg.shard.length() != 0 || groups.len() != 1 {
            return Err(context("unsharded certificate for a sharded configuration"));
        }
        let enclosing = &mbatch.proofs[0].proof.unicity_certificate;
        let target = DirectTarget::authenticate(
            enclosing,
            self.config.partition_id,
            &self.config.topology,
            session,
        )
        .map_err(|e| Stop::Error(ConsolidationError::Integrity(e)))?;
        let master_round = target.certificate().unicity_seal.root_chain_round_number;
        if master_round < bound.round() {
            // a genuinely signed older snapshot: publication lag, not forgery
            return Err(Stop::Unavailable(
                UnavailableReason::TargetNotYetAvailable,
                true,
            ));
        }
        budget.check()?;

        let mut replaced: Vec<Option<InclusionProof>> = alloc::vec![None; items.len()];
        for (k, (&idx, served)) in mg.items.iter().zip(&mbatch.proofs).enumerate() {
            let p = replacement_proof(&items[idx].proof, &served.proof, target.certificate())
                .map_err(|what| {
                    Stop::Error(ConsolidationError::Integrity(IntegrityError::Binding {
                        shard: mg.shard.clone(),
                        index: k,
                        what,
                    }))
                })?;
            verify_membership_under(
                session,
                &p,
                &items[idx].state_id,
                p.reference_time,
                target.policy(),
            )
            .map_err(|e| {
                Stop::Error(ConsolidationError::Integrity(IntegrityError::Verification(
                    e,
                )))
            })?;
            replaced[idx] = Some(p);
        }
        let proofs: Vec<InclusionProof> = first_of
            .iter()
            .map(|&f| {
                replaced[f]
                    .clone()
                    .expect("every state belongs to the one participating shard")
            })
            .collect();
        budget.check()?;

        summary.outer_seals_after = distinct_seals(&proofs);
        summary.requests = requests.load(Ordering::SeqCst);
        summary.certificates_derived = 0;
        summary.master = Some(mg.shard.clone());
        summary.master_round = Some(master_round);
        summary.consolidation_quorum_checks = session.stats().quorum_checks - base_quorum;
        Ok(ProofBundle { proofs, summary })
    }
}

fn options_cancelled<K: Clock>(budget: &Budget<'_, K>) -> bool {
    budget.cancel.is_cancelled()
}

fn stop_error(stop: Stop) -> ConsolidationError {
    match stop {
        Stop::Error(e) => e,
        Stop::Unavailable(..) => ConsolidationError::Cancelled,
    }
}

/// Type a failed batch call. Operational failures keep their own types;
/// "unavailable" is reserved for the specified material/pressure outcomes.
fn classify(shard: &ShardId, failure: BatchFailure) -> Stop {
    let shard = shard.clone();
    match &failure {
        BatchFailure::Timeout => Stop::Error(ConsolidationError::Timeout),
        BatchFailure::Cancelled => Stop::Error(ConsolidationError::Cancelled),
        BatchFailure::Transport(_) | BatchFailure::Http { .. } | BatchFailure::TooLarge { .. } => {
            Stop::Error(ConsolidationError::Transport { shard, failure })
        }
        BatchFailure::Decode(_) => Stop::Error(ConsolidationError::InvalidResponse {
            shard,
            what: "undecodable response",
        }),
        BatchFailure::Rpc {
            code,
            detail,
            retryable,
            ..
        } => match *code {
            rpc_code::METHOD_NOT_FOUND => {
                Stop::Unavailable(UnavailableReason::UnsupportedCapability, false)
            }
            rpc_code::CONCURRENCY_LIMIT => Stop::Unavailable(UnavailableReason::Busy, true),
            rpc_code::PROOF_UNAVAILABLE => {
                let retry = retryable.unwrap_or(true);
                match detail.as_deref() {
                    Some("unsupported_configuration") => {
                        Stop::Unavailable(UnavailableReason::UnsupportedConfiguration, false)
                    }
                    Some(detail::STATE_PENDING) => Stop::Unavailable(
                        UnavailableReason::StatePending,
                        retryable.unwrap_or(true),
                    ),
                    Some(detail::STATE_EXPIRED) => {
                        Stop::Unavailable(UnavailableReason::StateExpired, false)
                    }
                    Some(detail::STATE_UNKNOWN) => {
                        Stop::Unavailable(UnavailableReason::StateUnknown, false)
                    }
                    Some(detail::STATE_NOT_IN_ROOT) => {
                        Stop::Unavailable(UnavailableReason::StateNotInRoot, false)
                    }
                    Some("view_not_retained") => {
                        Stop::Unavailable(UnavailableReason::TargetNotRetained, retry)
                    }
                    Some("partition_view_unavailable") => {
                        Stop::Unavailable(UnavailableReason::PartitionViewUnavailable, retry)
                    }
                    _ => Stop::Unavailable(UnavailableReason::TargetNotYetAvailable, retry),
                }
            }
            rpc_code::INVALID_PARAMS | rpc_code::INVALID_REQUEST | rpc_code::LIMIT_EXCEEDED => {
                Stop::Error(ConsolidationError::Rejected { shard, failure })
            }
            // database, internal and unknown codes are operational failures
            _ => Stop::Error(ConsolidationError::Server { shard, failure }),
        },
    }
}
