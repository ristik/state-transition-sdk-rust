//! Shared configuration of the consolidation examples.
//!
//! Network configuration is explicit and local: nothing is learned from a token
//! or from an aggregator response.
//!
//! | Variable | Meaning |
//! |---|---|
//! | `UNICITY_TRUSTBASE` | path of the root trust base JSON (default `e2e/bft-trustbase.testnet2.json`) |
//! | `UNICITY_PARTITION_ID` | the partition number |
//! | `UNICITY_SHARD_ENDPOINTS` | `bits=url` pairs, comma separated, e.g. `00=https://a/,01=https://b/,10=...,11=...`; one shard: `=https://a/` |
//! | `UNICITY_API_KEY` | optional API key (HTTPS only) |

use unicity_token::api::bft::{RootTrustBase, ShardId};
use unicity_token::client::{HttpAggregatorClient, ProofClient, ProofClientConfig};
use unicity_token::client::{SystemClock, ThreadedExecutor};
use unicity_token::consolidation::PartitionTopology;

fn shard(bits: &str) -> ShardId {
    let mut id = ShardId::root();
    for c in bits.chars() {
        let (zero, one) = id.split();
        id = if c == '0' { zero } else { one };
    }
    id
}

pub type Client = ProofClient<HttpAggregatorClient, SystemClock, ThreadedExecutor>;

/// Build the trust base and the proof client from the environment.
pub fn load() -> (RootTrustBase, Client) {
    dotenvy::from_path("e2e/.env").ok();
    let trustbase = std::env::var("UNICITY_TRUSTBASE")
        .unwrap_or_else(|_| "e2e/bft-trustbase.testnet2.json".into());
    let trust_base = RootTrustBase::from_json(
        &std::fs::read_to_string(&trustbase).unwrap_or_else(|e| panic!("read {trustbase}: {e}")),
    )
    .expect("parse trust base");

    let partition_id: u32 = std::env::var("UNICITY_PARTITION_ID")
        .expect("UNICITY_PARTITION_ID")
        .parse()
        .expect("partition id");
    let spec = std::env::var("UNICITY_SHARD_ENDPOINTS").expect("UNICITY_SHARD_ENDPOINTS");
    let mut endpoints = Vec::new();
    for pair in spec.split(',') {
        let (bits, url) = pair.split_once('=').expect("bits=url");
        let mut http = HttpAggregatorClient::try_new(url.trim()).expect("https endpoint");
        if let Ok(key) = std::env::var("UNICITY_API_KEY") {
            http = http.with_api_key(key);
        }
        endpoints.push((shard(bits.trim()), http));
    }
    // the trusted scheme: the configured shards (a single empty id is the unsharded partition)
    let scheme = if endpoints.len() == 1 && endpoints[0].0.length() == 0 {
        Vec::new()
    } else {
        endpoints.iter().map(|(s, _)| s.clone()).collect()
    };
    let client = ProofClient::with_host_defaults(
        ProofClientConfig {
            partition_id,
            topology: PartitionTopology::new(scheme),
        },
        endpoints,
        trust_base.clone(),
        4, // at most four concurrent exact-root requests
    )
    .expect("proof client");
    (trust_base, client)
}
