//! Consumer of the shared Go fixture corpus `testdata/uc-consolidation/v1`
//! (aggregator-go PR 195, branch `uc/F1-fixtures`; see `PROVENANCE.txt`).
//!
//! Scope: the PartitionView / UC-assembly parts of the corpus. The reference's
//! expected certificates (`ucs/*.cbor`) are re-derived from the case's partition
//! view plus one of them as the enclosing certificate, under the case's trust
//! base, and must be byte-identical. The negative `view-*` and `trust-base-*`
//! cases must be refused. RPC/evidence-stage cases await the batch client.

use std::fs;
use std::path::PathBuf;

use unicity_token::api::bft::root_trust_base::RootTrustBaseNodeInfo;
use unicity_token::api::bft::{RootTrustBase, ShardId, UnicityCertificate};
use unicity_token::api::NetworkId;
use unicity_token::cbor::Decoder;
use unicity_token::consolidation::{
    PartitionTopology, PartitionView, PartitionViewError, ShardCertificate,
};
use unicity_token::crypto::signature::PublicKey;
use unicity_token::verify::{SealSession, VerificationError};

fn assemble(
    view: &PartitionView,
    enclosing: &UnicityCertificate,
    partition: u32,
    pins: Option<&PartitionTopology>,
    session: &mut SealSession<'_>,
) -> Result<Vec<ShardCertificate>, PartitionViewError> {
    view.authenticate(enclosing, partition, pins, session)?
        .certificates()
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/uc-consolidation/corpus-v1")
}

fn read(path: &str) -> Vec<u8> {
    fs::read(root().join(path)).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn text(path: &str) -> String {
    String::from_utf8(read(path)).unwrap()
}

fn number(json: &str, key: &str) -> u64 {
    let needle = format!("\"{key}\":");
    let start = json.find(&needle).expect("key present") + needle.len();
    let rest = json[start..].trim_start();
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap();
    rest[..end].parse().unwrap()
}

/// Quoted strings of the array under `key` (empty strings kept).
fn string_array(json: &str, key: &str) -> Vec<String> {
    let needle = format!("\"{key}\": [");
    let start = json.find(&needle).expect("key present") + needle.len();
    let end = json[start..].find(']').unwrap() + start;
    json[start..end]
        .split(',')
        .filter(|s| s.contains('"'))
        .map(|s| s.trim().trim_matches('"').to_string())
        .collect()
}

fn shard_from_bits(bits: &str) -> ShardId {
    let mut id = ShardId::root();
    for c in bits.chars() {
        let (zero, one) = id.split();
        id = if c == '0' { zero } else { one };
    }
    id
}

fn file_name(bits: &str) -> String {
    if bits.is_empty() {
        "root".into()
    } else {
        bits.into()
    }
}

/// `trust-base.cbor`: tag 39000 `[version, network, epoch, epochStart,
/// [[nodeId, sigKey, stake]...], threshold, ...]`.
fn trust_base(path: &str) -> RootTrustBase {
    let bytes = read(path);
    let items = Decoder::new(&bytes)
        .expect_tag(39000)
        .unwrap()
        .array(Some(10))
        .unwrap();
    let nodes = items[4]
        .array(None)
        .unwrap()
        .into_iter()
        .map(|n| {
            let f = n.array(Some(3)).unwrap();
            RootTrustBaseNodeInfo {
                node_id: f[0].text().unwrap().into(),
                signing_key: PublicKey::from_bytes(f[1].bytes_value().unwrap()).unwrap(),
                stake: f[2].uint().unwrap(),
            }
        })
        .collect();
    RootTrustBase::try_new(
        items[0].uint().unwrap(),
        NetworkId::new(items[1].uint().unwrap() as u16).unwrap(),
        items[2].uint().unwrap(),
        items[3].uint().unwrap(),
        nodes,
        items[5].uint().unwrap(),
    )
    .unwrap()
}

struct Case {
    partition: u32,
    shards: Vec<String>,
    topology: PartitionTopology,
}

fn case(dir: &str) -> Case {
    let context = text(&format!("{dir}/context.json"));
    let shards = string_array(&context, "shards");
    let hashes: Vec<[u8; 32]> = context
        .match_indices("\"hash\": \"")
        .map(|(i, m)| {
            let h = &context[i + m.len()..];
            hex::decode(&h[..64]).unwrap().try_into().unwrap()
        })
        .collect();
    assert_eq!(hashes.len(), shards.len());
    let ids: Vec<ShardId> = shards.iter().map(|s| shard_from_bits(s)).collect();
    let mut topology = PartitionTopology::new(if ids.len() == 1 { vec![] } else { ids.clone() });
    for (id, h) in ids.iter().zip(hashes) {
        topology = topology.with_shard_conf_hash(id, h);
    }
    Case {
        partition: number(&context, "partitionId") as u32,
        shards,
        topology,
    }
}

/// A reference certificate of the case that the SDK can hold, as the enclosing
/// certificate (every shard's certificate carries the same master seal).
fn enclosing(dir: &str, shards: &[String]) -> UnicityCertificate {
    shards
        .iter()
        .find_map(|s| {
            UnicityCertificate::from_cbor(Decoder::new(&read(&format!(
                "{dir}/ucs/{}.cbor",
                file_name(s)
            ))))
            .ok()
        })
        .expect("a participating shard")
}

const POSITIVE: [&str; 6] = [
    "shards-1",
    "shards-4",
    "shards-8",
    "shards-4-timeout-unchanged",
    "nil-vs-empty",
    "large-values",
];

#[test]
fn positive_cases_assemble_the_reference_certificates() {
    let mut skipped = 0;
    for dir in POSITIVE {
        let c = case(dir);
        let tb = trust_base(&format!("{dir}/trust-base.cbor"));
        let view_bytes = read(&format!("{dir}/partition-view.cbor"));
        let view = PartitionView::from_cbor(&view_bytes).unwrap_or_else(|e| panic!("{dir}: {e}"));
        assert_eq!(
            view.to_cbor().unwrap(),
            view_bytes,
            "{dir}: canonical re-encoding"
        );

        let expected: Vec<Vec<u8>> = c
            .shards
            .iter()
            .map(|s| read(&format!("{dir}/ucs/{}.cbor", file_name(s))))
            .collect();
        let enclosing = enclosing(dir, &c.shards);

        let mut session = SealSession::new(&tb);
        let ucs = assemble(
            &view,
            &enclosing,
            c.partition,
            Some(&c.topology),
            &mut session,
        )
        .unwrap_or_else(|e| panic!("{dir}: {e}"));
        assert_eq!(ucs.len(), expected.len(), "{dir}");
        for (got, want) in ucs.iter().zip(&expected) {
            match &got.certificate {
                Some(uc) => assert_eq!(
                    &uc.to_cbor(),
                    want,
                    "{dir}: certificate equals the reference's"
                ),
                None => {
                    // a shard that never certified a state (all-null input record) has no
                    // ordinary Rust certificate; its path and the master parts must still
                    // be exactly the reference's
                    let tail = [
                        enclosing.unicity_tree_certificate.to_cbor(),
                        enclosing.unicity_seal.to_cbor(),
                    ]
                    .concat();
                    assert!(
                        want.ends_with(&tail),
                        "{dir}: partition path and master seal"
                    );
                    let path = got.shard_tree_certificate.to_cbor();
                    assert!(
                        want.windows(path.len()).any(|w| w == path.as_slice()),
                        "{dir}: shard path"
                    );
                    skipped += 1;
                }
            }
        }
        assert_eq!(
            session.stats().quorum_checks,
            1,
            "{dir}: one master quorum check"
        );
    }
    assert!(
        skipped > 0,
        "the corpus exercises shards without a certified state"
    );
}

fn base_of(neg: &str) -> String {
    let e = text(&format!("negative/{neg}/expected.json"));
    let i = e.find("\"base\": \"").unwrap() + 9;
    e[i..i + e[i..].find('"').unwrap()].to_string()
}

fn stage_of(neg: &str) -> String {
    let e = text(&format!("negative/{neg}/expected.json"));
    let i = e.find("\"stage\": \"").unwrap() + 10;
    e[i..i + e[i..].find('"').unwrap()].to_string()
}

#[test]
fn negative_view_cases_are_refused() {
    let mut checked = 0;
    for entry in fs::read_dir(root().join("negative")).unwrap() {
        let name = entry.unwrap().file_name().into_string().unwrap();
        if !name.starts_with("view-")
            || !root()
                .join(format!("negative/{name}/partition-view.cbor"))
                .exists()
        {
            continue;
        }
        let base = base_of(&name);
        let c = case(&base);
        let tb = trust_base(&format!("{base}/trust-base.cbor"));
        let enclosing = enclosing(&base, &c.shards);
        let bytes = read(&format!("negative/{name}/partition-view.cbor"));

        let decoded = PartitionView::from_cbor(&bytes);
        if stage_of(&name) == "view_codec" {
            assert!(decoded.is_err(), "{name}: the codec must reject it");
        }
        if let Ok(view) = decoded {
            let mut session = SealSession::new(&tb);
            let r = assemble(
                &view,
                &enclosing,
                c.partition,
                Some(&c.topology),
                &mut session,
            );
            assert!(r.is_err(), "{name}: assembly must be refused");
        }
        checked += 1;
    }
    assert!(checked >= 25, "corpus has the view-* cases ({checked})");
}

#[test]
fn other_authorities_do_not_authenticate_the_master_seal() {
    for (name, want) in [
        (
            "trust-base-other-authority",
            VerificationError::QuorumNotMet,
        ),
        (
            "trust-base-other-epoch",
            VerificationError::SealEpochMismatch,
        ),
        (
            "trust-base-other-network",
            VerificationError::SealNetworkMismatch,
        ),
    ] {
        let base = base_of(name);
        let c = case(&base);
        let tb = trust_base(&format!("negative/{name}/trust-base.cbor"));
        let view = PartitionView::from_cbor(&read(&format!("{base}/partition-view.cbor"))).unwrap();
        let enclosing = enclosing(&base, &c.shards);
        let mut session = SealSession::new(&tb);
        assert_eq!(
            assemble(
                &view,
                &enclosing,
                c.partition,
                Some(&c.topology),
                &mut session
            ),
            Err(PartitionViewError::Seal(want)),
            "{name}"
        );
    }
}
