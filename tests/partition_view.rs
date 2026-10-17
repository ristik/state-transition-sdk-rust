//! Conformance of the `PartitionViewV1` codec, native shard-tree reconstruction
//! and authenticated certificate assembly against the frozen Go reference.
//!
//! `tests/vectors/uc-consolidation/partition-view/v1/golden` are the reference's
//! own golden files (byte-for-byte); `derived` holds enclosing certificates,
//! trust bases and the certificates the reference derives from them. See that
//! directory's `manifest.json` for the provenance commit.

use unicity_token::api::bft::root_trust_base::RootTrustBaseNodeInfo;
use unicity_token::api::bft::unicity_tree::UNICITY_TREE_CERTIFICATE_TAG;
use unicity_token::api::bft::{RootTrustBase, ShardId, UnicityCertificate, UnicityTreeCertificate};
use unicity_token::api::NetworkId;
use unicity_token::cbor::{encode_array, encode_byte_string, encode_tag, encode_uint, Decoder};
use unicity_token::consolidation::{
    PartitionTopology, PartitionView, PartitionViewError, PartitionViewInputRecord,
    PartitionViewLeaf, ShardCertificate, MAX_PARTITION_VIEW_BYTES, MAX_PARTITION_VIEW_LEAVES,
};
use unicity_token::crypto::hash::sha256;
use unicity_token::crypto::signature::PublicKey;
use unicity_token::verify::{SealAuthenticator, SealSession, VerificationError};

macro_rules! vector {
    ($path:literal) => {
        include_bytes!(concat!(
            "vectors/uc-consolidation/partition-view/v1/",
            $path
        ))
    };
}

const GOLDEN_MANIFEST: &str =
    include_str!("vectors/uc-consolidation/partition-view/v1/golden/manifest.json");

/// Tiny extractor, as in the other vector tests: the string after `"key":`.
fn field<'a>(json: &'a str, key: &str) -> &'a str {
    let needle = format!("\"{key}\"");
    let start = json.find(&needle).expect("key present") + needle.len();
    let rest = &json[start..];
    let q1 = rest.find('"').expect("open quote") + 1;
    let q2 = rest[q1..].find('"').expect("close quote") + q1;
    &rest[q1..q2]
}

fn number(json: &str, key: &str) -> u64 {
    let needle = format!("\"{key}\":");
    let start = json.find(&needle).expect("key present") + needle.len();
    let rest = json[start..].trim_start();
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap();
    rest[..end].parse().unwrap()
}

fn strings(json: &str, key: &str) -> Vec<String> {
    let needle = format!("\"{key}\": [");
    let start = json.find(&needle).expect("key present") + needle.len();
    let end = json[start..].find(']').unwrap() + start;
    json[start..end]
        .split(',')
        .map(|s| s.trim().trim_matches('"').to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

struct Case {
    view_bytes: &'static [u8],
    view: PartitionView,
    uc: UnicityCertificate,
    topology: PartitionTopology,
    trust_base: RootTrustBase,
    partition: u32,
    expected_ucs: Vec<&'static [u8]>,
    tree_root: Vec<u8>,
}

fn case(n: usize) -> Case {
    let (context, tb_json, view_bytes, uc_bytes, expected_ucs): (
        &str,
        &str,
        &[u8],
        &[u8],
        Vec<&[u8]>,
    ) = match n {
        1 => (
            include_str!(
                "vectors/uc-consolidation/partition-view/v1/derived/shards-1/context.json"
            ),
            include_str!(
                "vectors/uc-consolidation/partition-view/v1/derived/shards-1/trust-base.json"
            ),
            vector!("derived/shards-1/view.cbor"),
            vector!("derived/shards-1/enclosing-uc.cbor"),
            vec![vector!("derived/shards-1/ucs/00.cbor")],
        ),
        4 => (
            include_str!(
                "vectors/uc-consolidation/partition-view/v1/derived/shards-4/context.json"
            ),
            include_str!(
                "vectors/uc-consolidation/partition-view/v1/derived/shards-4/trust-base.json"
            ),
            vector!("derived/shards-4/view.cbor"),
            vector!("derived/shards-4/enclosing-uc.cbor"),
            vec![
                vector!("derived/shards-4/ucs/00.cbor"),
                vector!("derived/shards-4/ucs/01.cbor"),
                vector!("derived/shards-4/ucs/02.cbor"),
                vector!("derived/shards-4/ucs/03.cbor"),
            ],
        ),
        8 => (
            include_str!(
                "vectors/uc-consolidation/partition-view/v1/derived/shards-8/context.json"
            ),
            include_str!(
                "vectors/uc-consolidation/partition-view/v1/derived/shards-8/trust-base.json"
            ),
            vector!("derived/shards-8/view.cbor"),
            vector!("derived/shards-8/enclosing-uc.cbor"),
            vec![
                vector!("derived/shards-8/ucs/00.cbor"),
                vector!("derived/shards-8/ucs/01.cbor"),
                vector!("derived/shards-8/ucs/02.cbor"),
                vector!("derived/shards-8/ucs/03.cbor"),
                vector!("derived/shards-8/ucs/04.cbor"),
                vector!("derived/shards-8/ucs/05.cbor"),
                vector!("derived/shards-8/ucs/06.cbor"),
                vector!("derived/shards-8/ucs/07.cbor"),
            ],
        ),
        _ => unreachable!(),
    };

    let shard_ids = strings(context, "shardIds");
    let conf_hashes = strings(context, "shardConfHashes");
    assert_eq!(shard_ids.len(), n);
    let mut ids = Vec::new();
    let mut topology_conf = Vec::new();
    for (id, conf) in shard_ids.iter().zip(&conf_hashes) {
        let id = ShardId::decode(&hex::decode(id).unwrap()).unwrap();
        let conf: [u8; 32] = hex::decode(conf).unwrap().try_into().unwrap();
        topology_conf.push((id.clone(), conf));
        ids.push(id);
    }
    let scheme = if n == 1 { Vec::new() } else { ids };
    let mut topology = PartitionTopology::new(scheme);
    for (id, conf) in topology_conf {
        topology = topology.with_shard_conf_hash(&id, conf);
    }

    let key = PublicKey::from_bytes(
        &hex::decode(field(tb_json, "sigKey").trim_start_matches("0x")).unwrap(),
    )
    .unwrap();
    let trust_base = RootTrustBase::try_new(
        number(tb_json, "version"),
        NetworkId::new(number(tb_json, "networkId") as u16).unwrap(),
        number(tb_json, "epoch"),
        number(tb_json, "epochStartRound"),
        vec![RootTrustBaseNodeInfo {
            node_id: field(tb_json, "nodeId").into(),
            signing_key: key,
            stake: number(tb_json, "stake"),
        }],
        number(tb_json, "quorumThreshold"),
    )
    .unwrap();

    Case {
        view_bytes,
        view: PartitionView::from_cbor(view_bytes).expect("reference view decodes"),
        uc: UnicityCertificate::from_cbor(Decoder::new(uc_bytes)).expect("enclosing UC decodes"),
        topology,
        trust_base,
        partition: number(context, "partitionId") as u32,
        expected_ucs,
        tree_root: hex::decode(field(context, "shardTreeRoot")).unwrap(),
    }
}

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

const CASES: [usize; 3] = [1, 4, 8];

// ---------------------------------------------------------------- codec ----

#[test]
fn golden_files_match_manifest_and_roundtrip_byte_for_byte() {
    let golden: [(usize, &[u8]); 3] = [
        (1, vector!("golden/shards-1.cbor")),
        (4, vector!("golden/shards-4.cbor")),
        (8, vector!("golden/shards-8.cbor")),
    ];
    for (n, bytes) in golden {
        let name = format!("shards-{n}.cbor");
        let expected = field(GOLDEN_MANIFEST, &name);
        assert_eq!(
            hex::encode(sha256(bytes).data()),
            expected,
            "{name} checksum"
        );
        let view = PartitionView::from_cbor(bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(view.leaves.len(), n);
        assert_eq!(
            view.partition_id as u64,
            number(GOLDEN_MANIFEST, "partitionId")
        );
        assert_eq!(
            view.to_cbor().unwrap(),
            bytes,
            "{name} re-encodes identically"
        );
    }
}

#[test]
fn derived_views_equal_the_frozen_golden_files() {
    assert_eq!(
        vector!("derived/shards-1/view.cbor"),
        vector!("golden/shards-1.cbor")
    );
    assert_eq!(
        vector!("derived/shards-4/view.cbor"),
        vector!("golden/shards-4.cbor")
    );
    assert_eq!(
        vector!("derived/shards-8/view.cbor"),
        vector!("golden/shards-8.cbor")
    );
}

fn minimal_view() -> PartitionView {
    PartitionView {
        partition_id: 1,
        leaves: vec![PartitionViewLeaf {
            shard_id: ShardId::root(),
            input_record: PartitionViewInputRecord {
                round_number: 0,
                epoch: 0,
                previous_hash: Some(vec![]),
                hash: Some(vec![]),
                summary_value: None,
                timestamp: 0,
                block_hash: None,
                sum_of_earned_fees: 0,
                executed_transactions_hash: None,
            },
            tr_hash: vec![1; 32],
            shard_conf_hash: vec![2; 32],
        }],
    }
}

/// The reference's frozen minimal view (`Test_PartitionView_Golden`): note the
/// null summary value, which the ordinary `InputRecord` can not represent.
#[test]
fn minimal_golden_bytes() {
    // [1, 1, [[h'80', #39002([1,0,0,h'',h'',null,0,null,0,null]), h'01..', h'02..']]]
    let expected = [
        "83", "01", "01", "81", "84", "4180", "d9985a", "8a", "01", "00", "00", "40", "40", "f6",
        "00", "f6", "00", "f6",
    ]
    .concat()
        + &format!("5820{}5820{}", "01".repeat(32), "02".repeat(32));
    let bytes = minimal_view().to_cbor().unwrap();
    assert_eq!(hex::encode(&bytes), expected);
    assert_eq!(PartitionView::from_cbor(&bytes).unwrap(), minimal_view());
}

#[test]
fn nil_and_empty_stay_distinct() {
    let mut a = minimal_view();
    a.leaves[0].input_record.block_hash = Some(vec![]);
    a.leaves[0].input_record.executed_transactions_hash = None;
    let mut b = a.clone();
    b.leaves[0].input_record.block_hash = None;
    b.leaves[0].input_record.executed_transactions_hash = Some(vec![]);
    let (ab, bb) = (a.to_cbor().unwrap(), b.to_cbor().unwrap());
    assert_ne!(ab, bb);
    assert_eq!(PartitionView::from_cbor(&ab).unwrap(), a);
    assert_eq!(PartitionView::from_cbor(&bb).unwrap(), b);
}

#[test]
fn strict_decode_rejections() {
    let good = vector!("golden/shards-4.cbor").to_vec();
    assert!(PartitionView::from_cbor(&good).is_ok());
    let reject = |name: &str, bytes: Vec<u8>| {
        assert!(
            PartitionView::from_cbor(&bytes).is_err(),
            "{name} must be rejected"
        );
    };

    let mut trailing = good.clone();
    trailing.push(0);
    reject("trailing bytes", trailing);
    reject("truncated", good[..good.len() - 1].to_vec());
    for b in [vec![], vec![0xf6], vec![0x80]] {
        reject("empty/null/empty array", b);
    }
    let mut v0 = good.clone();
    v0[1] = 0;
    assert_eq!(
        PartitionView::from_cbor(&v0).unwrap_err(),
        PartitionViewError::UnsupportedVersion(0),
        "version zero is never defaulted"
    );
    let mut v2 = good.clone();
    v2[1] = 2;
    assert_eq!(
        PartitionView::from_cbor(&v2).unwrap_err(),
        PartitionViewError::UnsupportedVersion(2)
    );
    let mut extra = vec![0x84];
    extra.extend_from_slice(&good[1..]);
    extra.push(0);
    reject("extra array item", extra);
    let mut indef = vec![0x9f];
    indef.extend_from_slice(&good[1..]);
    indef.push(0xff);
    reject("indefinite length", indef);
    let mut noncanonical = vec![0x83, 0x18, 0x01];
    noncanonical.extend_from_slice(&good[2..]);
    reject("two-byte version", noncanonical);
    // first leaf: 0x84 (array 4), 0x41 .. (shard id bstr 1)
    let leaf = good.windows(2).position(|w| w == [0x84, 0x41]).unwrap();
    let mut as_uint = good.clone();
    as_uint.splice(leaf + 1..leaf + 3, [0x01]);
    reject("shard id as number", as_uint);
    let mut no_marker = good.clone();
    no_marker[leaf + 2] = 0;
    reject("shard id without end marker", no_marker);
    reject("oversize", vec![0; MAX_PARTITION_VIEW_BYTES + 1]);
    reject(
        "huge declared array",
        vec![0x83, 0x01, 0x01, 0x9b, 0, 0, 0, 1, 0, 0, 0, 0],
    );
    let mut tagged = vec![0xd9, 0x9a, 0x5a];
    tagged.extend_from_slice(&good);
    reject("tagged view", tagged);
}

#[test]
fn bounds_are_enforced_on_encode_and_decode() {
    let ok = |mutate: &dyn Fn(&mut PartitionView)| {
        let mut v = minimal_view();
        v.leaves[0].input_record.summary_value = Some(vec![]);
        mutate(&mut v);
        v.to_cbor()
    };
    assert!(ok(&|_| {}).is_ok());
    assert!(ok(&|v| v.partition_id = 0).is_err());
    assert!(ok(&|v| v.leaves.clear()).is_err());
    assert!(ok(&|v| {
        let l = v.leaves[0].clone();
        v.leaves = vec![l; MAX_PARTITION_VIEW_LEAVES + 1];
    })
    .is_err());
    assert!(ok(&|v| v.leaves[0].tr_hash.truncate(31)).is_err());
    assert!(ok(&|v| v.leaves[0].tr_hash.clear()).is_err());
    assert!(ok(&|v| v.leaves[0].shard_conf_hash.push(0)).is_err());
    assert!(ok(&|v| v.leaves[0].input_record.hash = Some(vec![1])).is_err());
    assert!(
        ok(&|v| v.leaves[0].input_record.executed_transactions_hash = Some(vec![0; 31])).is_err()
    );
    assert!(ok(&|v| v.leaves[0].input_record.summary_value = Some(vec![0; 257])).is_err());
    assert!(ok(&|v| v.leaves[0].input_record.summary_value = Some(vec![0; 256])).is_ok());
    // state hash changed but block hash nil / unchanged but block hash set
    assert!(ok(&|v| {
        v.leaves[0].input_record.hash = Some(vec![7; 32]);
    })
    .is_err());
    assert!(ok(&|v| v.leaves[0].input_record.block_hash = Some(vec![7; 32])).is_err());
    // an assigned round needs a summary value and a timestamp
    assert!(ok(&|v| v.leaves[0].input_record.round_number = 1).is_err());
}

// ------------------------------------------------------------- topology ----

fn ids(strs: &[&str]) -> Vec<ShardId> {
    strs.iter()
        .map(|s| {
            let mut id = ShardId::root();
            for c in s.chars() {
                let (z, o) = id.split();
                id = if c == '0' { z } else { o };
            }
            id
        })
        .collect()
}

fn order(strs: &[&str]) -> Result<Vec<String>, PartitionViewError> {
    PartitionTopology::new(ids(strs))
        .canonical_order()
        .map(|o| o.iter().map(ShardId::to_bit_string).collect())
}

#[test]
fn canonical_shard_order() {
    assert_eq!(order(&[]).unwrap(), [""]);
    assert_eq!(
        order(&["11", "00", "10", "01"]).unwrap(),
        ["00", "01", "10", "11"]
    );
    assert_eq!(
        order(&["000", "001", "010", "011", "100", "101", "110", "111"])
            .unwrap()
            .len(),
        8
    );
    assert_eq!(order(&["11", "0", "10"]).unwrap(), ["0", "10", "11"]);
    assert!(order(&["0", "10"]).is_err(), "incomplete");
    assert!(order(&["00", "01", "10"]).is_err(), "incomplete");
    assert!(order(&["0", "1", "10"]).is_err(), "overlapping");
    assert!(order(&["0", "0", "1"]).is_err(), "duplicate");
    assert!(order(&["0"]).is_err(), "single item scheme");
    let nine = [
        "0000", "0001", "0010", "0011", "0100", "0101", "0110", "0111", "1",
    ];
    assert!(order(&nine).is_err(), "more shards than the view limit");
    let mut with_root = ids(&["0", "1"]);
    with_root.push(ShardId::root());
    assert!(PartitionTopology::new(with_root).canonical_order().is_err());
}

// ------------------------------------------------- tree and assembly ------

#[test]
fn rebuilt_tree_and_assembled_certificates_equal_the_reference() {
    for n in CASES {
        let c = case(n);
        let tree = c.view.build_shard_tree(c.partition, &c.topology).unwrap();
        assert_eq!(
            tree.root_hash(),
            c.tree_root.as_slice(),
            "{n} shards: shard tree root"
        );

        let mut session = SealSession::new(&c.trust_base);
        let ucs = assemble(&c.view, &c.uc, c.partition, Some(&c.topology), &mut session)
            .unwrap_or_else(|e| panic!("{n} shards: {e}"));
        assert_eq!(ucs.len(), n);
        for (i, (sc, expected)) in ucs.iter().zip(&c.expected_ucs).enumerate() {
            let uc = sc.certificate.as_ref().expect("representable record");
            assert_eq!(sc.shard_tree_certificate, uc.shard_tree_certificate);
            assert_eq!(
                uc.to_cbor(),
                *expected,
                "{n} shards: UC {i} equals the reference's"
            );
            // natively verifiable: path folds to the seal hash
            assert_eq!(
                uc.computed_seal_hash().unwrap().data(),
                uc.unicity_seal.hash.as_slice(),
                "{n} shards: UC {i} path"
            );
            assert_eq!(uc.unicity_seal.to_cbor(), c.uc.unicity_seal.to_cbor());
        }
        assert_eq!(c.view_bytes, c.view.to_cbor().unwrap().as_slice());
        // all derived certificates share the master seal: one quorum check suffices
        let stats = session.stats();
        assert_eq!(stats.quorum_checks, 1, "{n} shards");
        // plain (policy-less) authentication reuses the signature verdict of the same
        // complete seal: every shared copy of the master seal is a hit
        for sc in &ucs {
            let uc = sc.certificate.as_ref().unwrap();
            session.authenticate_seal(&uc.unicity_seal).unwrap();
        }
        assert_eq!(
            session.stats().quorum_checks,
            1,
            "{n} shards: the shared seal's signatures are verified once"
        );
        assert_eq!(session.stats().memo_hits, n as u64);
    }
}

#[test]
fn structure_rejections() {
    let c = case(4);
    let t = &c.topology;
    let p = c.partition;
    assert!(c.view.validate_structure(p, t).is_ok());
    assert_eq!(
        c.view.validate_structure(p + 1, t),
        Err(PartitionViewError::PartitionMismatch)
    );
    let mut missing = c.view.clone();
    missing.leaves.pop();
    assert!(matches!(
        missing.validate_structure(p, t),
        Err(PartitionViewError::LeafSetMismatch(_))
    ));
    let mut extra = c.view.clone();
    extra.leaves.push(c.view.leaves[0].clone());
    assert!(matches!(
        extra.validate_structure(p, t),
        Err(PartitionViewError::LeafSetMismatch(_))
    ));
    let mut dup = c.view.clone();
    dup.leaves[1] = dup.leaves[0].clone();
    assert!(matches!(
        dup.validate_structure(p, t),
        Err(PartitionViewError::LeafSetMismatch(_))
    ));
    let mut reordered = c.view.clone();
    reordered.leaves.swap(0, 1);
    assert!(matches!(
        reordered.validate_structure(p, t),
        Err(PartitionViewError::LeafSetMismatch(_))
    ));
    let mut conf = c.view.clone();
    conf.leaves[2].shard_conf_hash = vec![9; 32];
    assert_eq!(
        conf.validate_structure(p, t),
        Err(PartitionViewError::ConfigHashMismatch)
    );
    // a view of another topology
    let eight = case(8).topology;
    assert!(matches!(
        c.view.validate_structure(p, &eight),
        Err(PartitionViewError::LeafSetMismatch(_))
    ));
    assert!(matches!(
        c.view
            .validate_structure(p, &PartitionTopology::single_shard()),
        Err(PartitionViewError::LeafSetMismatch(_))
    ));
}

#[test]
fn every_committed_field_is_bound_to_the_seal() {
    type Flip = fn(&mut PartitionViewLeaf);
    let flips: [(&str, Flip); 7] = [
        ("round", |l| l.input_record.round_number ^= 1),
        ("epoch", |l| l.input_record.epoch ^= 1),
        ("timestamp", |l| l.input_record.timestamp ^= 1),
        ("fees", |l| l.input_record.sum_of_earned_fees ^= 1),
        ("hash", |l| l.input_record.hash.as_mut().unwrap()[0] ^= 1),
        ("summary", |l| {
            l.input_record.summary_value.as_mut().unwrap().push(1)
        }),
        ("trHash", |l| l.tr_hash[0] ^= 1),
    ];
    for n in CASES {
        let c = case(n);
        assert!(c.view.verify_tree(&c.uc, c.partition, &c.topology).is_ok());
        // the enclosing UC's own leaf as well as any other leaf
        for leaf in [0, n - 1] {
            for (name, flip) in &flips {
                let mut v = c.view.clone();
                flip(&mut v.leaves[leaf]);
                let err = v.verify_tree(&c.uc, c.partition, &c.topology).unwrap_err();
                assert!(
                    matches!(
                        err,
                        PartitionViewError::TreeRootMismatch | PartitionViewError::Bounds(_)
                    ),
                    "{n} shards / {name} / leaf {leaf}: {err}"
                );
            }
        }
        // a configuration hash is bound twice: to the admitted configuration ...
        let mut v = c.view.clone();
        v.leaves[n - 1].shard_conf_hash[0] ^= 1;
        assert_eq!(
            v.verify_tree(&c.uc, c.partition, &c.topology).unwrap_err(),
            PartitionViewError::ConfigHashMismatch
        );
        // ... and to the seal, when nothing is admitted for that shard
        let unadmitted = PartitionTopology::new(if n == 1 {
            vec![]
        } else {
            c.topology.canonical_order().unwrap()
        });
        assert_eq!(
            v.verify_tree(&c.uc, c.partition, &unadmitted).unwrap_err(),
            PartitionViewError::TreeRootMismatch
        );
    }
}

#[test]
fn enclosing_certificate_is_checked() {
    let c = case(4);
    let go = |uc: &UnicityCertificate| c.view.verify_tree(uc, c.partition, &c.topology);
    assert!(go(&c.uc).is_ok());

    let mut other_partition = c.uc.clone();
    other_partition
        .unicity_tree_certificate
        .partition_identifier += 1;
    assert!(matches!(
        go(&other_partition),
        Err(PartitionViewError::EnclosingCertificate(_))
    ));

    let mut path = c.uc.clone();
    path.unicity_tree_certificate.steps[0].hash[0] ^= 1;
    assert_eq!(go(&path).unwrap_err(), PartitionViewError::TreeRootMismatch);

    let mut seal_hash = c.uc.clone();
    seal_hash.unicity_seal.hash[0] ^= 1;
    assert_eq!(
        go(&seal_hash).unwrap_err(),
        PartitionViewError::TreeRootMismatch
    );

    let mut own_ir = c.uc.clone();
    own_ir.input_record.round_number ^= 1;
    assert!(matches!(
        go(&own_ir),
        Err(PartitionViewError::EnclosingCertificate(_))
    ));

    let mut own_tr = c.uc.clone();
    own_tr.technical_record_hash = None;
    assert!(matches!(
        go(&own_tr),
        Err(PartitionViewError::EnclosingCertificate(_))
    ));

    let mut own_path = c.uc.clone();
    own_path.shard_tree_certificate.sibling_hash_list[0][0] ^= 1;
    assert!(matches!(
        go(&own_path),
        Err(PartitionViewError::EnclosingCertificate(_))
    ));

    let mut own_shard = c.uc.clone();
    own_shard.shard_tree_certificate.shard = ShardId::root();
    assert!(matches!(
        go(&own_shard),
        Err(PartitionViewError::EnclosingCertificate(_))
    ));

    // another partition's certificate over the same view
    let n8 = case(8);
    assert!(c
        .view
        .verify_tree(&n8.uc, c.partition, &c.topology)
        .is_err());
}

#[test]
fn nil_unicity_tree_path_steps_do_not_decode() {
    // the reference rejects a nil (CBOR null) path item instead of [key, hash]
    let cert = |steps: &[&[u8]]| {
        encode_tag(
            UNICITY_TREE_CERTIFICATE_TAG,
            &encode_array(&[&encode_uint(1), &encode_uint(7), &encode_array(steps)]),
        )
    };
    let step = encode_array(&[&encode_uint(1), &encode_byte_string(&[0; 32])]);
    assert!(UnicityTreeCertificate::from_cbor(Decoder::new(&cert(&[&step]))).is_ok());
    assert!(UnicityTreeCertificate::from_cbor(Decoder::new(&cert(&[&step, &[0xf6]]))).is_err());
    assert!(UnicityTreeCertificate::from_cbor(Decoder::new(&cert(&[&[0xf6]]))).is_err());
}

#[test]
fn seal_authentication_is_strict_and_not_reusable_across_witnesses() {
    let c = case(4);
    let assemble = |uc: &UnicityCertificate, tb: &RootTrustBase| {
        let mut s = SealSession::new(tb);
        assemble(&c.view, uc, c.partition, Some(&c.topology), &mut s)
    };
    assert!(assemble(&c.uc, &c.trust_base).is_ok());

    let mut tb = c.trust_base.clone();
    tb.network_id = NetworkId::TESTNET;
    assert_eq!(
        assemble(&c.uc, &tb),
        Err(PartitionViewError::Seal(
            VerificationError::SealNetworkMismatch
        ))
    );
    let mut tb = c.trust_base.clone();
    tb.epoch += 1;
    assert_eq!(
        assemble(&c.uc, &tb),
        Err(PartitionViewError::Seal(
            VerificationError::SealEpochMismatch
        ))
    );
    let mut tb = c.trust_base.clone();
    tb.epoch_start_round = c.uc.unicity_seal.root_chain_round_number + 1;
    assert_eq!(
        assemble(&c.uc, &tb),
        Err(PartitionViewError::Seal(
            VerificationError::SealBeforeEpochStart
        ))
    );

    // wrong authority (a different key): no quorum
    let mut tb = c.trust_base.clone();
    tb.root_nodes[0].signing_key = PublicKey::from_bytes(
        &hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap(),
    )
    .unwrap();
    assert_eq!(
        assemble(&c.uc, &tb),
        Err(PartitionViewError::Seal(VerificationError::QuorumNotMet))
    );

    // tampered / missing / empty signatures
    let mut bad = c.uc.clone();
    bad.unicity_seal.signatures[0].1[10] ^= 1;
    assert_eq!(
        assemble(&bad, &c.trust_base),
        Err(PartitionViewError::Seal(VerificationError::QuorumNotMet))
    );
    let mut none = c.uc.clone();
    none.unicity_seal.signatures.clear();
    assert_eq!(
        assemble(&none, &c.trust_base),
        Err(PartitionViewError::Seal(VerificationError::SealMalformed))
    );
    let mut empty_sig = c.uc.clone();
    empty_sig.unicity_seal.signatures[0].1.clear();
    assert_eq!(
        assemble(&empty_sig, &c.trust_base),
        Err(PartitionViewError::Seal(VerificationError::SealMalformed))
    );

    // a verdict is bound to the complete seal encoding, including the witness
    let mut s = SealSession::new(&c.trust_base);
    s.authenticate_seal(&c.uc.unicity_seal).unwrap();
    s.authenticate_seal(&c.uc.unicity_seal).unwrap();
    assert_eq!((s.stats().quorum_checks, s.stats().memo_hits), (1, 1));
    let mut other_witness = c.uc.unicity_seal.clone();
    other_witness.signatures.push(("extra".into(), vec![1; 65]));
    s.authenticate_seal(&other_witness).unwrap(); // still a quorum, but a different witness
    assert_eq!((s.stats().quorum_checks, s.stats().memo_hits), (2, 1));
    let mut tampered = c.uc.unicity_seal.clone();
    tampered.signatures[0].1[3] ^= 1;
    assert!(s.authenticate_seal(&tampered).is_err());
    assert_eq!(
        s.stats().quorum_checks,
        3,
        "a tampered witness never hits the memo"
    );
    assert!(s.authenticate_seal(&tampered).is_err());
    assert_eq!(s.stats().quorum_checks, 4, "failures are not remembered");
}

#[test]
fn memo_is_bounded_and_can_be_disabled() {
    let c = case(1);
    let mut s = SealSession::with_capacity(&c.trust_base, 0);
    s.authenticate_seal(&c.uc.unicity_seal).unwrap();
    s.authenticate_seal(&c.uc.unicity_seal).unwrap();
    assert_eq!((s.stats().quorum_checks, s.stats().memo_hits), (2, 0));

    let mut s = SealSession::with_capacity(&c.trust_base, 1);
    let a = c.uc.unicity_seal.clone();
    let mut b = a.clone();
    b.signatures.push(("extra".into(), vec![1; 65]));
    s.authenticate_seal(&a).unwrap();
    s.authenticate_seal(&b).unwrap(); // evicts a
    s.authenticate_seal(&b).unwrap();
    s.authenticate_seal(&a).unwrap(); // miss again
    assert_eq!((s.stats().quorum_checks, s.stats().memo_hits), (3, 1));
}

#[test]
fn null_summary_leaves_hash_exactly_and_yield_ordinary_certificates() {
    // a leaf whose summary value is null hashes into the tree exactly and, since the ordinary
    // input record preserves nullable fields, carries it into the derived certificate as null
    let view = minimal_view();
    let topo = PartitionTopology::single_shard().with_shard_conf_hash(&ShardId::root(), [2; 32]);
    assert!(view.build_shard_tree(1, &topo).is_ok());
    let ir = view.leaves[0].input_record.to_input_record();
    assert_eq!(ir.summary_value, None);
    assert_eq!(
        PartitionViewInputRecord::from_input_record(&ir),
        view.leaves[0].input_record
    );
}

fn node(id: &str, key: &str, stake: u64) -> RootTrustBaseNodeInfo {
    RootTrustBaseNodeInfo {
        node_id: id.into(),
        signing_key: PublicKey::from_bytes(&hex::decode(key).unwrap()).unwrap(),
        stake,
    }
}

/// The public session entry points refuse an unsafe authority and never cache
/// a verdict obtained under one.
#[test]
fn invalid_authorities_never_succeed_or_enter_the_memo() {
    let c = case(1);
    let seal = c.uc.unicity_seal.clone();
    let mut unsigned = seal.clone();
    unsigned.signatures.clear();

    let mut bad: Vec<(&str, RootTrustBase)> = Vec::new();
    let mut empty = c.trust_base.clone();
    empty.root_nodes.clear();
    empty.quorum_threshold = 0;
    bad.push(("no validators, zero threshold", empty));
    let mut zero_threshold = c.trust_base.clone();
    zero_threshold.quorum_threshold = 0;
    bad.push(("zero threshold", zero_threshold));
    let mut zero_stake = c.trust_base.clone();
    zero_stake.root_nodes[0].stake = 0;
    bad.push(("zero stake", zero_stake));
    let mut dup = c.trust_base.clone();
    dup.root_nodes.push(dup.root_nodes[0].clone());
    bad.push(("duplicate validator", dup));

    for (name, tb) in &bad {
        assert!(tb.validate().is_err(), "{name}");
        let mut s = SealSession::new(tb);
        for seal in [&unsigned, &seal] {
            for _ in 0..2 {
                assert!(
                    matches!(
                        s.verify_quorum(seal),
                        Err(VerificationError::InvalidTrustBase(_))
                    ),
                    "{name}"
                );
                assert!(
                    matches!(
                        s.authenticate_seal(seal),
                        Err(VerificationError::InvalidTrustBase(_))
                    ),
                    "{name}"
                );
            }
        }
        assert_eq!(
            (s.stats().quorum_checks, s.stats().memo_hits),
            (0, 0),
            "{name}"
        );
    }
}

/// Stake-weighted authorities are refused by the strict policy as an
/// unsupported configuration (the Rust quorum rule counts signers), not
/// misreported as a signature failure. The reference accepts this very seal:
/// stakes [2,1,1], threshold 3, signed by the first two validators.
#[test]
fn weighted_authority_is_unsupported_not_a_bad_signature() {
    let json = include_str!(
        "vectors/uc-consolidation/partition-view/v1/derived/weighted-4/trust-base.json"
    );
    let keys: Vec<String> = json
        .match_indices("\"sigKey\": \"")
        .map(|(i, m)| json[i + m.len()..].trim_start_matches("0x")[..66].to_string())
        .collect();
    assert_eq!(keys.len(), 3);
    let stakes = [2, 1, 1];
    let nodes: Vec<_> = keys
        .iter()
        .zip(stakes)
        .enumerate()
        .map(|(i, (k, s))| node(&format!("n{i}"), k, s))
        .collect();
    let tb = RootTrustBase::try_new(1, NetworkId::MAINNET, 1, 0, nodes, 3).unwrap();
    let uc = UnicityCertificate::from_cbor(Decoder::new(vector!(
        "derived/weighted-4/enclosing-uc.cbor"
    )))
    .unwrap();
    assert_eq!(uc.unicity_seal.signatures.len(), 2);

    let c = case(4);
    let mut s = SealSession::new(&tb);
    assert_eq!(
        s.authenticate_seal(&uc.unicity_seal),
        Err(VerificationError::UnsupportedAuthority)
    );
    assert_eq!(
        assemble(&c.view, &uc, c.partition, Some(&c.topology), &mut s),
        Err(PartitionViewError::Seal(
            VerificationError::UnsupportedAuthority
        ))
    );
    assert_eq!(
        (s.stats().quorum_checks, s.stats().memo_hits),
        (0, 0),
        "no signature work, nothing cached"
    );

    // with unit stakes the same keys judge signatures: a bad witness is a quorum failure
    let unit: Vec<_> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| node(&format!("n{i}"), k, 1))
        .collect();
    let tb = RootTrustBase::try_new(1, NetworkId::MAINNET, 1, 0, unit, 3).unwrap();
    let mut s = SealSession::new(&tb);
    assert_eq!(
        s.authenticate_seal(&uc.unicity_seal),
        Err(VerificationError::QuorumNotMet)
    );
}

// ------------------------------------------- authenticated view (1b) ------

#[test]
fn unpinned_authentication_needs_no_peer_configuration() {
    for n in CASES {
        let c = case(n);
        let mut session = SealSession::new(&c.trust_base);
        let view = c
            .view
            .authenticate(&c.uc, c.partition, None, &mut session)
            .unwrap_or_else(|e| panic!("{n} shards: {e}"));
        assert_eq!(view.partition_id(), c.partition);
        assert_eq!(view.network_id(), c.trust_base.network_id);
        assert_eq!(view.epoch(), c.trust_base.epoch);
        assert_eq!(view.leaves().len(), n);
        assert_eq!(view.seal(), &c.uc.unicity_seal);
        assert_eq!(view.shard_tree().root_hash(), c.tree_root.as_slice());
        let ucs = view.certificates().unwrap();
        for (sc, expected) in ucs.iter().zip(&c.expected_ucs) {
            assert_eq!(&sc.certificate.as_ref().unwrap().to_cbor(), expected);
        }
        assert_eq!(session.stats().quorum_checks, 1);
    }
}

#[test]
fn view_identity_binds_authority_partition_pins_and_seal() {
    let c = case(4);
    let id = |tb: &RootTrustBase, uc: &UnicityCertificate, pins: Option<&PartitionTopology>| {
        let mut s = SealSession::new(tb);
        *c.view
            .authenticate(uc, c.partition, pins, &mut s)
            .unwrap()
            .identity()
    };
    let base = id(&c.trust_base, &c.uc, None);
    assert_eq!(base, id(&c.trust_base, &c.uc, None), "deterministic");
    assert_ne!(
        base,
        id(&c.trust_base, &c.uc, Some(&c.topology)),
        "pins are part of the identity"
    );

    // another admitted authority (same keys, different threshold/stake layout is
    // rejected elsewhere; use an extra, unused validator)
    let mut other = c.trust_base.clone();
    other.root_nodes.push(RootTrustBaseNodeInfo {
        node_id: "unused".into(),
        signing_key: PublicKey::from_bytes(
            &hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap(),
        )
        .unwrap(),
        stake: 1,
    });
    assert_ne!(
        base,
        id(&other, &c.uc, None),
        "authority content is part of the identity"
    );

    // a different valid witness of the same unsigned seal is a different identity
    let mut witness = c.uc.clone();
    witness
        .unicity_seal
        .signatures
        .push(("extra".into(), vec![1; 65]));
    assert_ne!(base, id(&c.trust_base, &witness, None));

    // pins on different shards differ
    let mut partial = PartitionTopology::new(c.topology.canonical_order().unwrap());
    let first = c.topology.canonical_order().unwrap()[0].clone();
    partial = partial.with_shard_conf_hash(&first, *c.topology.shard_conf_hash(&first).unwrap());
    assert_ne!(
        id(&c.trust_base, &c.uc, Some(&partial)),
        id(&c.trust_base, &c.uc, Some(&c.topology))
    );
}

#[test]
fn candidate_data_is_never_authority() {
    let c = case(4);
    let go = |view: &PartitionView, uc: &UnicityCertificate, part: u32| {
        let mut s = SealSession::new(&c.trust_base);
        let r = view.authenticate(uc, part, None, &mut s).map(|_| ());
        (r, s.stats().quorum_checks)
    };
    // the wrong expected partition
    let (r, checks) = go(&c.view, &c.uc, c.partition + 1);
    assert_eq!(r, Err(PartitionViewError::PartitionMismatch));
    assert_eq!(checks, 0);

    // a changed candidate leaf, including its configuration hash, does not hash into the seal
    let mut v = c.view.clone();
    v.leaves[3].shard_conf_hash[0] ^= 1;
    let (r, checks) = go(&v, &c.uc, c.partition);
    assert_eq!(r, Err(PartitionViewError::TreeRootMismatch));
    assert_eq!(checks, 0, "no signature work for an unbound view");

    // candidate structure: order, coverage, duplicates
    let mut v = c.view.clone();
    v.leaves.swap(1, 2);
    assert!(matches!(
        go(&v, &c.uc, c.partition).0,
        Err(PartitionViewError::LeafSetMismatch(_))
    ));
    let mut v = c.view.clone();
    v.leaves.pop();
    assert!(go(&v, &c.uc, c.partition).0.is_err());
    let mut v = c.view.clone();
    v.leaves[1] = v.leaves[0].clone();
    assert!(go(&v, &c.uc, c.partition).0.is_err());

    // a perfect view under a seal the anchor does not authenticate yields no object
    let mut bad = c.uc.clone();
    bad.unicity_seal.signatures[0].1[5] ^= 1;
    let (r, checks) = go(&c.view, &bad, c.partition);
    assert_eq!(
        r,
        Err(PartitionViewError::Seal(VerificationError::QuorumNotMet))
    );
    assert_eq!(checks, 1);
}

#[test]
fn pins_are_a_stricter_policy() {
    let c = case(4);
    let go = |pins: &PartitionTopology| {
        let mut s = SealSession::new(&c.trust_base);
        c.view
            .authenticate(&c.uc, c.partition, Some(pins), &mut s)
            .map(|_| ())
    };
    assert!(go(&c.topology).is_ok());
    let order = c.topology.canonical_order().unwrap();
    // partial pins: only one shard's hash
    let partial = PartitionTopology::new(order.clone())
        .with_shard_conf_hash(&order[2], *c.topology.shard_conf_hash(&order[2]).unwrap());
    assert!(go(&partial).is_ok());
    let wrong = PartitionTopology::new(order.clone()).with_shard_conf_hash(&order[2], [7; 32]);
    assert_eq!(go(&wrong), Err(PartitionViewError::ConfigHashMismatch));
    // pinned scheme differs from the view's
    assert!(matches!(
        go(&case(8).topology),
        Err(PartitionViewError::LeafSetMismatch(_))
    ));
    assert!(go(&PartitionTopology::single_shard()).is_err());
}

// ------------------------------------------------ review of #22 ------------

/// Downstream compile/behaviour regression for the pre-1b entry point
/// (signature and error variant of the merged R1 API).
#[test]
fn pinned_assembly_api_is_preserved() {
    let c = case(4);
    let mut s = SealSession::new(&c.trust_base);
    let ucs: Vec<ShardCertificate> = c
        .view
        .assemble_certificates(&c.uc, c.partition, &c.topology, &mut s)
        .unwrap();
    for (sc, expected) in ucs.iter().zip(&c.expected_ucs) {
        assert_eq!(&sc.certificate.as_ref().unwrap().to_cbor(), expected);
    }
    // complete pins are required on this path
    let partial = PartitionTopology::new(c.topology.canonical_order().unwrap());
    let mut s = SealSession::new(&c.trust_base);
    let err = c
        .view
        .assemble_certificates(&c.uc, c.partition, &partial, &mut s)
        .unwrap_err();
    assert!(matches!(err, PartitionViewError::ConfigHashRequired));
    assert_eq!(s.stats().quorum_checks, 0);
    // and it still authenticates: a bad seal is refused
    let mut bad = c.uc.clone();
    bad.unicity_seal.signatures[0].1[5] ^= 1;
    let mut s = SealSession::new(&c.trust_base);
    assert_eq!(
        c.view
            .assemble_certificates(&bad, c.partition, &c.topology, &mut s),
        Err(PartitionViewError::Seal(VerificationError::QuorumNotMet))
    );
}

/// The signature verdict of a complete seal is shared by every policy (one native
/// verification per distinct seal); the policy-dependent rules are never memoized
/// across policies: the strict checks run on every call and bodies are policy-keyed.
#[test]
fn signature_memo_is_shared_but_policy_rules_are_not() {
    let c = case(4);
    let mut s = SealSession::new(&c.trust_base);
    let auth = |s: &mut SealSession<'_>, pins: Option<&PartitionTopology>| {
        c.view.authenticate(&c.uc, c.partition, pins, s).unwrap();
    };
    auth(&mut s, None);
    assert_eq!((s.stats().quorum_checks, s.stats().memo_hits), (1, 0));
    auth(&mut s, None);
    assert_eq!(
        (s.stats().quorum_checks, s.stats().memo_hits),
        (1, 1),
        "same policy reuses"
    );
    auth(&mut s, Some(&c.topology));
    assert_eq!(
        (s.stats().quorum_checks, s.stats().memo_hits),
        (1, 2),
        "the same seal's signatures are not verified again for another policy"
    );
    auth(&mut s, Some(&c.topology));
    assert_eq!((s.stats().quorum_checks, s.stats().memo_hits), (1, 3));
    let order = c.topology.canonical_order().unwrap();
    let partial = PartitionTopology::new(order.clone())
        .with_shard_conf_hash(&order[0], *c.topology.shard_conf_hash(&order[0]).unwrap());
    auth(&mut s, Some(&partial));
    assert_eq!(
        s.stats().quorum_checks,
        1,
        "different pins, same signatures"
    );

    // policy-dependent rules are still evaluated every time: a pin the certificate
    // does not satisfy fails even though the seal's signatures are memoized
    let mut wrong = PartitionTopology::new(order.clone());
    for shard in &order {
        wrong = wrong.with_shard_conf_hash(shard, [0xee; 32]);
    }
    assert!(c
        .view
        .authenticate(&c.uc, c.partition, Some(&wrong), &mut s)
        .is_err());
    // and the strict authority is checked by every call, whatever was verified before
    let mut tb = c.trust_base.clone();
    tb.epoch += 1;
    let mut other_epoch = SealSession::new(&tb);
    assert_eq!(
        other_epoch.authenticate_seal(&c.uc.unicity_seal),
        Err(VerificationError::SealEpochMismatch)
    );
}

/// A custom authenticator has no authority identity, so it can drive the
/// compatibility assembly (no view is exposed) but not `authenticate`, whose
/// views carry an authority-bound identity (`authenticate` takes a
/// `SealSession`). Two sessions of different authorities yield different views.
#[test]
fn custom_authenticators_cannot_mint_identified_views() {
    struct Delegating<'a>(SealSession<'a>);
    impl SealAuthenticator for Delegating<'_> {
        fn authenticate_seal(
            &mut self,
            seal: &unicity_token::api::bft::UnicitySeal,
        ) -> Result<(), VerificationError> {
            self.0.authenticate_seal(seal)
        }
    }
    let c = case(4);
    let mut custom = Delegating(SealSession::new(&c.trust_base));
    let ucs = c
        .view
        .assemble_certificates(&c.uc, c.partition, &c.topology, &mut custom)
        .unwrap();
    assert_eq!(ucs.len(), 4);

    let mut other = c.trust_base.clone();
    other.root_nodes.push(RootTrustBaseNodeInfo {
        node_id: "unused".into(),
        signing_key: PublicKey::from_bytes(
            &hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap(),
        )
        .unwrap(),
        stake: 1,
    });
    let (mut s1, mut s2) = (SealSession::new(&c.trust_base), SealSession::new(&other));
    let v1 = c
        .view
        .authenticate(&c.uc, c.partition, None, &mut s1)
        .unwrap();
    let v2 = c
        .view
        .authenticate(&c.uc, c.partition, None, &mut s2)
        .unwrap();
    assert_ne!(v1.identity(), v2.identity(), "authority separation");
}

#[test]
fn lazy_certificate_equals_the_eager_one_and_unknown_shards_are_refused() {
    for n in CASES {
        let c = case(n);
        let mut s = SealSession::new(&c.trust_base);
        let view = c
            .view
            .authenticate(&c.uc, c.partition, None, &mut s)
            .unwrap();
        let all = view.certificates().unwrap();
        assert_eq!(all.len(), n);
        for sc in &all {
            assert_eq!(
                &view.certificate_of(&sc.shard_id).unwrap(),
                sc,
                "{n} shards"
            );
            assert!(view.leaf_of(&sc.shard_id).is_some());
        }
        let unknown = ShardId::decode(&[0b0100_0001]).unwrap(); // shard "0000001"
        assert!(view.leaf_of(&unknown).is_none());
        assert!(matches!(
            view.certificate_of(&unknown),
            Err(PartitionViewError::LeafSetMismatch(_))
        ));
    }
}
