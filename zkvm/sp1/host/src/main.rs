//! Execute both guests (patched / unpatched) on the same inputs and print the
//! instruction and syscall counts.
use sp1_sdk::blocking::{Prover, ProverClient};
use sp1_sdk::{include_elf, Elf, SP1Stdin};
use unicity_token::cbor::Decoder;

#[derive(serde::Serialize)]
struct Input {
    mode: u8,
    version: u64,
    network: u16,
    epoch: u64,
    epoch_start_round: u64,
    threshold: u64,
    nodes: Vec<(String, Vec<u8>, u64)>,
    payload: Vec<u8>,
}

const PATCHED: Elf = include_elf!("unicity-sp1-guest");
const UNPATCHED: Elf = include_elf!("unicity-sp1-guest-unpatched");

const FLOW: &str = include_str!("../../../../tests/vectors/transition_flow.json");
const CORPUS_TB: &[u8] =
    include_bytes!("../../../../tests/vectors/uc-consolidation/corpus-v1/shards-4/trust-base.cbor");
const CORPUS_UC: &[u8] =
    include_bytes!("../../../../tests/vectors/uc-consolidation/corpus-v1/shards-4/ucs/00.cbor");

fn json_str<'a>(json: &'a str, key: &str) -> &'a str {
    let needle = format!("\"{key}\"");
    let rest = &json[json.find(&needle).expect("key") + needle.len()..];
    let q1 = rest.find('"').unwrap() + 1;
    let q2 = rest[q1..].find('"').unwrap() + q1;
    &rest[q1..q2]
}

fn corpus_trust_base() -> Input {
    let items = Decoder::new(CORPUS_TB)
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
            (
                f[0].text().unwrap().to_string(),
                f[1].bytes_value().unwrap().to_vec(),
                f[2].uint().unwrap(),
            )
        })
        .collect();
    Input {
        mode: 1,
        version: items[0].uint().unwrap(),
        network: items[1].uint().unwrap() as u16,
        epoch: items[2].uint().unwrap(),
        epoch_start_round: items[3].uint().unwrap(),
        threshold: items[5].uint().unwrap(),
        nodes,
        payload: CORPUS_UC.to_vec(),
    }
}

fn token_input(name: &str) -> Input {
    Input {
        mode: 0,
        version: 0,
        network: 3,
        epoch: 0,
        epoch_start_round: 0,
        threshold: 1,
        nodes: vec![(
            "NODE".into(),
            hex::decode(json_str(FLOW, "aggregatorPublicKey")).unwrap(),
            1,
        )],
        payload: hex::decode(json_str(FLOW, name)).unwrap(),
    }
}

fn main() {
    let client = ProverClient::builder().light().build();
    let cases = [
        ("token carol (mint + 2 transfers, 1-of-1 quorum)", token_input("carolToken")),
        ("token alice (mint only)", token_input("aliceToken")),
        ("native UC (4-node trust base, quorum seal)", corpus_trust_base()),
    ];
    for (name, input) in cases {
        println!("== {name}");
        for (label, elf) in [("unpatched", UNPATCHED), ("patched  ", PATCHED)] {
            let mut stdin = SP1Stdin::new();
            stdin.write(&input);
            let (mut out, report) = client
                .execute(elf, stdin)
                .run()
                .expect("guest execution");
            let ok: bool = out.read();
            assert!(ok, "guest rejected the input");
            let mut sys: Vec<_> = report
                .syscall_counts
                .iter()
                .filter(|(_, n)| **n > 0)
                .map(|(c, n)| format!("{c:?}={n}"))
                .collect();
            sys.sort();
            println!(
                "  {label}: instructions={} syscalls: {}",
                report.total_instruction_count(),
                sys.join(" ")
            );
        }
    }
}
