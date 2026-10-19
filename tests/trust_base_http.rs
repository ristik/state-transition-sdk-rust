#![cfg(feature = "http")]
//! `HttpAggregatorClient` as a `TrustBaseSource`: `GET /api/v1/trustbases` on the aggregator's
//! origin, plain HTTP (no JSON-RPC), `Accept: application/cbor`, the raw tag-39015 response as
//! body. A loopback server serves the shared Go-generated UTB chain
//! (`tests/fixtures/utb/v1`).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use serde_json::Value;
use unicity_token::api::bft::{
    TrustBaseEntry, TrustBaseHistory, TrustBaseRequest, TrustBaseStatus,
};
use unicity_token::cbor::{encode_array, encode_byte_string, encode_null, encode_tag, encode_uint};
use unicity_token::client::{
    update_trust_base, HttpAggregatorClient, HttpError, TrustBaseSource, UpdateLimits,
    UpdateOutcome,
};

fn chain() -> (u16, Vec<Vec<u8>>) {
    let raw = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/utb/v1/utb-vectors-v1.json"
    ))
    .unwrap();
    let v: Value = serde_json::from_slice(&raw).unwrap();
    let entries = v["chain"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| hex::decode(c["hex"].as_str().unwrap()).unwrap())
        .collect();
    (v["network"].as_u64().unwrap() as u16, entries)
}

fn response(
    network: u16,
    status: u64,
    from: u64,
    end: u64,
    end_id: Option<[u8; 32]>,
    entries: &[&[u8]],
    next: Option<u64>,
) -> Vec<u8> {
    let entry_refs: Vec<&[u8]> = entries.to_vec();
    encode_tag(
        39015,
        &encode_array(&[
            &encode_uint(1),
            &encode_uint(u64::from(network)),
            &encode_uint(status),
            &encode_uint(from),
            &encode_uint(end),
            &end_id.map_or_else(encode_null, |id| encode_byte_string(&id)),
            &encode_array(&entry_refs),
            &next.map_or_else(encode_null, encode_uint),
        ]),
    )
}

/// The request lines and headers a server saw.
type RequestLog = Arc<Mutex<Vec<(String, Vec<(String, String)>)>>>;

type Handler = Box<dyn Fn(&str) -> (u16, String, Vec<u8>) + Send + Sync>;

/// A loopback server: for every request the handler gets the request target (path and query)
/// and answers `(status, content type, body)`. Returns the base URL and the request log.
fn serve(handler: Handler) -> (String, RequestLog) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let log = Arc::new(Mutex::new(Vec::new()));
    let log2 = log.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut buf = vec![0u8; 8192];
            let n = stream.read(&mut buf).unwrap_or(0);
            let text = String::from_utf8_lossy(&buf[..n]).to_string();
            let mut lines = text.lines();
            let first = lines.next().unwrap_or("").to_string();
            let target = first.split_whitespace().nth(1).unwrap_or("").to_string();
            let headers: Vec<(String, String)> = lines
                .take_while(|l| !l.is_empty())
                .filter_map(|l| l.split_once(": "))
                .map(|(k, v)| (k.to_ascii_lowercase(), v.to_string()))
                .collect();
            log2.lock().unwrap().push((first.clone(), headers));
            let (status, ctype, body) = handler(&target);
            let head = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&body);
        }
    });
    (url, log)
}

fn query(target: &str, key: &str) -> Option<String> {
    target
        .split_once('?')?
        .1
        .split('&')
        .find_map(|kv| kv.strip_prefix(&format!("{key}=")).map(str::to_string))
}

/// Serve the fixture chain like the aggregator: `from`, `maxEntries`, frozen snapshot.
fn chain_server() -> (String, RequestLog) {
    let (network, entries) = chain();
    let ids: Vec<[u8; 32]> = entries
        .iter()
        .map(|e| TrustBaseEntry::from_cbor(e).unwrap().entry_id())
        .collect();
    serve(Box::new(move |target| {
        let from: u64 = query(target, "from").unwrap().parse().unwrap();
        let max: u64 = query(target, "maxEntries").map_or(64, |m| m.parse().unwrap());
        let tip = entries.len() as u64;
        if from > tip {
            return (
                200,
                "application/cbor".into(),
                response(
                    network,
                    3,
                    from,
                    tip,
                    Some(ids[tip as usize - 1]),
                    &[],
                    None,
                ),
            );
        }
        let last = tip.min(from + max - 1);
        let page: Vec<&[u8]> = (from..=last)
            .map(|e| entries[e as usize - 1].as_slice())
            .collect();
        let next = (last < tip).then_some(last + 1);
        (
            200,
            "application/cbor".into(),
            response(
                network,
                0,
                from,
                tip,
                Some(ids[tip as usize - 1]),
                &page,
                next,
            ),
        )
    }))
}

#[test]
fn a_page_is_fetched_with_the_documented_request() {
    let (url, log) = chain_server();
    let client = HttpAggregatorClient::new_insecure_http(format!("{url}/some/rpc/path"));
    let page = client
        .get_trust_bases(&TrustBaseRequest {
            from: 2,
            to: None,
            snapshot: Some((4, [0xab; 32])),
            max_entries: 2,
        })
        .unwrap();
    assert_eq!(page.status, TrustBaseStatus::Ok);
    assert_eq!(
        page.entries.iter().map(|e| e.epoch).collect::<Vec<_>>(),
        vec![2, 3]
    );
    assert_eq!(page.next_epoch, Some(4));
    let log = log.lock().unwrap();
    let (line, headers) = &log[0];
    assert!(line.starts_with("GET /api/v1/trustbases?"), "{line}");
    assert!(
        line.contains("from=2") && line.contains("maxEntries=2"),
        "{line}"
    );
    assert!(line.contains("snapshotEnd=4"), "{line}");
    assert!(
        line.contains(&format!("snapshotEntryId=0x{}", "ab".repeat(32))),
        "{line}"
    );
    assert!(!line.contains("to="), "{line}");
    assert!(headers
        .iter()
        .any(|(k, v)| k == "accept" && v == "application/cbor"));
}

#[test]
fn the_history_is_extended_from_the_genesis_over_http() {
    let (url, log) = chain_server();
    let client = HttpAggregatorClient::new_insecure_http(url);
    let (_, entries) = chain();
    let genesis = TrustBaseEntry::from_cbor(&entries[0]).unwrap();
    let mut history = TrustBaseHistory::from_genesis(genesis, None).unwrap();
    let limits = UpdateLimits {
        page_entries: 2,
        total_entries: 100,
    };
    let out = update_trust_base(&mut history, &client, 4, &limits).unwrap();
    assert_eq!(out, UpdateOutcome::Extended { added: 3 });
    assert_eq!(history.latest().epoch, 4);
    let froms: Vec<String> = log
        .lock()
        .unwrap()
        .iter()
        .map(|(l, _)| {
            l.split(['?', '&', ' '])
                .find(|p| p.starts_with("from="))
                .unwrap()
                .to_string()
        })
        .collect();
    assert_eq!(froms, vec!["from=2", "from=4"], "always from held + 1");

    // the tip is reached: asking beyond it is "not yet available", not an error
    let out = update_trust_base(&mut history, &client, 9, &limits).unwrap();
    assert_eq!(out, UpdateOutcome::NotYetAvailable { held: 4, added: 0 });
}

#[test]
fn bad_answers_are_errors() {
    let wrong_type = serve(Box::new(|_| {
        (200, "application/json".into(), b"{}".to_vec())
    }));
    let bad_request = serve(Box::new(|_| {
        (400, "text/plain".into(), b"bad from".to_vec())
    }));
    let garbage = serve(Box::new(|_| {
        (200, "application/cbor".into(), vec![0xff, 0x00])
    }));
    let huge = serve(Box::new(|_| {
        (200, "application/cbor".into(), vec![0u8; (1 << 20) + 10])
    }));
    let request = TrustBaseRequest {
        from: 2,
        to: None,
        snapshot: None,
        max_entries: 64,
    };
    let get = |url: &str| {
        HttpAggregatorClient::new_insecure_http(url.to_string()).get_trust_bases(&request)
    };
    assert!(matches!(get(&wrong_type.0), Err(HttpError::Decode(_))));
    assert!(matches!(
        get(&bad_request.0),
        Err(HttpError::Http { status: 400, .. })
    ));
    assert!(matches!(get(&garbage.0), Err(HttpError::Decode(_))));
    assert!(matches!(
        get(&huge.0),
        Err(HttpError::ResponseTooLarge { .. })
    ));
}
