//! `GET /api/v1/trustbases` through `HttpAggregatorClient` as a `TrustBaseSource`: the query, the origin, the size cap and the refusals,
//! against a loopback server.
#![cfg(all(feature = "http", feature = "client"))]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use unicity_token::api::bft::trust_base_update::{Snapshot, TrustBaseRequest, TrustBaseSource};
use unicity_token::api::NetworkId;
use unicity_token::client::HttpAggregatorClient;

/// Serve `reply` (a complete HTTP response) to each request and record the request heads.
fn serve(reply: Vec<u8>) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 8192];
            let n = stream.read(&mut buf).unwrap_or(0);
            log.lock()
                .unwrap()
                .push(String::from_utf8_lossy(&buf[..n]).to_string());
            let _ = stream.write_all(&reply);
        }
    });
    (format!("http://127.0.0.1:{port}"), seen)
}

fn ok(body: &[u8]) -> Vec<u8> {
    let mut r = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    r.extend_from_slice(body);
    r
}

fn request(snapshot: Option<Snapshot>) -> TrustBaseRequest {
    TrustBaseRequest {
        from_epoch: 7,
        max_entries: 64,
        network_id: NetworkId::new(5).unwrap(),
        snapshot,
    }
}

#[test]
fn the_query_is_on_the_origin_whatever_path_the_rpc_url_has() {
    let (url, seen) = serve(ok(&[1, 2, 3]));
    let client = HttpAggregatorClient::new_insecure_http(format!("{url}/some/rpc/path"));
    let body = client.get_trust_base_page(&request(None)).unwrap();
    assert_eq!(body, vec![1, 2, 3]);
    let head = seen.lock().unwrap()[0].clone();
    let line = head.lines().next().unwrap();
    assert_eq!(line, "GET /api/v1/trustbases?from=7&maxEntries=64 HTTP/1.1");
    assert!(head.to_lowercase().contains("accept: application/cbor"));
    assert!(!head.to_lowercase().contains("x-api-key"));

    let snap = Snapshot {
        end: 12,
        entry_id: [0xab; 32],
    };
    client.get_trust_base_page(&request(Some(snap))).unwrap();
    let line = seen.lock().unwrap()[1].lines().next().unwrap().to_string();
    assert_eq!(
        line,
        format!(
            "GET /api/v1/trustbases?from=7&maxEntries=64&snapshotEnd=12&snapshotEntryId=0x{} HTTP/1.1",
            "ab".repeat(32)
        )
    );
}

#[test]
fn non_success_statuses_and_redirects_are_refusals() {
    for status in [
        "404 Not Found",
        "400 Bad Request",
        "503 Service Unavailable",
        "302 Found",
    ] {
        let reply = format!(
            "HTTP/1.1 {status}\r\nLocation: http://127.0.0.1:1/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let (url, _) = serve(reply.into_bytes());
        let client = HttpAggregatorClient::new_insecure_http(url);
        let e = client.get_trust_base_page(&request(None)).unwrap_err();
        assert!(e.0.contains(&status[..3]), "{status}: {e}");
    }
}

#[test]
fn a_body_over_the_cap_is_refused() {
    use unicity_token::client::MAX_TRUST_BASE_RESPONSE_BYTES;
    let (url, _) = serve(ok(&vec![0u8; MAX_TRUST_BASE_RESPONSE_BYTES + 1]));
    let client = HttpAggregatorClient::new_insecure_http(url);
    let e = client.get_trust_base_page(&request(None)).unwrap_err();
    assert!(e.0.contains("size cap"), "{e}");
    // exactly the cap is accepted
    let (url, _) = serve(ok(&vec![0u8; MAX_TRUST_BASE_RESPONSE_BYTES]));
    let client = HttpAggregatorClient::new_insecure_http(url);
    assert_eq!(
        client.get_trust_base_page(&request(None)).unwrap().len(),
        MAX_TRUST_BASE_RESPONSE_BYTES
    );
}

#[test]
fn an_unusable_endpoint_is_a_source_error_not_a_panic() {
    let client = HttpAggregatorClient::new("http://127.0.0.1:1/");
    // plaintext without opting in
    assert!(client.get_trust_base_page(&request(None)).is_err());
    let client = HttpAggregatorClient::new_insecure_http("http://127.0.0.1:1/");
    assert!(client.get_trust_base_page(&request(None)).is_err());
}
