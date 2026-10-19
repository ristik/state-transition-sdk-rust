//! Shared helpers of the long-poll transport tests: fixture proofs and a scripted
//! loopback JSON-RPC server that can delay, record and script each reply.
#![allow(dead_code)]

use std::io::Read;

use unicity_token::api::inclusion_proof::INCLUSION_PROOF_TAG;
use unicity_token::api::{CertificationData, InclusionProof, InclusionProofResponse, StateId};
use unicity_token::cbor::{
    encode_array, encode_byte_string, encode_null, encode_tag, encode_uint, Decoder,
};
use unicity_token::transaction::Token;

const FIXTURE: &str = include_str!("../vectors/transition_flow.json");

// --- fixture helpers -------------------------------------------------------

pub fn field<'a>(json: &'a str, key: &str) -> &'a str {
    let needle = format!("\"{key}\"");
    let start = json.find(&needle).expect("key present") + needle.len();
    let rest = &json[start..];
    let q1 = rest.find('"').expect("open quote") + 1;
    let q2 = rest[q1..].find('"').expect("close quote") + q1;
    &rest[q1..q2]
}

/// A real `InclusionProof` and `CertificationData` taken from the cross-SDK
/// fixture (the first transfer of the Carol token).
pub fn fixture_proof_and_data() -> (InclusionProof, CertificationData) {
    let carol = hex::decode(field(FIXTURE, "carolToken")).unwrap();
    let token = Token::from_cbor(&carol).unwrap();
    let proof = token.transactions()[0].inclusion_proof().clone();
    let data = proof.certification_data.clone();
    (proof, data)
}

/// Wrap an inclusion proof as the `[blockNumber, InclusionProof]` response body
/// the aggregator returns, hex-encoded.
pub fn proof_response_hex(proof: &InclusionProof) -> String {
    hex::encode(
        InclusionProofResponse::Certified {
            block_number: 7,
            proof: proof.clone(),
        }
        .to_cbor(),
    )
}

/// The same wrapper for a leaf that is not certified yet: the three leaf fields
/// are absent together, which is what aggregator-go returns while pending.
pub fn empty_proof_response_hex(proof: &InclusionProof) -> String {
    hex::encode(
        InclusionProofResponse::NotCertified {
            block_number: 7,
            unicity_certificate: proof.unicity_certificate.clone(),
        }
        .to_cbor(),
    )
}

/// A response whose leaf fields are only partly present, which no aggregator
/// may send. Assembled by hand: neither `InclusionProof` nor
/// `InclusionProofResponse` can represent it, which is what this asserts.
pub fn partial_proof_response_hex(proof: &InclusionProof, keep_reference_time: bool) -> String {
    let reference_time = if keep_reference_time {
        encode_uint(proof.reference_time)
    } else {
        encode_null()
    };
    let inner = encode_tag(
        INCLUSION_PROOF_TAG,
        &encode_array(&[
            &encode_uint(1),
            &encode_null(),
            &reference_time,
            &encode_null(),
            &proof.unicity_certificate.to_cbor(),
        ]),
    );
    hex::encode(encode_array(&[encode_uint(7).as_slice(), inner.as_slice()]))
}

/// A state id with all 32 bytes equal to `b`.
pub fn state_id(b: u8) -> StateId {
    let cbor = encode_byte_string(&[b; 32]);
    StateId::from_cbor(Decoder::new(&cbor)).unwrap()
}

#[allow(unused_imports)]
pub use self::mock::*;

mod mock {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    /// What the scripted server does with one request.
    pub struct Reply {
        /// Sleep before answering (a held long-poll).
        pub delay: Duration,
        pub body: Body,
    }

    pub enum Body {
        /// JSON-RPC `result` JSON.
        Result(String),
        /// JSON-RPC `error` object JSON.
        Error(String),
        /// A full raw HTTP response.
        Raw(Vec<u8>),
        /// Accept the connection and never answer.
        Silent,
    }

    impl Reply {
        pub fn result(json: impl Into<String>) -> Self {
            Reply {
                delay: Duration::ZERO,
                body: Body::Result(json.into()),
            }
        }
        pub fn error(json: impl Into<String>) -> Self {
            Reply {
                delay: Duration::ZERO,
                body: Body::Error(json.into()),
            }
        }
        pub fn after(mut self, d: Duration) -> Self {
            self.delay = d;
            self
        }
        pub fn silent() -> Self {
            Reply {
                delay: Duration::ZERO,
                body: Body::Silent,
            }
        }
        pub fn raw(bytes: Vec<u8>) -> Self {
            Reply {
                delay: Duration::ZERO,
                body: Body::Raw(bytes),
            }
        }
    }

    /// One received request.
    #[derive(Clone, Debug)]
    pub struct Seen {
        pub at: Instant,
        pub method: String,
        /// The JSON `params` value.
        pub params: serde_json::Value,
    }

    pub struct Scripted {
        pub url: String,
        pub seen: Arc<Mutex<Vec<Seen>>>,
    }

    impl Scripted {
        /// `script(i, request)` decides the reply of the i-th request (0-based).
        /// Every connection runs on its own thread so a silent or delayed reply
        /// never blocks the next request.
        pub fn start(script: impl Fn(usize, &Seen) -> Reply + Send + Sync + 'static) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let seen = Arc::new(Mutex::new(Vec::new()));
            let script = Arc::new(script);
            let log = seen.clone();
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { continue };
                    let script = script.clone();
                    let log = log.clone();
                    std::thread::spawn(move || {
                        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
                        let request = read_http_request(&mut stream);
                        let body = request.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
                        let json: serde_json::Value =
                            serde_json::from_str(body).unwrap_or(serde_json::Value::Null);
                        let id = json["id"].clone();
                        let entry = Seen {
                            at: Instant::now(),
                            method: json["method"].as_str().unwrap_or("").to_string(),
                            params: json["params"].clone(),
                        };
                        let index = {
                            let mut l = log.lock().unwrap();
                            l.push(entry.clone());
                            l.len() - 1
                        };
                        let reply = script(index, &entry);
                        std::thread::sleep(reply.delay);
                        let bytes = match reply.body {
                            Body::Silent => {
                                std::thread::sleep(Duration::from_secs(30));
                                return;
                            }
                            Body::Raw(b) => b,
                            Body::Result(r) => http_response(
                                "200 OK",
                                &format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{r}}}"#),
                            ),
                            Body::Error(e) => http_response(
                                "200 OK",
                                &format!(r#"{{"jsonrpc":"2.0","id":{id},"error":{e}}}"#),
                            ),
                        };
                        let _ = stream.write_all(&bytes);
                        let _ = stream.flush();
                    });
                }
            });
            Scripted {
                url: format!("http://127.0.0.1:{port}/"),
                seen,
            }
        }

        pub fn count(&self) -> usize {
            self.seen.lock().unwrap().len()
        }
        pub fn request(&self, i: usize) -> Seen {
            self.seen.lock().unwrap()[i].clone()
        }
    }
}

/// Read a full HTTP request (headers + Content-Length body) from the stream.
pub fn read_http_request(stream: &mut std::net::TcpStream) -> String {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
                    let header_end = pos + 4;
                    if buf.len() >= header_end + content_length(&buf[..header_end]) {
                        break;
                    }
                }
            }
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

pub fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

pub fn content_length(headers: &[u8]) -> usize {
    let text = String::from_utf8_lossy(headers);
    for line in text.lines() {
        if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            if let Ok(n) = value.trim().parse::<usize>() {
                return n;
            }
        }
    }
    0
}

pub fn http_response(status_line: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}
