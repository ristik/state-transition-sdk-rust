//! `X-SDK-Version: rust/<crate version>` on every aggregator request (owner §43), default on, switchable, validated.
#![cfg(feature = "http")]

mod common;

use common::*;
use unicity_token::client::{
    AggregatorClient, HttpAggregatorClient, HttpError, SdkVersionHeader, SDK_VERSION,
};

fn client(url: &str) -> HttpAggregatorClient {
    HttpAggregatorClient::new_insecure_http(url)
}

/// Make one request of each kind the client has; the replies do not matter, the request headers do.
fn every_method(c: &HttpAggregatorClient) {
    let (proof, data) = fixture_proof_and_data();
    let _ = c.submit_certification_request(&data);
    let _ = c.get_inclusion_proof(&state_id(1));
    let _ = unicity_token::client::NonInclusionAggregatorClient::get_non_inclusion_proof(
        c,
        &state_id(2),
    );
    drop(proof);
}

fn server() -> Scripted {
    Scripted::start(|_, _| Reply::error(r#"{"code":-32000,"message":"no"}"#))
}

#[test]
fn the_default_is_rust_slash_the_crate_version_on_every_method() {
    assert_eq!(SDK_VERSION, concat!("rust/", env!("CARGO_PKG_VERSION")));
    let s = server();
    every_method(&client(&s.url));
    assert!(s.count() >= 3);
    let methods: Vec<String> = (0..s.count()).map(|i| s.request(i).method).collect();
    for needle in [
        "certification_request",
        "get_inclusion_proof.v2",
        "get_non_inclusion_proof.v1",
    ] {
        assert!(
            methods.iter().any(|m| m == needle),
            "{needle} in {methods:?}"
        );
    }
    for i in 0..s.count() {
        assert_eq!(
            s.request(i).header("x-sdk-version"),
            vec![SDK_VERSION.to_string()],
            "{}",
            s.request(i).method
        );
    }
}

#[test]
fn off_sends_no_header() {
    let s = server();
    every_method(
        &client(&s.url)
            .with_sdk_version_header(SdkVersionHeader::Off)
            .unwrap(),
    );
    assert!(s.count() >= 3);
    for i in 0..s.count() {
        assert!(s.request(i).header("x-sdk-version").is_empty());
    }
}

#[test]
fn a_custom_value_is_sent_as_it_is() {
    let s = server();
    every_method(
        &client(&s.url)
            .with_sdk_version_header(SdkVersionHeader::Custom("my-wallet/1.2 (rust/x)".into()))
            .unwrap(),
    );
    for i in 0..s.count() {
        assert_eq!(
            s.request(i).header("x-sdk-version"),
            vec!["my-wallet/1.2 (rust/x)".to_string()]
        );
    }
}

#[test]
fn a_value_that_is_not_printable_ascii_is_refused_at_construction() {
    for bad in ["", "caf\u{e9}", "a\nb", "a\u{7f}b", "tab\there"] {
        let r = client("http://127.0.0.1:1/")
            .with_sdk_version_header(SdkVersionHeader::Custom(bad.to_string()));
        assert!(matches!(r, Err(HttpError::Configuration(_))), "{bad:?}");
    }
    // the default can be restored after switching off
    let c = client("http://127.0.0.1:1/")
        .with_sdk_version_header(SdkVersionHeader::Off)
        .unwrap()
        .with_sdk_version_header(SdkVersionHeader::Default)
        .unwrap();
    let _ = c;
}
