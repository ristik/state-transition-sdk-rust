//! The shared maximum-size entry (bft-go-base 81ee667) through the history: bundle load, append, export, install.
#![cfg(feature = "std")]

use serde_json::Value;
use unicity_token::api::bft::{Appended, TrustBaseEntry, TrustBaseHistory};

fn fixture() -> Value {
    serde_json::from_slice(include_bytes!("vectors/trust-base-v2-max/max-entry.json")).unwrap()
}

fn hx(v: &Value, key: &str) -> Vec<u8> {
    hex::decode(v[key].as_str().unwrap()).unwrap()
}

fn pin(v: &Value) -> [u8; 32] {
    hx(v, "genesisId").try_into().unwrap()
}

#[test]
fn the_two_entry_bundle_loads_exports_the_same_bytes_and_installs() {
    let v = fixture();
    let bundle = hx(&v, "bundle");
    let h = TrustBaseHistory::from_bundle(&bundle, Some(pin(&v))).unwrap();
    assert_eq!(h.latest().epoch, 2);
    assert_eq!(
        hex::encode(h.latest().entry_id()),
        v["entryId"].as_str().unwrap()
    );
    assert_eq!(h.to_bundle(), bundle, "export is the same bytes");
    // append from the genesis alone
    let genesis = TrustBaseEntry::from_cbor(&hx(&v, "genesis")).unwrap();
    let entry = TrustBaseEntry::from_cbor(&hx(&v, "entry")).unwrap();
    let mut a = TrustBaseHistory::from_genesis(genesis.clone(), Some(pin(&v))).unwrap();
    assert_eq!(a.append(entry.clone()), Ok(Appended::Added));
    assert_eq!(a.append(entry), Ok(Appended::AlreadyHeld));
    assert_eq!(a.to_bundle(), bundle);
    // install into a history that holds only the genesis
    let mut b = TrustBaseHistory::from_genesis(genesis, Some(pin(&v))).unwrap();
    b.install_bundle(&bundle).unwrap();
    assert_eq!(b.latest().epoch, 2);
}
