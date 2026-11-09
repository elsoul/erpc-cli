// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

use super::ConsensusKey;

// Public RFC 8032 test 1: never operational material or new key generation.
const SEED_B64: &str = "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=";
const PUBLIC_B64: &str = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";

#[test]
fn original_public_vector_has_the_native_wire_form_without_debug_disclosure() {
    let key = ConsensusKey::parse_seed(SEED_B64).unwrap();
    assert_eq!(key.public_key(), PUBLIC_B64);
    assert_eq!(
        key.node_json().as_str(),
        format!("{{\"type\":\"tendermint/PrivKeyEd25519\",\"value\":\"{SEED_B64}\"}}")
    );
    assert!(!format!("{key:?}").contains(SEED_B64));
    for bad in ["", "not base64!", "AAAA", PUBLIC_B64.trim_end_matches('=')] {
        assert!(ConsensusKey::parse_seed(bad).is_err());
    }
}
