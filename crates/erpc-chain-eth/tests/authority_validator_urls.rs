// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Carried URL scope includes only the two dedicated validator TLS audiences.
#[test]
fn carried_urls_remain_in_their_exact_role_scope() {
    for path in erpc_chain_eth::files()
        .into_iter()
        .filter(|p| !p.starts_with("gpg/"))
    {
        let mut body = std::str::from_utf8(erpc_chain_eth::file(path).unwrap())
            .unwrap()
            .replace("http://127.0.0.1", "")
            .replace(&["https:", "//mainnet.checkpoint.sigp.io"].concat(), "")
            .replace(&["https:", "//hoodi.checkpoint.sigp.io"].concat(), "");
        if path.starts_with("authority/eth_validator_") {
            body = body
                .replace("https://127.0.0.2", "")
                .replace("https://127.0.0.3", "");
        }
        assert!(!body.contains("http://"), "{path}");
        assert!(!body.contains("https://"), "{path}");
    }
}
