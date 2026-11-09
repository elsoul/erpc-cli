// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Public BSC validator identities, proof of possession, and external registration.
//! No operator key, transaction signer, deposit submission or private key export.

use crate::Network;
use serde_json::{Value, json};
use sha3::{Digest, Keccak256};

const BLS_DOMAIN: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
/// Native `StakeHub` address, separate from the validator's financial operator.
pub const STAKE_HUB: &str = "0x0000000000000000000000000000000000002002";

fn bytes<const N: usize>(text: &str) -> Result<[u8; N], &'static str> {
    let text = text.strip_prefix("0x").unwrap_or(text);
    if text.len() != N * 2 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid public identity encoding");
    }
    let mut out = [0; N];
    for (slot, pair) in out.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
        let digit = |v: u8| {
            if v <= b'9' {
                v - b'0'
            } else {
                v.to_ascii_lowercase() - b'a' + 10
            }
        };
        *slot = digit(pair[0]) * 16 + digit(pair[1]);
    }
    Ok(out)
}
fn hex(raw: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut result = String::with_capacity(raw.len() * 2);
    for value in raw {
        let _ = write!(result, "{value:02x}");
    }
    result
}
/// Canonical nonzero EVM public address. Mixed-case input is treated as raw hex.
/// # Errors
/// Rejects malformed, oversized or zero addresses.
pub fn address(text: &str) -> Result<String, &'static str> {
    let value = bytes::<20>(text)?;
    if value == [0; 20] {
        return Err("validator addresses must be nonzero");
    }
    Ok(format!("0x{}", hex(&value)))
}
fn chain_id(network: Network) -> u64 {
    match network {
        Network::Mainnet => 56,
        Network::Chapel => 97,
    }
}
fn proof_message(network: Network, operator: &[u8; 20], vote: &[u8; 48]) -> [u8; 32] {
    let mut chain = [0; 32];
    chain[24..].copy_from_slice(&chain_id(network).to_be_bytes());
    let mut digest = Keccak256::new();
    digest.update(operator);
    digest.update(vote);
    digest.update(chain);
    digest.finalize().into()
}
fn verify(message: &[u8; 32], vote: &[u8; 48], proof: &[u8; 96]) -> Result<(), &'static str> {
    let public =
        blst::min_pk::PublicKey::key_validate(vote).map_err(|_| "invalid BSC vote public key")?;
    let signature = blst::min_pk::Signature::sig_validate(proof, true)
        .map_err(|_| "invalid BSC possession proof")?;
    if signature.verify(true, message, BLS_DOMAIN, &[], &public, true)
        != blst::BLST_ERROR::BLST_SUCCESS
    {
        return Err("BSC possession proof does not bind this operator, vote key and network");
    }
    Ok(())
}
/// Verify the pinned Geth/`StakeHub` proof domain and prepare public external-tool inputs.
/// The possession proof binds operator, vote key and chain ID; consensus identity
/// is separately preserved in the host contract and checked against registration.
/// # Errors
/// Rejects duplicate roles, malformed/infinity points, or any mismatching proof.
pub fn registration(
    network: Network,
    operator: &str,
    consensus: &str,
    vote: &str,
    proof: &str,
) -> Result<Value, &'static str> {
    let operator = address(operator)?;
    let consensus = address(consensus)?;
    if operator == consensus {
        return Err("operator and consensus identities must be separate");
    }
    let vote = bytes::<48>(vote)?;
    let proof = bytes::<96>(proof)?;
    verify(
        &proof_message(network, &bytes::<20>(&operator)?, &vote),
        &vote,
        &proof,
    )?;
    Ok(
        json!({"network":network.name(),"chain_id":chain_id(network),"operator_address":operator,
        "consensus_address":consensus,"vote_public_key":hex(&vote),"proof":format!("0x{}",hex(&proof)),
        "stake_hub":STAKE_HUB,"financial_signing":"external","registration_tool":"official BNB staking dApp"}),
    )
}
/// Fixed read-only `StakeHub` calls for an exact public operator address.
/// # Errors
/// Rejects a malformed/zero address. No mutable contract method is exposed.
pub fn registration_queries(operator: &str) -> Result<Value, &'static str> {
    let operator = bytes::<20>(&address(operator)?)?;
    let mut word = [0; 32];
    word[12..].copy_from_slice(&operator);
    let query = |method: &str| {
        let selector = Keccak256::digest(method.as_bytes());
        json!({"to":STAKE_HUB,"data":format!("0x{}{}",hex(&selector[..4]),hex(&word))})
    };
    Ok(
        json!({"consensus":query("getValidatorConsensusAddress(address)"),
        "vote":query("getValidatorVoteAddress(address)"),"basic":query("getValidatorBasicInfo(address)")}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_geth_precompile_vector_matches_the_selected_bls_domain() {
        // Public mathematical test vector (message || signature || public key):
        // https://github.com/bnb-chain/bsc/blob/cdb7548b5baacfdae92f9f63437d6456411665f3/core/vm/testdata/precompiles/blsSignatureVerify.json
        let raw=bytes::<176>("f2d8e8e5bf354429e3ce8b97c4e88f7a0bf7bc917e856de762ed6d70dd8ec2d289a04d63285e4b45309e7c180ea82565e375dd62c7b80d957aea4c9b7e16bdb28a0f910036bd3220fe3d7614fb137a8f0a68b3c564ddd214b5041d8f7a124e6e7285ac42635e75eeb9051a052fb500b1c2bc23bd4290db59fc02be11f2b80896b6e22d5b8dd31ba2e49b13cd6be19fcd01c1e23af3e5165d88d8b9deaf38baa77770fa6a358e2eebdffd1bd8a1eb7386").expect("published vector");
        let mut message: [u8; 32] = raw[..32].try_into().expect("message");
        let signature = raw[32..128].try_into().expect("signature");
        let public = raw[128..].try_into().expect("public key");
        verify(&message, &public, &signature).expect("Geth accepted vector");
        message[0] ^= 1;
        assert!(verify(&message, &public, &signature).is_err());
        assert!(verify(&message, &[0; 48], &signature).is_err());
    }

    #[test]
    fn registration_rejects_cross_network_and_cross_operator_replay() {
        // Deterministic test-only scalar, never a generated or funded node key.
        let fixture = blst::min_pk::SecretKey::from_bytes(&[1; 32]).expect("synthetic scalar");
        let vote = fixture.sk_to_pk().to_bytes();
        let operator = [2; 20];
        let proof = fixture
            .sign(
                &proof_message(Network::Mainnet, &operator, &vote),
                BLS_DOMAIN,
                &[],
            )
            .to_bytes();
        let operator = hex(&operator);
        let consensus = hex(&[3; 20]);
        let vote = hex(&vote);
        let proof = hex(&proof);
        let reviewed = registration(Network::Mainnet, &operator, &consensus, &vote, &proof)
            .expect("bound proof");
        assert_eq!(reviewed["chain_id"], 56);
        assert!(registration(Network::Chapel, &operator, &consensus, &vote, &proof).is_err());
        assert!(registration(Network::Mainnet, &hex(&[4; 20]), &consensus, &vote, &proof).is_err());
        assert!(registration(Network::Mainnet, &operator, &operator, &vote, &proof).is_err());
        assert!(address(&hex(&[0; 20])).is_err());
        assert!(address("not-an-address").is_err());
        let queries = registration_queries(&operator).expect("read-only calls");
        assert_eq!(queries.as_object().expect("query set").len(), 3);
        for (name, selector) in [
            ("consensus", "059ddd22"),
            ("vote", "6f8e2fa4"),
            ("basic", "cbb04d9d"),
        ] {
            assert!(
                queries[name]["data"]
                    .as_str()
                    .expect("ABI input")
                    .starts_with(&format!("0x{selector}"))
            );
        }
        assert_eq!(
            queries["consensus"]["data"]
                .as_str()
                .expect("ABI input")
                .len(),
            74
        );
    }
}
