// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Public identity verification for a concealed, host-bound core-cell backup.
//! No transaction or consensus message is signed here. BLS proof of possession
//! uses the exact domain in the pinned Kaia crypto/bls implementation.

use k256::ecdsa::SigningKey;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use zeroize::Zeroizing;

const POP_DOMAIN: &[u8] = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Public data required for external node registration.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicIdentity {
    /// Ethereum-compatible address derived from the dedicated consensus key.
    pub address: String,
    /// Uncompressed secp256k1 public key, excluding the 0x04 prefix.
    pub peer_key: String,
    /// Compressed BLS public key, as returned by `admin_nodeInfo`.
    pub bls_key: String,
    /// BLS proof of possession, as returned by `admin_nodeInfo`.
    pub bls_pop: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    schema: u8,
    owner: String,
    network: String,
    node_kind: String,
    binding: String,
    nodekey: SecretString,
    bls_nodekey: SecretString,
}

/// Holds the original concealed encoding for an exact 1Password read-back.
/// Deliberately does not implement Debug or serialization.
pub struct Capsule {
    encoded: SecretString,
    identity: PublicIdentity,
    digest: String,
}
impl Capsule {
    /// Validate the host's key material and immutable ownership before backup.
    ///
    /// # Errors
    /// Rejects malformed material, cross-owner/network/kind data and a BLS key
    /// that differs from the pinned native derivation of the original nodekey.
    pub fn parse(
        encoded: SecretString,
        owner: &str,
        network: &str,
        node_kind: &str,
    ) -> Result<Self, &'static str> {
        if encoded.expose_secret().len() > 16_384 {
            return Err("Kaia custody response exceeds its bounded format");
        }
        let wire: Wire = serde_json::from_str(encoded.expose_secret())
            .map_err(|_| "invalid concealed Kaia custody response")?;
        if owner.is_empty()
            || owner.len() > 80
            || !owner
                .bytes()
                .all(|v| v.is_ascii_lowercase() || v.is_ascii_digit())
            || wire.schema != 1
            || wire.owner != owner
            || wire.network != network
            || wire.node_kind != node_kind
            || !matches!(node_kind, "cn" | "pn")
            || crate::Network::parse(network).is_none()
            || wire.binding.len() != 64
            || !wire.binding.bytes().all(|v| v.is_ascii_hexdigit())
        {
            return Err("Kaia custody ownership or host binding differs");
        }
        let node = decode(&wire.nodekey)?;
        let scalar = decode(&wire.bls_nodekey)?;
        let signing =
            SigningKey::from_slice(node.as_ref()).map_err(|_| "invalid Kaia consensus scalar")?;
        let point = signing.verifying_key().to_sec1_point(false);
        let peer = &point.as_bytes()[1..];
        let derived = blst::min_pk::SecretKey::key_gen(node.as_ref(), &[])
            .map_err(|_| "Kaia BLS derivation failed")?;
        let derived_bytes = Zeroizing::new(derived.to_bytes());
        if scalar.as_ref() != derived_bytes.as_ref() {
            return Err("Kaia BLS key differs from the original node identity");
        }
        let public = derived.sk_to_pk().to_bytes();
        let proof = derived.sign(&public, POP_DOMAIN, &[]).to_bytes();
        let address = Keccak256::digest(peer);
        let identity = PublicIdentity {
            address: format!("0x{}", hex(&address[12..])),
            peer_key: hex(peer),
            bls_key: hex(&public),
            bls_pop: hex(&proof),
        };
        let digest = hex(&Sha256::digest(encoded.expose_secret().as_bytes()));
        Ok(Self {
            encoded,
            identity,
            digest,
        })
    }

    /// Borrow the concealed original payload only for the backup transport.
    #[must_use]
    pub const fn secret(&self) -> &SecretString {
        &self.encoded
    }
    /// Public identity derived independently of the remote response metadata.
    #[must_use]
    pub const fn public(&self) -> &PublicIdentity {
        &self.identity
    }
    /// Binds the backup read-back acknowledgment to this exact host payload.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

fn decode(value: &SecretString) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    let text = value.expose_secret().as_bytes();
    if text.len() != 64 {
        return Err("invalid Kaia custody scalar encoding");
    }
    let mut output = Zeroizing::new([0u8; 32]);
    for (index, pair) in text.as_chunks::<2>().0.iter().enumerate() {
        let nibble = |v: u8| match v {
            b'0'..=b'9' => Some(v - b'0'),
            b'a'..=b'f' => Some(v - b'a' + 10),
            _ => None,
        };
        output[index] = nibble(pair[0]).ok_or("invalid Kaia custody scalar encoding")? * 16
            + nibble(pair[1]).ok_or("invalid Kaia custody scalar encoding")?;
    }
    Ok(output)
}
fn hex(value: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> SecretString {
        // Published EIP-712 example, never an operational account.
        let node = Keccak256::digest(b"cow");
        let bls = blst::min_pk::SecretKey::key_gen(&node, &[]).expect("public test vector");
        SecretString::from(
            json!({"schema":1,"owner":"fixture","network":"kairos","node_kind":"cn",
            "binding":"a".repeat(64),"nodekey":hex(&node),"bls_nodekey":hex(&bls.to_bytes())})
            .to_string(),
        )
    }

    #[test]
    fn public_eip712_identity_and_native_bls_pop_are_bound_to_concealed_material() {
        let capsule = Capsule::parse(fixture(), "fixture", "kairos", "cn").expect("valid fixture");
        assert_eq!(
            capsule.public().address,
            "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826"
        );
        assert_eq!(capsule.public().peer_key.len(), 128);
        assert_eq!(capsule.public().bls_key.len(), 96);
        assert_eq!(capsule.public().bls_pop.len(), 192);
        assert_eq!(
            capsule.digest(),
            hex(&Sha256::digest(capsule.secret().expose_secret().as_bytes()))
        );
        assert!(
            !serde_json::to_string(capsule.public())
                .unwrap()
                .contains("nodekey")
        );
    }

    #[test]
    fn cross_owner_network_kind_and_substituted_scalars_are_refused_without_echo() {
        for (owner, network, kind) in [
            ("foreign", "kairos", "cn"),
            ("fixture", "mainnet", "cn"),
            ("fixture", "kairos", "pn"),
        ] {
            assert!(Capsule::parse(fixture(), owner, network, kind).is_err());
        }
        let original = fixture();
        for key in ["nodekey", "bls_nodekey"] {
            let mut value: serde_json::Value =
                serde_json::from_str(original.expose_secret()).unwrap();
            value[key] = json!("01".repeat(32));
            let changed = SecretString::from(value.to_string());
            let error = Capsule::parse(changed, "fixture", "kairos", "cn")
                .err()
                .unwrap();
            assert!(!error.contains(&"01".repeat(32)));
        }
        let oversized = SecretString::from("x".repeat(16_385));
        assert!(Capsule::parse(oversized, "fixture", "kairos", "cn").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn host_hkdf_derivation_matches_the_pinned_native_blst_keygen() {
        let script =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("templates/node/custody.py");
        let output = std::process::Command::new("python3")
            .args(["-I", "-B", "-c", "import hashlib,importlib.util,sys; s=importlib.util.spec_from_file_location('custody',sys.argv[1]); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); [print(hashlib.sha256(m.derive_bls(bytes([v])*32)).hexdigest()) for v in (0,1,255)]"])
            .arg(script)
            .output().expect("offline Python derivation");
        assert!(output.status.success());
        let actual = String::from_utf8(output.stdout).unwrap();
        let expected = [0, 1, 255].map(|value| {
            let scalar = blst::min_pk::SecretKey::key_gen(&[value; 32], &[]).unwrap();
            hex(&Sha256::digest(scalar.to_bytes()))
        });
        assert_eq!(actual.lines().collect::<Vec<_>>(), expected);
    }
}
