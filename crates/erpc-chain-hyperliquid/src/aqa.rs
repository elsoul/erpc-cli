// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Separate original AQA agent authority; approval and financial management stay external.
use crate::{Network, validator};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Bind the original SSH destination and pinned public host key.
#[must_use]
pub fn host_binding(address: &str, user: &str, port: u16, host_key: &str) -> String {
    format!(
        "{:x}",
        Sha256::digest(format!("{address}\0{user}\0{port}\0{host_key}").as_bytes())
    )
}

/// Public, compiled publisher catalog.
/// # Errors
/// Refuses corrupted embedded qualification metadata.
pub fn catalog() -> Result<serde_json::Value, &'static str> {
    serde_json::from_slice(include_bytes!("../templates/aqa/catalog.json"))
        .map_err(|_| "invalid embedded AQA catalog")
}

/// External authentication of a sealed carried controller before interpretation.
#[must_use]
pub fn carried_loader() -> String {
    format!(
        "{}\nimport runpy,sys\nfrom pathlib import Path\np=Path(sys.argv[1])\nif not p.is_absolute() or p.name!='control.py': raise ValueError('invalid carried AQA controller')\ntrusted_imports(str(p.parent))\nsys.argv=sys.argv[1:]\nrunpy.run_path(str(p),run_name='__main__')",
        include_str!("../templates/aqa/erpc_aqa_trust.py")
    )
}

/// Canonical management networks; public publisher ports are never opened.
/// # Errors
/// Refuses unbounded lists, all-address ranges and ambiguous mapped addresses.
pub fn management(values: &[String]) -> Result<Vec<String>, &'static str> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    if values.len() > 128 {
        return Err("too many management networks");
    }
    let mut output = Vec::new();
    for value in values {
        let (address, prefix) = value
            .split_once('/')
            .map_or((value.as_str(), None), |(a, p)| (a, Some(p)));
        let address = address
            .parse::<IpAddr>()
            .map_err(|_| "invalid management address")?;
        let maximum = if address.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.map_or(Ok(maximum), |text| {
            text.parse::<u8>().map_err(|_| "invalid management prefix")
        })?;
        if prefix == 0 || prefix > maximum {
            return Err("management network must have a restricted prefix");
        }
        let network = match address {
            IpAddr::V4(ip) => {
                IpAddr::V4(Ipv4Addr::from(u32::from(ip) & (u32::MAX << (32 - prefix))))
            }
            IpAddr::V6(ip) => {
                if ip.to_ipv4_mapped().is_some() {
                    return Err("use explicit IPv4 management networks");
                }
                IpAddr::V6(Ipv6Addr::from(
                    u128::from(ip) & (u128::MAX << (128 - prefix)),
                ))
            }
        };
        output.push(format!("{network}/{prefix}"));
    }
    output.sort_unstable();
    output.dedup();
    Ok(output)
}

/// Explicit public validator, consensus and agent approval relationship.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    /// Original external validator address; never a hosted private key.
    pub validator: String,
    /// Separate original consensus signer; never mounted on the AQA host.
    pub consensus_signer: String,
    /// Operator-selected master that externally approved this agent.
    pub agent_master: String,
    /// Dedicated agent address, with the platform's general agent authority.
    pub agent: String,
    /// Original uncompressed SEC1 point, independently verified by the host.
    pub agent_public_key: String,
    /// Exact named approval; empty/unnamed agents are outside this profile.
    pub agent_name: String,
}
impl Identity {
    /// Verify distinct keys and public binding without claiming vote eligibility.
    /// # Errors
    /// Rejects ambiguous addresses, name or substituted public point.
    pub fn validate(&self) -> Result<(), &'static str> {
        for value in [
            &self.validator,
            &self.consensus_signer,
            &self.agent_master,
            &self.agent,
        ] {
            validator::address(value)?;
        }
        if self.validator == self.consensus_signer
            || [&self.validator, &self.consensus_signer, &self.agent_master].contains(&&self.agent)
            || validator::point_address(&self.agent_public_key)? != self.agent
            || self.agent_name.is_empty()
            || self.agent_name.len() > 16
            || !self
                .agent_name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
        {
            return Err("AQA requires a separate original agent and exact bounded approval name");
        }
        Ok(())
    }
}

/// Immutable separate-host authority; no credential reference or private value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contract {
    /// Fixed ownership schema.
    pub schema: u8,
    /// Explicit profile, preventing adoption by a consensus or RPC controller.
    pub profile: String,
    /// Random original inventory identity.
    pub owner: String,
    /// Explicit native network; no implicit mainnet fallback.
    pub network: Network,
    /// Original SSH address/key binding digest.
    pub host_binding: String,
    /// Original public key and externally selected approval scope.
    pub identity: Identity,
}
impl Contract {
    /// Check the public host and original authority before inventory or SSH use.
    /// # Errors
    /// Rejects other profiles, malformed owners and unsafe identity substitution.
    pub fn validate(&self) -> Result<(), &'static str> {
        fn hexadecimal(value: &str, length: usize) -> bool {
            value.len() == length
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }
        if self.schema != 1
            || self.profile != "hyperliquid-aqa"
            || !hexadecimal(&self.owner, 32)
            || !hexadecimal(&self.host_binding, 64)
        {
            return Err("invalid original AQA host contract");
        }
        self.identity.validate()
    }
}

/// Concealed original scalar object. Never formats or signs with its private value.
pub struct AgentMaterial(validator::HotMaterial);
impl std::fmt::Debug for AgentMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AgentMaterial([REDACTED])")
    }
}
impl AgentMaterial {
    /// Parse exactly one operator-provided key object; never generate a key.
    /// # Errors
    /// Invalid, extra or duplicated fields are refused without exposing input.
    pub fn parse(original: SecretString) -> Result<Self, &'static str> {
        validator::HotMaterial::parse(original)
            .map(Self)
            .map_err(|_| "invalid concealed original AQA key object")
    }
    /// Bind public roles without inferring which master the protocol requires.
    /// # Errors
    /// Refuses reuse of the validator, consensus or approving master key.
    pub fn identity(
        &self,
        validator: &str,
        consensus_signer: &str,
        agent_master: &str,
        agent_name: &str,
    ) -> Result<Identity, &'static str> {
        let (agent, agent_public_key) = self.0.public_identity();
        let value = Identity {
            validator: validator.into(),
            consensus_signer: consensus_signer.into(),
            agent_master: agent_master.into(),
            agent: agent.into(),
            agent_public_key: agent_public_key.into(),
            agent_name: agent_name.into(),
        };
        value.validate()?;
        Ok(value)
    }
    /// Original bytes solely for concealed stdin transport and encrypted custody.
    #[must_use]
    pub fn original(&self) -> &SecretString {
        self.0.original()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret as _;
    #[test]
    fn original_agent_cannot_be_a_cold_consensus_or_master_key() {
        let text = format!("{{\"key\":\"{}\"}}", "01".repeat(32));
        let material = AgentMaterial::parse(text.clone().into()).unwrap();
        assert_eq!(material.original().expose_secret(), text);
        assert_eq!(format!("{material:?}"), "AgentMaterial([REDACTED])");
        let cold = format!("0x{}", "ab".repeat(20));
        let hot = format!("0x{}", "cd".repeat(20));
        let public = material.identity(&cold, &hot, &cold, "erpc-aqa").unwrap();
        for (validator, signer, master) in [
            (&public.agent, &hot, &cold),
            (&cold, &public.agent, &cold),
            (&cold, &hot, &public.agent),
        ] {
            assert!(
                material
                    .identity(validator, signer, master, "erpc-aqa")
                    .is_err()
            );
        }
        let mut changed = public.clone();
        changed.agent = hot;
        assert!(changed.validate().is_err());
        assert!(
            material
                .identity(&cold, &public.consensus_signer, &cold, "name valid_until 1")
                .is_err()
        );
        let contract = Contract {
            schema: 1,
            profile: "hyperliquid-aqa".into(),
            owner: "a".repeat(32),
            network: Network::Testnet,
            host_binding: "b".repeat(64),
            identity: public,
        };
        contract.validate().unwrap();
        let mut wrong = contract;
        wrong.profile = "hyperliquid-validator".into();
        assert!(wrong.validate().is_err());
    }
}
