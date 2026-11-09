// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Public authority for an isolated Arc validator; governance keys stay external.
use serde::{Deserialize, Serialize};
use sha3::{Digest as _, Keccak256};
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};

/// Dedicated validator protocol, separate from the existing RPC contract.
pub const SCHEMA: &str = "erpc-arc-validator-v1";
/// Pinned native consensus source qualified for this profile.
pub const SOURCE: &str = "ab09dbfd9553a7ad48f9c134ec5e808c36512c74";
/// Native registry predeploy, also used by the execution-engine client.
pub const REGISTRY: &str = "0x3600000000000000000000000000000000000002";
/// Permissioned governance manager; ERPC never holds its controller/owner keys.
pub const MANAGER: &str = "0x3600000000000000000000000000000000000003";
/// Official external signer's publicly released source; its tested image is partner-delivered.
pub const REMOTE_SIGNER_SOURCE: &str = "a95f05b2d8e90af0bc9e890efd9ee7bc8b51b5b0";
/// Dedicated immutable helper namespace, separate from RPC ownership.
pub const NAMESPACE: &str = "/usr/local/lib/erpc/arc-validator";

/// Sealed entry plays for the dedicated validator preparation profile.
pub mod plays {
    /// Qualify a dedicated original namespace before inventory or identity creation.
    pub const PREFLIGHT: &str = "ansible/arc-validator/preflight.yml";
    /// Original account, public signer transport and mounted storage reservation.
    pub const INIT: &str = "ansible/arc-validator/init.yml";
    /// Short per-operation ingress preparation, confirmed from a fresh SSH session.
    pub const FIREWALL: &str = "ansible/arc-validator/firewall.yml";
    /// Original-source observer preparation; production signing remains unavailable.
    pub const DEPLOY: &str = "ansible/arc-validator/deploy.yml";
    /// Original scoped stop from a sealed carried helper when installed code is absent.
    pub const CONTROL: &str = "ansible/arc-validator/control.yml";
    /// Original scoped cancellation with all data and keys retained.
    pub const DESTROY: &str = "ansible/arc-validator/destroy.yml";
}

/// Every carried validator module plus unchanged reviewed descriptor primitives.
/// # Errors
/// Refuses missing, nested or duplicate embedded modules.
pub fn helper_files() -> Result<BTreeMap<String, Vec<u8>>, String> {
    let mut result = BTreeMap::new();
    for path in crate::files() {
        let Some(name) = path.strip_prefix("validator/") else {
            continue;
        };
        let python = matches!(
            std::path::Path::new(name)
                .extension()
                .and_then(std::ffi::OsStr::to_str),
            Some("py")
        );
        if name.contains('/') || !(python || name == "networks.json") {
            return Err("unexpected Arc validator helper source".into());
        }
        result.insert(
            name.to_owned(),
            crate::file(path)
                .ok_or("missing validator module")?
                .to_vec(),
        );
    }
    for name in [
        "arc_files.py",
        "arc_release.py",
        "arc_process.py",
        "arc_trust.py",
        "arc_helper_release.py",
    ] {
        if result
            .insert(
                name.to_owned(),
                crate::file(&format!("authority/{name}"))
                    .ok_or("missing reviewed Arc descriptor primitive")?
                    .to_vec(),
            )
            .is_some()
        {
            return Err("duplicate Arc validator helper module".into());
        }
    }
    if result.len() > 32 || !result.contains_key("control.py") {
        return Err("invalid Arc validator helper profile".into());
    }
    Ok(result)
}

/// Complete sealed validator play tree with the flat externally checked profile.
/// # Errors
/// Refuses an incomplete carried play or helper resource.
pub fn carried_files() -> Result<BTreeMap<String, Vec<u8>>, String> {
    let mut files = BTreeMap::new();
    for (name, bytes) in helper_files()? {
        files.insert(format!("validator/{name}"), bytes);
    }
    for path in [
        plays::PREFLIGHT,
        plays::INIT,
        plays::FIREWALL,
        plays::DEPLOY,
        plays::DESTROY,
        plays::CONTROL,
    ] {
        files.insert(
            path.into(),
            crate::file(path)
                .ok_or("missing Arc validator play")?
                .to_vec(),
        );
    }
    Ok(files)
}

/// Complete flat installed profile, used by the external SSH release loader.
/// # Errors
/// Refuses an incomplete embedded profile.
pub fn helper_profile() -> Result<Vec<String>, String> {
    Ok(helper_files()?.into_keys().collect())
}

/// Exact native-controller release identifier in the original helper namespace.
/// # Errors
/// Refuses an incomplete embedded profile.
pub fn helper_hash() -> Result<String, String> {
    use sha2::Sha256;
    let mut hash = Sha256::new();
    for content in helper_files()?.values() {
        hash.update(content);
    }
    Ok(format!("{:x}", hash.finalize()))
}

/// Canonical external trust check before any carried sibling module is imported.
/// # Errors
/// Refuses missing or invalid canonical verifier bytes.
pub fn carried_loader() -> Result<String, String> {
    let trust = std::str::from_utf8(
        crate::file("authority/arc_trust.py").ok_or("missing canonical Arc verifier")?,
    )
    .map_err(|_| "invalid canonical Arc verifier")?;
    Ok(format!(
        "{trust}\nimport os,runpy,sys\nscript=os.path.abspath(sys.argv[1])\ntrusted_imports(os.path.dirname(script))\nsys.argv=[script,*sys.argv[2:]]\nrunpy.run_path(script,run_name='__main__')\n"
    ))
}

/// Operator-provided qualification inputs for an already prepared official service.
///
/// These inputs record the operator's artifact/attestation evidence. They do not
/// establish live Nitro attestation or solve the opaque proposal signing history
/// limitation in the public protocol. No AWS resource or key export is implied.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteSigner {
    /// Fixed numeric HTTPS endpoint; no credentials, DNS, query or arbitrary path.
    pub endpoint: String,
    /// SHA-256 of the exact server CA certificate supplied separately by the operator.
    pub server_ca_sha256: String,
    /// Partner-provided tested OCI image digest, independently qualified by the operator.
    pub image_sha256: String,
    /// Original measured enclave image PCR0, SHA-384 hex.
    pub pcr0: String,
    /// Original measured enclave kernel PCR1, SHA-384 hex.
    pub pcr1: String,
    /// Original measured enclave application PCR2, SHA-384 hex.
    pub pcr2: String,
    /// Original parent-instance PCR4, SHA-384 hex.
    pub pcr4: String,
}

impl RemoteSigner {
    /// Validate transport and original measurement input shape without contacting AWS.
    /// # Errors
    /// Refuses credential-bearing/non-TLS endpoints or missing bounded measurements.
    pub fn validate(&self) -> Result<(), &'static str> {
        let endpoint = reqwest::Url::parse(&self.endpoint)
            .map_err(|_| "invalid operator-provided Arc signer endpoint")?;
        let address = endpoint
            .host_str()
            .ok_or("Arc signer endpoint requires its fixed numeric address")?
            .trim_matches(['[', ']'])
            .parse::<IpAddr>()
            .map_err(|_| "Arc signer endpoint requires its fixed numeric address")?;
        if endpoint.scheme() != "https"
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.path() != "/"
            || endpoint
                .port_or_known_default()
                .is_none_or(|port| port == 0)
            || address.is_unspecified()
            || address.is_multicast()
            || !lower_hex(&self.server_ca_sha256, 64)
            || !lower_hex(&self.image_sha256, 64)
            || [&self.pcr0, &self.pcr1, &self.pcr2, &self.pcr4]
                .iter()
                .any(|value| !lower_hex(value, 96))
        {
            return Err("incomplete original Arc signer transport or artifact/PCR qualification");
        }
        Ok(())
    }
}

/// Qualify a bounded single public CA certificate before any inventory/key creation.
/// This parses the trust anchor without making a network request or generating a key.
/// # Errors
/// Refuses another CA digest, private material, multiple certificates or malformed DER.
pub fn qualify_ca(profile: &RemoteSigner, raw: &str) -> Result<(), &'static str> {
    use sha2::Sha256;
    profile.validate()?;
    if raw.len() > 65536
        || !raw.starts_with("-----BEGIN CERTIFICATE-----\n")
        || !raw.trim_end().ends_with("-----END CERTIFICATE-----")
        || raw.matches("-----BEGIN CERTIFICATE-----").count() != 1
        || raw.matches("-----END CERTIFICATE-----").count() != 1
        || format!("{:x}", Sha256::digest(raw.as_bytes())) != profile.server_ca_sha256
    {
        return Err("supplied public signer CA differs from its original qualification");
    }
    let certificate =
        reqwest::Certificate::from_pem(raw.as_bytes()).map_err(|_| "invalid public signer CA")?;
    reqwest::Client::builder()
        .tls_certs_only([certificate])
        .build()
        .map_err(|_| "invalid public signer trust anchor")?;
    Ok(())
}

/// Desired native participation, never inferred from software installation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    /// Follow finalized blocks without consensus votes.
    Observer,
    /// Use the original signer only after explicit admission checks.
    Validator,
}

/// Immutable public original host/key/network identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contract {
    /// Inventory item identity from the public reservation.
    pub owner: String,
    /// Qualified Arc network.
    pub network: String,
    /// Exact source-qualified execution chain ID.
    pub chain_id: u64,
    /// Source-qualified genesis hash.
    pub genesis_hash: String,
    /// Canonical base64 Ed25519 public key; never the private seed.
    pub public_key: String,
    /// Distinct local P2P identity; this host does not hold the remote consensus seed.
    pub peer_public_key: String,
    /// External EVM controller assigned by permissioned governance.
    pub controller: String,
    /// Original pinned management connection digest.
    pub host_binding: String,
}

impl Contract {
    /// Validate immutable public fields against the carried network and key rules.
    /// # Errors
    /// Refuses another network/genesis, malformed identity or external address.
    pub fn validate(&self) -> Result<(), &'static str> {
        let network =
            crate::network::get(&self.network).ok_or("unsupported Arc validator network")?;
        if self.owner.len() != 26
            || !self
                .owner
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            || self.chain_id != network.chain_id
            || self.genesis_hash != network.genesis_hash
            || !crate::authority::public_identity(&self.public_key)
            || !crate::authority::public_identity(&self.peer_public_key)
            || self.public_key == self.peer_public_key
            || !address(&self.controller)
            || !lower_hex(&self.host_binding, 64)
        {
            return Err("invalid original Arc validator public authority");
        }
        Ok(())
    }
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Canonical nonzero external governance or fee-recipient address.
#[must_use]
pub fn address(value: &str) -> bool {
    value
        .strip_prefix("0x")
        .is_some_and(|raw| lower_hex(raw, 40) && raw.bytes().any(|b| b != b'0'))
}

fn peer_ip(value: &str) -> Option<IpAddr> {
    let ip: IpAddr = value.parse().ok()?;
    (!ip.is_unspecified() && !ip.is_multicast() && !ip.is_loopback()).then_some(ip)
}

/// Validate an explicitly approved numeric execution peer, without DNS discovery.
#[must_use]
pub fn execution_peer(value: &str) -> bool {
    let Some((key, endpoint)) = value
        .strip_prefix("enode://")
        .and_then(|v| v.split_once('@'))
    else {
        return false;
    };
    let Ok(socket) = endpoint.parse::<SocketAddr>() else {
        return false;
    };
    lower_hex(key, 128)
        && key.bytes().any(|b| b != b'0')
        && socket.port() != 0
        && peer_ip(&socket.ip().to_string()).is_some()
}

/// Validate the bounded numeric TCP/libp2p sentry form accepted by this profile.
#[must_use]
pub fn sentry_peer(value: &str) -> bool {
    if value.len() > 512 {
        return false;
    }
    let parts: Vec<_> = value.split('/').collect();
    if parts.len() != 7 || !parts[0].is_empty() || parts[3] != "tcp" || parts[5] != "p2p" {
        return false;
    }
    let Some(ip) = peer_ip(parts[2]) else {
        return false;
    };
    let family = matches!(
        (parts[1], ip),
        ("ip4", IpAddr::V4(_)) | ("ip6", IpAddr::V6(_))
    );
    let port = parts[4]
        .parse::<u16>()
        .is_ok_and(|p| p != 0 && p.to_string() == parts[4]);
    let peer = parts[6];
    family
        && port
        && (16..=128).contains(&peer.len())
        && peer
            .bytes()
            .all(|b| b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(&b))
}

/// Public operator-approved runtime policy; no governance signing material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Explicit institutional/operator approval, separate from live registry membership.
    pub approved: bool,
    /// Approved external reward destination.
    pub fee_recipient: String,
    /// Explicit execution peers supplied by the admitted operator.
    pub execution_peers: Vec<String>,
    /// Explicit consensus sentries supplied by the admitted operator.
    pub sentry_peers: Vec<String>,
    /// Observer by default; first consensus activation must be requested explicitly.
    pub phase: Phase,
    /// Observed SSH server port, never inferred from the local forwarded port.
    pub ssh_port: u16,
    /// Explicit additional IPv4 management networks.
    pub management_allow: Vec<String>,
    /// Explicit IPv4 metric-scraping networks; private listeners when empty.
    pub monitoring_allow: Vec<String>,
}

impl Policy {
    /// Check public policy shape; membership and positive voting power are runtime checks.
    /// # Errors
    /// Refuses malformed peers/fees or activation without operator approval and peers.
    pub fn validate(&self) -> Result<(), &'static str> {
        fn unique(values: &[String]) -> bool {
            values.len() <= 128
                && values
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    == values.len()
        }
        if !address(&self.fee_recipient)
            || self.ssh_port == 0
            || !unique(&self.management_allow)
            || !unique(&self.monitoring_allow)
            || !self.management_allow.iter().all(|v| network(v))
            || !self.monitoring_allow.iter().all(|v| network(v))
            || !unique(&self.execution_peers)
            || !unique(&self.sentry_peers)
            || !self.execution_peers.iter().all(|p| execution_peer(p))
            || !self.sentry_peers.iter().all(|p| sentry_peer(p))
        {
            return Err("invalid approved Arc validator policy");
        }
        if self.phase == Phase::Validator
            && (!self.approved || self.execution_peers.is_empty() || self.sentry_peers.is_empty())
        {
            return Err(
                "Arc consensus activation requires explicit operator approval and qualified sentries",
            );
        }
        Ok(())
    }
}

/// Build the dedicated ingress table from validated public policy and observed SSH peer.
/// RPC and private consensus REST ports remain loopback-only; incoming peer ports
/// admit only the explicit approved peer IPs. Outbound traffic remains unchanged.
/// # Errors
/// Refuses malformed policy or an unspecified/multicast management observation.
pub fn firewall(policy: &Policy, controller: IpAddr) -> Result<String, &'static str> {
    use std::collections::BTreeSet;
    use std::fmt::Write as _;
    policy.validate()?;
    if controller.is_unspecified() || controller.is_multicast() {
        return Err("invalid observed Arc validator management address");
    }
    let mut management_v4: BTreeSet<String> = policy.management_allow.iter().cloned().collect();
    let mut management_v6 = BTreeSet::new();
    match controller {
        IpAddr::V4(value) => {
            management_v4.insert(format!("{value}/32"));
        }
        IpAddr::V6(value) => {
            management_v6.insert(format!("{value}/128"));
        }
    }
    let (mut execution_v4, mut execution_v6) = (BTreeSet::new(), BTreeSet::new());
    for peer in &policy.execution_peers {
        let endpoint = peer
            .split_once('@')
            .ok_or("invalid original execution peer")?
            .1;
        let ip = endpoint
            .parse::<SocketAddr>()
            .map_err(|_| "invalid execution endpoint")?
            .ip();
        if ip.is_ipv4() {
            execution_v4.insert(ip.to_string());
        } else {
            execution_v6.insert(ip.to_string());
        }
    }
    let (mut sentry_v4, mut sentry_v6) = (BTreeSet::new(), BTreeSet::new());
    for peer in &policy.sentry_peers {
        let address = peer
            .split('/')
            .nth(2)
            .ok_or("invalid original sentry")?
            .parse::<IpAddr>()
            .map_err(|_| "invalid sentry address")?;
        if address.is_ipv4() {
            sentry_v4.insert(address.to_string());
        } else {
            sentry_v6.insert(address.to_string());
        }
    }
    let mut text = String::from(
        "table inet erpc_arc_validator\ndelete table inet erpc_arc_validator\n\ntable inet erpc_arc_validator {\n",
    );
    for (name, kind, values) in [
        ("management_v4", "ipv4_addr", management_v4),
        ("management_v6", "ipv6_addr", management_v6),
        (
            "monitoring_v4",
            "ipv4_addr",
            policy.monitoring_allow.iter().cloned().collect(),
        ),
        ("execution_v4", "ipv4_addr", execution_v4),
        ("execution_v6", "ipv6_addr", execution_v6),
        ("sentry_v4", "ipv4_addr", sentry_v4),
        ("sentry_v6", "ipv6_addr", sentry_v6),
    ] {
        let _ = writeln!(
            text,
            "  set {name} {{\n    type {kind}\n    flags interval\n    auto-merge"
        );
        if !values.is_empty() {
            let _ = writeln!(
                text,
                "    elements = {{ {} }}",
                values.into_iter().collect::<Vec<_>>().join(", ")
            );
        }
        text.push_str("  }\n");
    }
    text.push_str("  chain input {\n    type filter hook input priority 0\n    policy drop\n    ct state invalid drop\n    ct state established,related accept\n    iifname \"lo\" accept\n    ip protocol icmp accept\n    ip6 nexthdr ipv6-icmp accept\n");
    let _ = writeln!(
        text,
        "    tcp dport {} ip saddr @management_v4 accept\n    tcp dport {} ip6 saddr @management_v6 accept",
        policy.ssh_port, policy.ssh_port
    );
    text.push_str("    tcp dport { 9001, 29000 } ip saddr @monitoring_v4 accept\n    meta l4proto { tcp, udp } th dport 30303 ip saddr @execution_v4 accept\n    meta l4proto { tcp, udp } th dport 30303 ip6 saddr @execution_v6 accept\n    tcp dport 27000 ip saddr @sentry_v4 accept\n    tcp dport 27000 ip6 saddr @sentry_v6 accept\n    counter drop\n  }\n}\n");
    Ok(text)
}

fn network(value: &str) -> bool {
    let Some((address, prefix)) = value.split_once('/') else {
        return false;
    };
    let Ok(address) = address.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    (1..=32).contains(&prefix)
        && (prefix == 32 || u32::from(address) & (u32::MAX >> prefix) == 0)
        && format!("{address}/{prefix}") == value
}

/// Official permissioned-management action, signed and submitted outside ERPC.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "step", rename_all = "kebab-case", deny_unknown_fields)]
pub enum GovernanceStep {
    /// Register the original public Ed25519 key with initial zero voting power.
    Register,
    /// Bind the externally held controller to the externally observed registration ID.
    ConfigureController {
        /// Public registration identifier from the actual registration event.
        registration_id: u64,
        /// Governance-approved maximum voting power for that controller.
        voting_power_limit: u64,
    },
    /// Mark this controller's validator active; zero power still cannot vote.
    Activate,
    /// Set this controller's voting power within its separately assigned limit.
    VotingPower {
        /// Governance-approved positive voting power.
        voting_power: u64,
    },
    /// Request removal of this controller's validator, signed externally.
    Remove,
}

/// Unsigned public transaction intent; no account key, gas signing or broadcast.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceIntent {
    /// Original chain ID; the external wallet must check it independently.
    pub chain_id: u64,
    /// Original network genesis, for the external RPC qualification.
    pub genesis_hash: String,
    /// Permissioned governance manager predeploy from the pinned native source.
    pub to: String,
    /// Exact externally held EVM account authorized to sign this action.
    pub from: String,
    /// Always zero native value; this interface never prepares funding transfers.
    pub value: String,
    /// Exact ABI calldata derived from the official contract signature.
    pub data: String,
    /// Human-readable required contract role, not a claim of live authorization.
    pub required_role: String,
    /// Public original signer identity, never the native seed.
    pub consensus_public_key: String,
    /// Whether the plan itself proves live permission or successful registration.
    pub admission_verified: bool,
}

fn selector(signature: &str) -> Vec<u8> {
    Keccak256::digest(signature.as_bytes())[..4].to_vec()
}

fn word(number: u64) -> [u8; 32] {
    let mut result = [0; 32];
    result[24..].copy_from_slice(&number.to_be_bytes());
    result
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::from("0x"), |mut result, byte| {
        let _ = write!(result, "{byte:02x}");
        result
    })
}

fn address_word(value: &str) -> Result<[u8; 32], &'static str> {
    if !address(value) {
        return Err("a canonical external governance address is required");
    }
    let mut bytes = [0; 32];
    for (index, destination) in bytes[12..].iter_mut().enumerate() {
        *destination = u8::from_str_radix(&value[2 + index * 2..4 + index * 2], 16)
            .map_err(|_| "invalid external governance address")?;
    }
    Ok(bytes)
}

/// Prepare the official unsigned management call without handling financial keys.
///
/// # Errors
/// Refuses another original identity, malformed governance address, zero ID/power,
/// or a controller action whose proposed sender differs from the reserved controller.
pub fn prepare_governance(
    contract: &Contract,
    step: &GovernanceStep,
    sender: &str,
) -> Result<GovernanceIntent, &'static str> {
    use base64::Engine as _;
    contract.validate()?;
    let _ = address_word(sender)?;
    let (data, role) = match step {
        GovernanceStep::Register => {
            let mut data = selector("registerValidator(bytes)");
            data.extend_from_slice(&word(32));
            data.extend_from_slice(&word(32));
            data.extend_from_slice(
                &base64::engine::general_purpose::STANDARD
                    .decode(&contract.public_key)
                    .map_err(|_| "invalid original consensus public key")?,
            );
            (data, "validator-registerer")
        }
        GovernanceStep::ConfigureController {
            registration_id,
            voting_power_limit,
        } => {
            if *registration_id == 0 || *voting_power_limit == 0 {
                return Err(
                    "external registration ID and positive voting-power limit are required",
                );
            }
            let mut data = selector("configureController(address,uint256,uint64)");
            data.extend_from_slice(&address_word(&contract.controller)?);
            data.extend_from_slice(&word(*registration_id));
            data.extend_from_slice(&word(*voting_power_limit));
            (data, "permissioned-validator-manager-owner")
        }
        GovernanceStep::Activate | GovernanceStep::Remove => {
            if sender != contract.controller {
                return Err("the externally signing account must be the original controller");
            }
            (
                selector(if matches!(step, GovernanceStep::Activate) {
                    "activateValidator()"
                } else {
                    "removeValidator()"
                }),
                "configured-controller",
            )
        }
        GovernanceStep::VotingPower { voting_power } => {
            if sender != contract.controller || *voting_power == 0 {
                return Err("the original controller and positive voting power are required");
            }
            let mut data = selector("updateValidatorVotingPower(uint64)");
            data.extend_from_slice(&word(*voting_power));
            (data, "configured-controller-with-sufficient-power-limit")
        }
    };
    Ok(GovernanceIntent {
        chain_id: contract.chain_id,
        genesis_hash: contract.genesis_hash.clone(),
        to: MANAGER.into(),
        from: sender.into(),
        value: "0x0".into(),
        data: hex(&data),
        required_role: role.into(),
        consensus_public_key: contract.public_key.clone(),
        admission_verified: false,
    })
}

/// Validate an external unsigned plan against this exact original public intent.
///
/// # Errors
/// Refuses any substituted network, destination, sender, value, key or calldata.
pub fn validate_governance(
    contract: &Contract,
    step: &GovernanceStep,
    sender: &str,
    proposed: &GovernanceIntent,
) -> Result<(), &'static str> {
    if *proposed != prepare_governance(contract, step, sender)? {
        return Err("external Arc governance intent differs from the original prepared action");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn contract() -> Contract {
        let network = crate::network::get("testnet").unwrap();
        Contract {
            owner: "a".repeat(26),
            network: "testnet".into(),
            chain_id: network.chain_id,
            genesis_hash: network.genesis_hash,
            // RFC 8032 test-vector public key, no private seed in this fixture.
            public_key: "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=".into(),
            peer_public_key: "PUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw=".into(),
            controller: format!("0x{}", "1".repeat(40)),
            host_binding: "a".repeat(64),
        }
    }
    #[test]
    fn role_contract_rejects_network_substitution_and_invalid_signer_before_custody() {
        let original = contract();
        original.validate().unwrap();
        let mut changed = original.clone();
        changed.network = "mainnet".into();
        assert!(changed.validate().is_err());
        changed = original.clone();
        changed.public_key =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0_u8; 32]);
        assert!(changed.validate().is_err());
        changed = original;
        changed.controller = format!("0x{}", "0".repeat(40));
        assert!(changed.validate().is_err());
    }
    #[test]
    fn operator_permission_is_required_but_not_claimed_to_be_live_admission() {
        let mut policy = Policy {
            approved: false,
            fee_recipient: format!("0x{}", "2".repeat(40)),
            execution_peers: vec![],
            sentry_peers: vec![],
            phase: Phase::Observer,
            ssh_port: 22,
            management_allow: vec![],
            monitoring_allow: vec![],
        };
        policy.validate().unwrap();
        policy.phase = Phase::Validator;
        assert!(policy.validate().is_err());
        policy.execution_peers = vec![format!("enode://{}@192.0.2.2:30303", "3".repeat(128))];
        policy.sentry_peers =
            vec!["/ip4/192.0.2.3/tcp/27000/p2p/12D3KooWInertPeer".replace('I', "J")];
        assert!(policy.validate().is_err());
        policy.approved = true;
        policy.validate().unwrap();
        policy.sentry_peers.push(policy.sentry_peers[0].clone());
        assert!(policy.validate().is_err());
    }
    #[test]
    fn ingress_uses_observed_ssh_port_and_explicit_peers_without_public_rpc() {
        let mut policy = Policy {
            approved: false,
            fee_recipient: format!("0x{}", "2".repeat(40)),
            execution_peers: vec![format!("enode://{}@192.0.2.2:30303", "3".repeat(128))],
            sentry_peers: vec!["/ip6/2001:db8::2/tcp/27000/p2p/12D3KooWabcdefgh".into()],
            phase: Phase::Observer,
            ssh_port: 2222,
            management_allow: vec!["192.0.2.0/24".into()],
            monitoring_allow: vec![],
        };
        let candidate = firewall(&policy, "2001:db8::1".parse().unwrap()).unwrap();
        assert!(candidate.contains("table inet erpc_arc_validator"));
        assert!(candidate.contains("2001:db8::1/128"));
        assert!(candidate.contains("tcp dport 2222 ip6 saddr @management_v6"));
        assert!(candidate.contains("192.0.2.2"));
        assert!(candidate.contains("2001:db8::2"));
        for private in ["8545", "8546", "31000"] {
            assert!(!candidate.contains(private));
        }
        policy.sentry_peers[0].push_str("; arbitrary");
        assert!(firewall(&policy, "192.0.2.1".parse().unwrap()).is_err());
    }

    #[test]
    fn numeric_peers_refuse_names_ambiguous_ports_and_loopback_services() {
        assert!(network("192.0.2.1/32"));
        assert!(network("192.0.2.0/24"));
        for value in ["0.0.0.0/0", "192.0.2.1/24", "192.0.2.1/33", "192.0.2.1/032"] {
            assert!(!network(value));
        }
        for value in [
            "/dns4/example.com/tcp/27000/p2p/12D3KooWabcdefgh",
            "/ip4/127.0.0.1/tcp/27000/p2p/12D3KooWabcdefgh",
            "/ip4/192.0.2.1/tcp/027000/p2p/12D3KooWabcdefgh",
        ] {
            assert!(!sentry_peer(value));
        }
        assert!(!execution_peer(&format!(
            "enode://{}@127.0.0.1:8545",
            "a".repeat(128)
        )));
    }

    #[test]
    fn external_governance_plan_is_public_exact_and_never_proves_admission() {
        let original = contract();
        let register =
            prepare_governance(&original, &GovernanceStep::Register, &original.controller).unwrap();
        assert_eq!(register.data.len(), 2 + (4 + 32 * 3) * 2);
        assert_eq!(
            &register.data[10..74],
            hex(&word(32)).strip_prefix("0x").unwrap()
        );
        assert!(!register.admission_verified);
        assert_eq!(register.value, "0x0");
        assert_eq!(register.to, MANAGER);
        validate_governance(
            &original,
            &GovernanceStep::Register,
            &original.controller,
            &register,
        )
        .unwrap();
        let mut changed = register;
        changed.value = "0x1".into();
        assert!(
            validate_governance(
                &original,
                &GovernanceStep::Register,
                &original.controller,
                &changed
            )
            .is_err()
        );
        assert!(
            prepare_governance(
                &original,
                &GovernanceStep::Activate,
                &format!("0x{}", "2".repeat(40))
            )
            .is_err()
        );
        assert!(
            prepare_governance(
                &original,
                &GovernanceStep::ConfigureController {
                    registration_id: 0,
                    voting_power_limit: 1,
                },
                &original.controller
            )
            .is_err()
        );
        assert!(
            prepare_governance(
                &original,
                &GovernanceStep::VotingPower { voting_power: 0 },
                &original.controller
            )
            .is_err()
        );
        for step in [
            GovernanceStep::Activate,
            GovernanceStep::Remove,
            GovernanceStep::ConfigureController {
                registration_id: 3,
                voting_power_limit: 4,
            },
            GovernanceStep::VotingPower { voting_power: 4 },
        ] {
            let value = prepare_governance(&original, &step, &original.controller).unwrap();
            validate_governance(&original, &step, &original.controller, &value).unwrap();
        }
    }

    #[test]
    fn native_admission_selectors_match_the_exact_official_solidity_abi() {
        let module =
            std::str::from_utf8(crate::file("validator/av_admission.py").unwrap()).unwrap();
        for (signature, expected) in [
            ("getValidator(address)", "1904bb2e"),
            ("getRegistrationId(address)", "d773a741"),
            ("getValidator(uint256)", "b5d89627"),
        ] {
            assert_eq!(hex(&selector(signature)), format!("0x{expected}"));
            assert!(module.contains(expected));
        }
    }

    #[test]
    fn carried_preparation_plays_use_the_complete_separate_profile() {
        let resources = carried_files().unwrap();
        let profile = helper_profile().unwrap();
        assert!(profile.len() > 16 && profile.len() <= 32);
        assert_eq!(resources.len(), profile.len() + 6);
        for name in profile {
            assert!(resources.contains_key(&format!("validator/{name}")));
        }
        for play in [
            plays::PREFLIGHT,
            plays::INIT,
            plays::FIREWALL,
            plays::DEPLOY,
            plays::DESTROY,
        ] {
            let text = std::str::from_utf8(&resources[play]).unwrap();
            assert!(text.contains("arc_validator_loader"));
            assert!(text.contains("../../validator/control.py"));
            assert!(!text.contains("authority/control.py"));
            assert!(!text.contains("'key':"));
        }
        assert!(carried_loader().unwrap().contains("trusted_imports"));
        assert_eq!(helper_hash().unwrap().len(), 64);
    }

    #[test]
    fn external_signer_inputs_do_not_accept_credentials_or_an_unqualified_destination() {
        let original = RemoteSigner {
            endpoint: "https://127.0.0.1:10340/".into(),
            server_ca_sha256: "a".repeat(64),
            image_sha256: "b".repeat(64),
            pcr0: "c".repeat(96),
            pcr1: "d".repeat(96),
            pcr2: "e".repeat(96),
            pcr4: "f".repeat(96),
        };
        original.validate().unwrap();
        for endpoint in [
            "http://127.0.0.1:10340/",
            "https://localhost:10340/",
            "https://127.0.0.1:0/",
            "https://127.0.0.1:10340/other",
        ] {
            let mut changed = original.clone();
            changed.endpoint = endpoint.into();
            assert!(changed.validate().is_err());
        }
        let mut endpoint = reqwest::Url::parse(&original.endpoint).unwrap();
        endpoint.set_username("example").unwrap();
        let mut changed = original.clone();
        changed.endpoint = endpoint.into();
        assert!(changed.validate().is_err());
        changed = original;
        changed.pcr4.clear();
        assert!(changed.validate().is_err());
    }
}
