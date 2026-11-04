// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Solana RPC nodes: which client and which kind of RPC, the releases they
//! are pinned to, and what the carried plays are told about them.
//!
//! - **Clients.** agave and jito, built from source at a pinned tag and
//!   commit, as a validator's are. Firedancer is not offered: Frankendancer,
//!   which ran agave's RPC, ends with Alpenglow, and the full Firedancer's
//!   own RPC has no sendTransaction, history, indexes or plugins.
//! - **Types.** SLV's four: `SendTx`, Index, Geyser gRPC and Index + gRPC.
//!   The gRPC types build the Yellowstone plugin at the tag built for the
//!   client's exact agave version; the Index types run Old Faithful
//!   (`faithful-cli`) for history, pinned by the SHA-256 GitHub gives its
//!   Linux binary.
//! - **Pins** are chosen at `init` and kept in the node's item; the run's
//!   `vars/versions.yml` is made from them, and the plays stop rather than
//!   build or install anything else.

use core::cmp::Ordering;

use erpc_chain::inventory::SolanaRpc;
use serde_json::{Map, Value, json};

use crate::github::Published;
use crate::versions::{self, VersionError};

/// The networks erpc sets Solana RPC nodes up on so far.
pub const NETWORKS: [&str; 1] = ["mainnet"];
/// The Yellowstone gRPC Geyser plugin's repository.
pub const YELLOWSTONE_REPO: &str = "rpcpool/yellowstone-grpc";
/// Old Faithful's repository.
pub const FAITHFUL_REPO: &str = "rpcpool/yellowstone-faithful";
/// The repositories besides the clients' that erpc reads releases from.
pub const REPOSITORIES: [&str; 2] = [YELLOWSTONE_REPO, FAITHFUL_REPO];
/// The Old Faithful binary a node downloads.
pub const FAITHFUL_ASSET: &str = "faithful-cli_linux_amd64";

/// JSON-RPC over HTTP, as SLV binds it.
pub const RPC_PORT: u16 = 7211;
/// JSON-RPC over WebSocket: the RPC port plus one, agave's default.
pub const WS_PORT: u16 = 7212;
/// The Yellowstone plugin's gRPC.
pub const GRPC_PORT: u16 = 10000;
/// Old Faithful's JSON-RPC.
pub const FAITHFUL_PORT: u16 = 8888;
/// The ports clients reach, admitted from the RPC allow list.
pub const CLIENT_PORTS: [u16; 4] = [RPC_PORT, WS_PORT, GRPC_PORT, FAITHFUL_PORT];
/// Metrics: node exporter and the Yellowstone plugin's Prometheus,
/// admitted from the monitoring allow list.
pub const METRICS_PORTS: [u16; 2] = [9100, 8999];
/// The cluster's ports, admitted from anywhere: agave's dynamic range.
pub const CLUSTER_PORTS: (u16, u16) = (8000, 8030);

/// Why a client, type or release was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RpcError {
    /// The choice is not one erpc sets up.
    #[error("{0}")]
    Refused(String),
    /// A version is not acceptable.
    #[error(transparent)]
    Version(#[from] VersionError),
}

/// The client an RPC node runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Client {
    /// Anza's agave.
    Agave,
    /// Jito's fork of agave.
    Jito,
}

impl Client {
    /// Every client, in the order `--help` lists them.
    pub const ALL: [Self; 2] = [Self::Jito, Self::Agave];

    /// From `--client` or the item.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "agave" => Some(Self::Agave),
            "jito" => Some(Self::Jito),
            _ => None,
        }
    }

    /// As stored.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Agave => "agave",
            Self::Jito => "jito",
        }
    }

    /// SLV's `validator_type` for it.
    #[must_use]
    pub const fn validator_type(self) -> &'static str {
        self.as_str()
    }
}

/// The kind of RPC node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcType {
    /// Sending transactions: no indexes, a short ledger.
    SendTx,
    /// Account indexes, transaction history, and Old Faithful.
    Index,
    /// The Yellowstone gRPC plugin.
    Grpc,
    /// Both.
    IndexGrpc,
}

impl RpcType {
    /// Every type, in the order `--help` lists them.
    pub const ALL: [Self; 4] = [Self::SendTx, Self::Index, Self::Grpc, Self::IndexGrpc];

    /// From `--type` or the item.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "send-tx" => Some(Self::SendTx),
            "index" => Some(Self::Index),
            "grpc" => Some(Self::Grpc),
            "index-grpc" => Some(Self::IndexGrpc),
            _ => None,
        }
    }

    /// As stored and on the command line.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SendTx => "send-tx",
            Self::Index => "index",
            Self::Grpc => "grpc",
            Self::IndexGrpc => "index-grpc",
        }
    }

    /// SLV's `rpc_type`, which the carried templates branch on.
    #[must_use]
    pub const fn slv_name(self) -> &'static str {
        match self {
            Self::SendTx => "SendTx RPC",
            Self::Index => "Index RPC",
            Self::Grpc => "Geyser gRPC",
            Self::IndexGrpc => "Index RPC + gRPC",
        }
    }

    /// It builds the Yellowstone plugin.
    #[must_use]
    pub const fn geyser(self) -> bool {
        matches!(self, Self::Grpc | Self::IndexGrpc)
    }

    /// It runs Old Faithful.
    #[must_use]
    pub const fn faithful(self) -> bool {
        matches!(self, Self::Index | Self::IndexGrpc)
    }
}

/// Refuses a network, client or type erpc does not set up, and a client and
/// type that do not go together.
///
/// # Errors
///
/// Returns [`RpcError::Refused`] saying which.
pub fn check_choice(
    network: &str,
    client: &str,
    rpc_type: &str,
) -> Result<(Client, RpcType), RpcError> {
    if !NETWORKS.contains(&network) {
        return Err(RpcError::Refused(format!(
            "erpc sets up Solana RPC nodes on {} so far, not {network}",
            NETWORKS.join(", ")
        )));
    }
    let c = Client::parse(client)
        .ok_or_else(|| RpcError::Refused(format!("--client {client:?} is not jito or agave")))?;
    let t = RpcType::parse(rpc_type).ok_or_else(|| {
        RpcError::Refused(format!(
            "--type {rpc_type:?} is not send-tx, index, grpc or index-grpc"
        ))
    })?;
    Ok((c, t))
}

/// The agave a Yellowstone tag is built for: `v16.1.5+solana.4.3.2` is
/// `4.3.2`.
#[must_use]
pub fn geyser_agave(tag: &str) -> Option<&str> {
    tag.split_once("+solana.").map(|(_, v)| v)
}

/// The X.Y.Z of a client tag, without `v` or a suffix: `v4.3.2-jito` is
/// `4.3.2`.
fn base(tag: &str) -> Option<[u64; 3]> {
    let r = versions::read(tag)?;
    (r.rank == 3).then_some(r.numbers)
}

/// The Yellowstone release a gRPC node builds: the tag asked for, or the
/// newest that is not a pre-release; either way built for exactly the
/// agave the client runs (`client_tag`, such as `v4.3.2-jito`).
///
/// # Errors
///
/// Returns [`RpcError::Refused`] when none is built for that agave.
pub fn choose_geyser<'a>(
    releases: &'a [Published],
    client_tag: &str,
    wanted: Option<&str>,
) -> Result<&'a Published, RpcError> {
    let client = base(client_tag)
        .ok_or_else(|| RpcError::Refused(format!("{client_tag} is not a release version")))?;
    let built_for_client = |r: &Published| geyser_agave(&r.tag).and_then(base) == Some(client);
    let pick = if let Some(tag) = wanted {
        releases.iter().find(|r| r.tag == tag)
    } else {
        releases
            .iter()
            .filter(|r| !r.prerelease && !r.tag.contains("-rc") && built_for_client(r))
            .max_by(|a, b| versions::compare(&a.tag, &b.tag).unwrap_or(Ordering::Equal))
    };
    match pick {
        Some(r) if built_for_client(r) => Ok(r),
        Some(r) => Err(RpcError::Refused(format!(
            "Yellowstone {} is built for solana {}, and the client runs {client_tag}",
            r.tag,
            geyser_agave(&r.tag).unwrap_or("?")
        ))),
        None => Err(RpcError::Refused(format!(
            "no Yellowstone gRPC release on GitHub is built for {client_tag}{}; pass --geyser-version \
             or pin another --version",
            wanted.map_or_else(String::new, |w| format!(" ({w} is not on GitHub)"))
        ))),
    }
}

/// The Old Faithful release an Index node downloads, and its binary's
/// SHA-256: the tag asked for, or the newest that is not a pre-release.
///
/// # Errors
///
/// Returns [`RpcError::Refused`] when none fits or it has no digest for
/// [`FAITHFUL_ASSET`].
pub fn choose_faithful(
    releases: &[Published],
    wanted: Option<&str>,
) -> Result<(String, String), RpcError> {
    let digest = |r: &Published| {
        r.assets
            .iter()
            .find(|(name, _)| name == FAITHFUL_ASSET)
            .map(|(_, sha)| sha.clone())
            .filter(|sha| sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit()))
    };
    let pick = if let Some(tag) = wanted {
        releases.iter().find(|r| r.tag == tag)
    } else {
        releases
            .iter()
            .filter(|r| !r.prerelease && digest(r).is_some())
            .max_by(|a, b| versions::compare(&a.tag, &b.tag).unwrap_or(Ordering::Equal))
    };
    let r = pick.ok_or_else(|| {
        RpcError::Refused(
            "no Old Faithful release on GitHub has a Linux binary with a digest".to_owned(),
        )
    })?;
    let sha = digest(r).ok_or_else(|| {
        RpcError::Refused(format!(
            "Old Faithful {} has no digest for {FAITHFUL_ASSET}",
            r.tag
        ))
    })?;
    Ok((r.tag.clone(), sha))
}

/// The bundle's `vars/versions.yml` for an RPC node: the `mainnet_rpcs`
/// section the carried plays read, from the node's pins. JSON, which YAML
/// reads as it is.
///
/// # Errors
///
/// Returns [`RpcError`] when a pin is missing, below the floor, or not a full
/// commit SHA.
pub fn versions_yml(network: &str, node: &SolanaRpc) -> Result<String, RpcError> {
    let (client, rpc_type) = check_choice(network, &node.client, &node.rpc_type)?;
    let mut section = Map::new();
    let strip = |t: &str| t.strip_prefix('v').unwrap_or(t).to_owned();
    versions::check_floor(network, &node.version)?;
    versions::check_commit(&node.commit)?;
    section.insert(
        format!("version_{}", client.as_str()),
        json!(strip(&node.version)),
    );
    section.insert(format!("commit_{}", client.as_str()), json!(node.commit));
    if rpc_type.geyser() {
        if geyser_agave(&node.geyser_version).and_then(base) != base(&node.version) {
            return Err(RpcError::Refused(format!(
                "Yellowstone {:?} is not built for {}",
                node.geyser_version, node.version
            )));
        }
        versions::check_commit(&node.geyser_commit)?;
        section.insert("geyser_version".to_owned(), json!(node.geyser_version));
        section.insert("geyser_commit".to_owned(), json!(node.geyser_commit));
    }
    let doc = json!({ format!("{network}_rpcs"): section });
    Ok(format!("{doc:#}\n"))
}

/// The host variables the carried RPC plays read, for `node`, with the
/// operator's key for the `solv` user. The firewall's lists are the
/// caller's to add: they need the address erpc connects from.
///
/// # Errors
///
/// Returns [`RpcError`] when the node's client or type is not one erpc sets
/// up, or an Index node has no Old Faithful pin.
pub fn host_vars(
    network: &str,
    node: &SolanaRpc,
    solv_authorized_key: &str,
) -> Result<Map<String, Value>, RpcError> {
    let (client, rpc_type) = check_choice(network, &node.client, &node.rpc_type)?;
    if rpc_type.faithful() && (node.of1_version.is_empty() || node.of1_sha256.len() != 64) {
        return Err(RpcError::Refused(format!(
            "{} is an Index node with no Old Faithful pin; run init again",
            node.name
        )));
    }
    let vars = json!({
        "name": node.name,
        "identity_account": node.identity_account,
        "validator_type": client.validator_type(),
        "rpc_type": rpc_type.slv_name(),
        "erpc_rpc_type": rpc_type.as_str(),
        "region": node.region,
        "port_rpc": RPC_PORT,
        "rpc_port": RPC_PORT,
        "dynamic_port_range": "8000-8030",
        "geyser_plugin": "yellowstone",
        "snapshot_url": "",
        "of1_version": node.of1_version,
        "of1_sha256": node.of1_sha256,
        "erpc_geyser": rpc_type.geyser(),
        "erpc_faithful": rpc_type.faithful(),
        "solv_authorized_key": solv_authorized_key,
    });
    Ok(match vars {
        Value::Object(map) => map,
        _ => Map::new(),
    })
}

#[cfg(test)]
mod tests {
    use erpc_chain::inventory::SolanaRpc;
    use serde_json::Value;

    use super::{
        Client, RpcType, check_choice, choose_faithful, choose_geyser, geyser_agave, host_vars,
        versions_yml,
    };
    use crate::github::Published;

    fn release(tag: &str, pre: bool, line: &str) -> Published {
        Published {
            tag: tag.to_owned(),
            prerelease: pre,
            first_line: line.to_owned(),
            assets: Vec::new(),
        }
    }

    #[test]
    fn clients_and_types_go_together_as_in_slv() {
        assert_eq!(
            check_choice("mainnet", "jito", "index-grpc"),
            Ok((Client::Jito, RpcType::IndexGrpc))
        );
        assert!(check_choice("mainnet", "firedancer", "send-tx").is_err());
        assert!(check_choice("testnet", "jito", "index").is_err());
        assert!(check_choice("mainnet", "allnodes-jito", "index").is_err());
        assert!(check_choice("mainnet", "jito", "Index RPC").is_err());
        assert_eq!(RpcType::IndexGrpc.slv_name(), "Index RPC + gRPC");
        assert_eq!(Client::Agave.validator_type(), "agave");
    }

    #[test]
    fn the_geyser_plugin_is_the_one_built_for_the_clients_agave() {
        assert_eq!(geyser_agave("v16.1.5+solana.4.3.2"), Some("4.3.2"));
        let listed = [
            release("v16.1.5+solana.4.3.2", false, "rust 1.97.1"),
            release("v16.1.4+solana.4.3.2", false, "rust 1.97.1"),
            release("v16.1.3+solana.4.3.0", false, "rust 1.97.1"),
            release("v16.0.0-rc10+solana.4.3.0", false, "rust 1.97.1"),
            release("v17.0.0-rc5+solana.4.4.0.beta.0", true, ""),
        ];
        assert_eq!(
            choose_geyser(&listed, "v4.3.2-jito", None)
                .expect("jito")
                .tag,
            "v16.1.5+solana.4.3.2"
        );
        assert_eq!(
            choose_geyser(&listed, "v4.3.0", None).expect("agave").tag,
            "v16.1.3+solana.4.3.0"
        );
        assert!(choose_geyser(&listed, "v4.3.1", None).is_err());
        assert!(choose_geyser(&listed, "v4.3.2", Some("v16.1.3+solana.4.3.0")).is_err());
        assert!(choose_geyser(&listed, "v4.3.2", Some("v16.1.4+solana.4.3.2")).is_ok());
    }

    #[test]
    fn old_faithful_comes_with_its_binarys_digest() {
        let sha = "3c7f0ddbeebfb4a1edc5e6cbc00944b457583961de0114b5091afa33e8808b33";
        let with = |tag: &str, pre: bool| Published {
            assets: vec![(super::FAITHFUL_ASSET.to_owned(), sha.to_owned())],
            ..release(tag, pre, "")
        };
        let listed = [
            with("v0.7.31", false),
            with("v0.7.31-rc1", true),
            with("v0.7.30", false),
        ];
        assert_eq!(
            choose_faithful(&listed, None).expect("one"),
            ("v0.7.31".to_owned(), sha.to_owned())
        );
        assert!(choose_faithful(&[release("v0.7.31", false, "")], None).is_err());
    }

    fn node(client: &str, rpc_type: &str) -> SolanaRpc {
        SolanaRpc {
            name: "rpc1".to_owned(),
            client: client.to_owned(),
            rpc_type: rpc_type.to_owned(),
            version: "v4.3.2-jito".to_owned(),
            commit: "a".repeat(40),
            geyser_version: "v16.1.5+solana.4.3.2".to_owned(),
            geyser_commit: "b".repeat(40),
            of1_version: "v0.7.31".to_owned(),
            of1_sha256: "c".repeat(64),
            region: "frankfurt".to_owned(),
            ..SolanaRpc::default()
        }
    }

    #[test]
    fn the_versions_file_has_the_mainnet_rpcs_pins_the_plays_read() {
        let text = versions_yml("mainnet", &node("jito", "index-grpc")).expect("yml");
        let doc: Value = serde_json::from_str(&text).expect("JSON");
        let s = &doc["mainnet_rpcs"];
        assert_eq!(s["version_jito"], "4.3.2-jito");
        assert_eq!(s["commit_jito"], "a".repeat(40));
        assert_eq!(s["geyser_version"], "v16.1.5+solana.4.3.2");
        // A plugin built for another agave is refused.
        let off = SolanaRpc {
            version: "v4.3.0-jito".to_owned(),
            ..node("jito", "grpc")
        };
        assert!(versions_yml("mainnet", &off).is_err());
        let send = versions_yml("mainnet", &node("jito", "send-tx")).expect("send-tx");
        let doc: Value = serde_json::from_str(&send).expect("JSON");
        assert!(doc["mainnet_rpcs"].get("geyser_version").is_none());
    }

    #[test]
    fn the_host_variables_are_slvs_with_the_pins_and_no_address() {
        let n = SolanaRpc {
            address: "192.0.2.10".to_owned(),
            ..node("jito", "index")
        };
        let vars = host_vars("mainnet", &n, "ssh-ed25519 AAAA op").expect("vars");
        assert_eq!(vars["validator_type"], "jito");
        assert_eq!(vars["rpc_type"], "Index RPC");
        assert_eq!(vars["port_rpc"], 7211);
        assert_eq!(vars["dynamic_port_range"], "8000-8030");
        assert_eq!(vars["erpc_faithful"], true);
        assert_eq!(vars["erpc_geyser"], false);
        assert!(!Value::Object(vars).to_string().contains("192.0.2.10"));
        let unpinned = SolanaRpc {
            of1_sha256: String::new(),
            ..node("agave", "index")
        };
        assert!(host_vars("mainnet", &unpinned, "k").is_err());
    }
}
