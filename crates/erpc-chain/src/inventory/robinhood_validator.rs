// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Public-only projected validator inventory. Wallet bytes live in a separate
//! concealed item; no whole-item get or Host item traversal occurs here.
use super::{InventoryError, Kind, OpRunner, Store, TAG, check_name};
use erpc_chain_nitro::robinhood_validator::{Contract, Network, Phase, host_binding, identifier};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

const FORMAT: &str = "robinhood-defensive-validator-v1";
const RECORD: &str = "robinhood_validator_record";
const SELECTOR: &str = "label=erpc_format,label=robinhood_validator_record";

/// Public reservation of one dedicated assertion-validator host and original wallet.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Validator {
    /// Item identity assigned by the public inventory service.
    #[serde(skip)]
    pub id: Option<String>,
    /// Observed optimistic version, never represented as compare-and-swap.
    #[serde(skip)]
    pub item_version: u64,
    /// Exact name in this scope.
    pub name: String,
    /// Original Robinhood network, independent of the parent chain name.
    pub network: Network,
    /// Original SSH target.
    pub address: String,
    /// Original login identity.
    pub ssh_user: String,
    /// Original external SSH port.
    pub ssh_port: u16,
    /// Pinned original host key.
    pub host_key: String,
    /// Domain-separated canonical host authority digest.
    pub host_binding: String,
    /// Original data filesystem observed before custody reservation.
    pub data_uuid: String,
    /// Original public wallet; immutable even while creation is pending.
    pub wallet: String,
    /// Original creation token; ambiguous creation must not regenerate a wallet.
    pub creation: String,
    /// Identifier-only concealed item reference; empty only before successful readback.
    pub signer_ref: String,
    /// Identifier-only parent execution and beacon configuration reference.
    pub upstreams_ref: String,
    /// Requested runtime mode, never a claim of accepted activation.
    pub desired: Phase,
    /// Additional management ACLs.
    pub management_allow: Vec<String>,
    /// Last orchestration run identity.
    pub last_run: String,
    /// Last completed operation.
    pub last_result: String,
}
fn invalid() -> InventoryError {
    InventoryError::Unreadable("Robinhood public validator inventory")
}
impl Validator {
    /// Exact contract sent to the host; it requires a persisted original item ID.
    /// # Errors
    /// Missing ownership or malformed public fields are refused.
    pub fn contract(&self) -> Result<Contract, InventoryError> {
        let c = Contract {
            owner: self.id.clone().ok_or_else(invalid)?,
            family: "robinhood".into(),
            network: self.network.name().into(),
            platform: "amd64".into(),
            role: "defensive-validator".into(),
            wallet: self.wallet.clone(),
            creation: self.creation.clone(),
            host_binding: self.host_binding.clone(),
            data_uuid: self.data_uuid.clone(),
        };
        c.validate().map_err(|_| invalid())?;
        Ok(c)
    }
    fn validate(&self) -> Result<(), InventoryError> {
        check_name(&self.name)?;
        let mut qualified = self.clone();
        if qualified.id.is_none() {
            qualified.id = Some("a".repeat(26));
        }
        qualified.contract()?;
        if host_binding(&self.address, &self.ssh_user, self.ssh_port, &self.host_key)
            .map_err(|_| invalid())?
            != self.host_binding
        {
            return Err(invalid());
        }
        erpc_secret::OpRef::parse(&self.upstreams_ref).map_err(|_| invalid())?;
        if self.desired == Phase::Active && self.signer_ref.is_empty() {
            return Err(invalid());
        }
        if !self.signer_ref.is_empty() {
            erpc_secret::OpRef::parse(&self.signer_ref).map_err(|_| invalid())?;
        }
        if self.management_allow.len() > 64
            || self
                .management_allow
                .iter()
                .any(|v| v.len() > 64 || v.chars().any(char::is_control))
            || self.last_run.len() > 80
            || self.last_result.len() > 80
        {
            return Err(invalid());
        }
        Ok(())
    }
    fn same_original(&self, other: &Self) -> bool {
        (
            self.id.as_ref(),
            &self.name,
            self.network,
            &self.address,
            &self.ssh_user,
            self.ssh_port,
            &self.host_key,
            &self.host_binding,
            &self.data_uuid,
            &self.wallet,
            &self.creation,
        ) == (
            other.id.as_ref(),
            &other.name,
            other.network,
            &other.address,
            &other.ssh_user,
            other.ssh_port,
            &other.host_key,
            &other.host_binding,
            &other.data_uuid,
            &other.wallet,
            &other.creation,
        ) && (self.signer_ref.is_empty() || self.signer_ref == other.signer_ref)
            && (self.desired != Phase::Active || other.desired == Phase::Active)
    }
}
#[derive(Deserialize, PartialEq, Eq)]
struct Vault {
    id: String,
}
#[derive(Deserialize, PartialEq, Eq)]
struct Listed {
    id: String,
    title: String,
    version: u64,
    vault: Vault,
    category: String,
    tags: Vec<String>,
}
#[derive(Deserialize)]
struct Field {
    id: String,
    label: String,
    #[serde(rename = "type")]
    kind: String,
    value: SecretString,
}

impl<R: OpRunner> Store<R> {
    fn robinhood_output(
        &self,
        args: &[&str],
        input: Option<&str>,
    ) -> Result<SecretString, InventoryError> {
        let out = self.runner.run(args, input).map_err(|_| invalid())?;
        let _stderr = SecretString::from(out.stderr);
        let raw = SecretString::from(out.stdout);
        if !out.success || raw.expose_secret().len() > 1_048_576 {
            return Err(invalid());
        }
        Ok(raw)
    }
    fn robinhood_listing(&self) -> Result<Vec<Listed>, InventoryError> {
        if self.scope.chain != "robinhood" || Network::parse(&self.scope.network).is_none() {
            return Err(invalid());
        }
        let tag = self.scope.tag(Kind::Validator);
        let raw = self.robinhood_output(
            &[
                "item",
                "list",
                "--vault",
                &self.vault,
                "--tags",
                &tag,
                "--format",
                "json",
            ],
            None,
        )?;
        let listed: Vec<Listed> =
            serde_json::from_str(raw.expose_secret()).map_err(|_| invalid())?;
        let mut ids = BTreeSet::new();
        let mut titles = BTreeSet::new();
        let mut exact = Vec::new();
        for item in listed {
            if !identifier(&item.id) || !identifier(&item.vault.id) || !ids.insert(item.id.clone())
            {
                return Err(invalid());
            }
            if !item.tags.contains(&tag) {
                continue;
            }
            if item.category != "SECURE_NOTE"
                || item.version == 0
                || !item.tags.iter().any(|v| v == TAG)
                || item
                    .tags
                    .iter()
                    .any(|v| v.starts_with("erpc/") && v != &tag)
                || item.tags.iter().collect::<BTreeSet<_>>().len() != item.tags.len()
                || !titles.insert(item.title.clone())
            {
                return Err(invalid());
            }
            exact.push(item);
        }
        exact.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(exact)
    }
    fn robinhood_projection(&self, item: &Listed) -> Result<Validator, InventoryError> {
        let raw = self.robinhood_output(
            &[
                "item",
                "get",
                &item.id,
                "--vault",
                &item.vault.id,
                "--fields",
                SELECTOR,
                "--format",
                "json",
            ],
            None,
        )?;
        if raw.expose_secret().len() > 32_768 {
            return Err(invalid());
        }
        let fields: Vec<Field> =
            serde_json::from_str(raw.expose_secret()).map_err(|_| invalid())?;
        if fields.len() != 2 {
            return Err(invalid());
        }
        let mut values = BTreeMap::new();
        let mut ids = BTreeSet::new();
        for field in fields {
            if field.kind != "STRING"
                || field.id.is_empty()
                || !ids.insert(field.id)
                || !["erpc_format", RECORD].contains(&field.label.as_str())
                || values.insert(field.label, field.value).is_some()
            {
                return Err(invalid());
            }
        }
        if values
            .get("erpc_format")
            .ok_or_else(invalid)?
            .expose_secret()
            != FORMAT
        {
            return Err(invalid());
        }
        let mut node: Validator =
            serde_json::from_str(values.get(RECORD).ok_or_else(invalid)?.expose_secret())
                .map_err(|_| invalid())?;
        node.id = Some(item.id.clone());
        node.item_version = item.version;
        node.validate()?;
        if node.network.name() != self.scope.network
            || item.title != self.title(Kind::Validator, &node.name)
        {
            return Err(invalid());
        }
        Ok(node)
    }
    /// List only exact-scope public records, detecting edits/retags across projection.
    /// # Errors
    /// Ambiguous metadata, wrong field types, changed versions or invalid ownership fail closed.
    pub fn robinhood_validators(&self) -> Result<Vec<Validator>, InventoryError> {
        let before = self.robinhood_listing()?;
        let nodes = before
            .iter()
            .map(|v| self.robinhood_projection(v))
            .collect::<Result<Vec<_>, _>>()?;
        if before != self.robinhood_listing()? {
            return Err(invalid());
        }
        Ok(nodes)
    }
    fn robinhood_template(&self, node: &Validator) -> Result<String, InventoryError> {
        node.validate()?;
        if self.scope.chain != "robinhood" || node.network.name() != self.scope.network {
            return Err(invalid());
        }
        Ok(json!({"title":self.title(Kind::Validator,&node.name),"category":"SECURE_NOTE","tags":[TAG,self.scope.tag(Kind::Validator)],"fields":[{"id":"erpc_format","label":"erpc_format","type":"STRING","value":FORMAT},{"id":RECORD,"label":RECORD,"type":"STRING","value":serde_json::to_string(node).map_err(|_|invalid())?}]}).to_string())
    }
    /// Reserve public original metadata before creating any concealed wallet item.
    /// # Errors
    /// Duplicate ownership, ambiguous creation or readback mismatch is refused.
    pub fn add_robinhood_validator(&self, node: &Validator) -> Result<Validator, InventoryError> {
        if node.id.is_some() || !node.signer_ref.is_empty() || node.desired != Phase::Observing {
            return Err(invalid());
        }
        let _lock = self.lock()?;
        if self.robinhood_validators()?.iter().any(|v| {
            v.name == node.name
                || v.address == node.address
                || v.wallet == node.wallet
                || v.creation == node.creation
        }) {
            return Err(invalid());
        }
        let template = self.robinhood_template(node)?;
        let _concealed_output = self.robinhood_output(
            &[
                "item",
                "create",
                "-",
                "--vault",
                &self.vault,
                "--format",
                "json",
            ],
            Some(&template),
        )?;
        let back = self
            .robinhood_validators()?
            .into_iter()
            .find(|v| v.name == node.name)
            .ok_or_else(invalid)?;
        let mut wanted = node.clone();
        wanted.id.clone_from(&back.id);
        wanted.item_version = back.item_version;
        if back != wanted {
            return Err(invalid());
        }
        Ok(back)
    }
    /// Persist public progression while preserving every original ownership field.
    /// # Errors
    /// Stale versions, wallet/host replacement, signer-reference replacement and demotion fail closed.
    pub fn update_robinhood_validator(
        &self,
        node: &Validator,
    ) -> Result<Validator, InventoryError> {
        let _lock = self.lock()?;
        node.validate()?;
        let id = node.id.as_deref().ok_or_else(invalid)?;
        let old = self
            .robinhood_validators()?
            .into_iter()
            .find(|v| v.id.as_deref() == Some(id))
            .ok_or_else(invalid)?;
        if old.item_version != node.item_version || !old.same_original(node) {
            return Err(invalid());
        }
        let template = self.robinhood_template(node)?;
        let _concealed_output = self.robinhood_output(
            &[
                "item",
                "edit",
                id,
                "--vault",
                &self.vault,
                "--format",
                "json",
            ],
            Some(&template),
        )?;
        let back = self
            .robinhood_validators()?
            .into_iter()
            .find(|v| v.id.as_deref() == Some(id))
            .ok_or_else(invalid)?;
        let mut wanted = node.clone();
        wanted.item_version = back.item_version;
        if back != wanted || back.item_version <= old.item_version {
            return Err(invalid());
        }
        Ok(back)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use erpc_auth::store::{StoreError, one_password::OpOutput};
    use serde_json::Value;
    use std::cell::{Cell, RefCell};
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Mock {
        item: RefCell<Option<Value>>,
        calls: RefCell<Vec<Vec<String>>>,
        change_on_get: Cell<bool>,
        duplicate_field: Cell<bool>,
        concealed: Cell<bool>,
        lost_create: Cell<bool>,
    }
    impl Mock {
        fn new() -> Self {
            Self {
                item: RefCell::new(None),
                calls: RefCell::new(Vec::new()),
                change_on_get: Cell::new(false),
                duplicate_field: Cell::new(false),
                concealed: Cell::new(false),
                lost_create: Cell::new(false),
            }
        }
    }
    impl OpRunner for &Mock {
        fn run(&self, args: &[&str], stdin: Option<&str>) -> Result<OpOutput, StoreError> {
            self.calls
                .borrow_mut()
                .push(args.iter().map(|v| (*v).into()).collect());
            let mut item = self.item.borrow_mut();
            let stdout = match args {
                [
                    "item",
                    "list",
                    "--vault",
                    _,
                    "--tags",
                    _,
                    "--format",
                    "json",
                ] => {
                    let mut result = Vec::new();
                    if let Some(v) = item.as_ref() {
                        result.push(json!({"id":v["id"],"title":v["title"],"version":v["version"],"vault":{"id":"v".repeat(26)},"category":"SECURE_NOTE","tags":v["tags"]}));
                    }
                    result.push(json!({"id":"h".repeat(26),"title":"decoy host","version":1,"vault":{"id":"v".repeat(26)},"category":"SECURE_NOTE","tags":["erpc","erpc/robinhood/mainnet/host"]}));
                    json!(result).to_string()
                }
                [
                    "item",
                    "get",
                    id,
                    "--vault",
                    _,
                    "--fields",
                    selector,
                    "--format",
                    "json",
                ] => {
                    assert_eq!(*selector, SELECTOR);
                    assert_eq!(*id, "i".repeat(26));
                    assert!(stdin.is_none());
                    let v = item.as_mut().unwrap();
                    let mut fields = v["fields"].as_array().unwrap().clone();
                    if self.duplicate_field.get() {
                        fields[1] = fields[0].clone();
                    }
                    if self.concealed.get() {
                        fields[1]["type"] = json!("CONCEALED");
                        fields[1]["value"] = json!("inert-secret-sentinel");
                    }
                    if self.change_on_get.get() {
                        v["version"] = json!(v["version"].as_u64().unwrap() + 1);
                    }
                    json!(fields).to_string()
                }
                ["item", "create", "-", "--vault", _, "--format", "json"] => {
                    assert!(item.is_none());
                    let mut value: Value = serde_json::from_str(stdin.unwrap()).unwrap();
                    value["id"] = json!("i".repeat(26));
                    value["version"] = json!(1);
                    *item = Some(value);
                    if self.lost_create.get() {
                        return Ok(OpOutput {
                            success: false,
                            stdout: "inert-secret-sentinel".into(),
                            stderr: "inert-secret-sentinel".into(),
                        });
                    }
                    "{}".into()
                }
                ["item", "edit", _, "--vault", _, "--format", "json"] => {
                    let version = item.as_ref().unwrap()["version"].as_u64().unwrap();
                    let mut value: Value = serde_json::from_str(stdin.unwrap()).unwrap();
                    value["id"] = json!("i".repeat(26));
                    value["version"] = json!(version + 1);
                    *item = Some(value);
                    "{}".into()
                }
                _ => panic!("unprojected inventory access: {args:?}"),
            };
            Ok(OpOutput {
                success: true,
                stdout,
                stderr: String::new(),
            })
        }
    }
    fn store(mock: &Mock) -> Store<&Mock> {
        Store::new(
            mock,
            "fixture-vault",
            super::super::Scope {
                chain: "robinhood".into(),
                network: "mainnet".into(),
            },
            std::env::temp_dir().join(format!(
                "robinhood-public-inventory-{}-{}.lock",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            )),
        )
    }
    fn pending() -> Validator {
        Validator {
            id: None,
            item_version: 0,
            name: "fixture".into(),
            network: Network::Mainnet,
            address: "192.0.2.1".into(),
            ssh_user: "ubuntu".into(),
            ssh_port: 22,
            host_key: "fixture-key".into(),
            host_binding: host_binding("192.0.2.1", "ubuntu", 22, "fixture-key").unwrap(),
            data_uuid: "00000000-0000-0000-0000-000000000001".into(),
            wallet: format!("0x{}", "1".repeat(40)),
            creation: "2".repeat(32),
            signer_ref: String::new(),
            upstreams_ref: format!("op://{}/{}/credential", "v".repeat(26), "u".repeat(26)),
            desired: Phase::Observing,
            management_allow: Vec::new(),
            last_run: String::new(),
            last_result: "custody-pending".into(),
        }
    }
    #[test]
    fn original_network_is_required_and_cannot_cross_a_public_inventory_scope() {
        let mock = Mock::new();
        let inventory = store(&mock);
        let mut wrong = pending();
        wrong.network = Network::Testnet;
        assert!(inventory.add_robinhood_validator(&wrong).is_err());
        assert!(
            !mock
                .calls
                .borrow()
                .iter()
                .any(|args| args.get(1).is_some_and(|v| v == "create"))
        );
        let mut separate = store(&mock);
        separate.scope.network = "testnet".into();
        let stored = separate.add_robinhood_validator(&wrong).unwrap();
        assert_eq!(stored.contract().unwrap().network, "testnet");
        assert!(inventory.robinhood_validators().unwrap().is_empty());
        let mut substituted = stored;
        substituted.network = Network::Mainnet;
        assert!(separate.update_robinhood_validator(&substituted).is_err());
    }

    #[test]
    fn projected_creation_and_updates_never_request_host_or_concealed_fields() {
        let mock = Mock::new();
        let inventory = store(&mock);
        let mut node = inventory.add_robinhood_validator(&pending()).unwrap();
        assert!(node.contract().is_ok());
        node.signer_ref = format!("op://{}/{}/private-key", "v".repeat(26), "s".repeat(26));
        node.desired = Phase::Active;
        node = inventory.update_robinhood_validator(&node).unwrap();
        assert_eq!(node.item_version, 2);
        assert_eq!(inventory.robinhood_validators().unwrap(), vec![node]);
        assert!(
            mock.calls
                .borrow()
                .iter()
                .filter(|a| a[1] == "get")
                .all(|a| a[5] == "--fields" && a[6] == SELECTOR)
        );
    }
    #[test]
    fn original_wallet_host_creation_and_active_mode_cannot_be_replaced() {
        let mock = Mock::new();
        let inventory = store(&mock);
        let mut original = inventory.add_robinhood_validator(&pending()).unwrap();
        for field in ["wallet", "creation", "host", "uuid"] {
            let mut changed = original.clone();
            match field {
                "wallet" => changed.wallet = format!("0x{}", "3".repeat(40)),
                "creation" => changed.creation = "4".repeat(32),
                "host" => {
                    changed.host_key = "different".into();
                    changed.host_binding = host_binding(
                        &changed.address,
                        &changed.ssh_user,
                        changed.ssh_port,
                        &changed.host_key,
                    )
                    .unwrap();
                }
                _ => changed.data_uuid = "00000000-0000-0000-0000-000000000002".into(),
            }
            assert!(inventory.update_robinhood_validator(&changed).is_err());
        }
        original.desired = Phase::Active;
        original.signer_ref = format!("op://{}/{}/private-key", "v".repeat(26), "s".repeat(26));
        let active = inventory.update_robinhood_validator(&original).unwrap();
        assert!(inventory.update_robinhood_validator(&original).is_err());
        let mut changed = active.clone();
        changed.desired = Phase::Observing;
        assert!(inventory.update_robinhood_validator(&changed).is_err());
        changed = active;
        changed.signer_ref.clear();
        assert!(inventory.update_robinhood_validator(&changed).is_err());
    }
    #[test]
    fn projection_rejects_wrong_types_duplicates_and_metadata_races_without_secret_errors() {
        let mock = Mock::new();
        let inventory = store(&mock);
        inventory.add_robinhood_validator(&pending()).unwrap();
        for flag in [&mock.concealed, &mock.duplicate_field, &mock.change_on_get] {
            flag.set(true);
            let error = inventory.robinhood_validators().unwrap_err().to_string();
            assert!(!error.contains("inert-secret-sentinel"));
            flag.set(false);
        }
    }
    #[test]
    fn ambiguous_public_creation_is_recovered_by_listing_not_a_second_reservation() {
        let mock = Mock::new();
        let inventory = store(&mock);
        mock.lost_create.set(true);
        assert!(inventory.add_robinhood_validator(&pending()).is_err());
        let records = inventory.robinhood_validators().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].creation, pending().creation);
        assert!(inventory.add_robinhood_validator(&pending()).is_err());
        assert_eq!(
            mock.calls
                .borrow()
                .iter()
                .filter(|a| a[1] == "create")
                .count(),
            1
        );
    }
}
