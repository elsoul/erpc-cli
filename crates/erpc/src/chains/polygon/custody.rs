// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Original dedicated signer custody. The caller durably records this public
//! binding before creation and never generates again for a pending binding.
use erpc_auth::store::one_password::OpRunner;
use erpc_secret::OpRef;
use erpc_wallet::evm::EvmKey;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::json;

pub(crate) struct Binding<'a> {
    pub vault: &'a str,
    pub network: &'a str,
    pub owner: &'a str,
    pub creation: &'a str,
    pub address: &'a str,
}

pub(crate) struct Original {
    pub reference: String,
    pub secret: SecretString,
}

#[derive(Deserialize, PartialEq, Eq)]
struct Vault {
    id: String,
}
#[derive(Deserialize, PartialEq, Eq)]
struct Listed {
    id: String,
    title: String,
    tags: Vec<String>,
    vault: Vault,
    category: String,
    version: u64,
}
#[derive(Deserialize)]
struct Field {
    id: String,
    label: String,
    #[serde(rename = "type")]
    kind: String,
    value: Option<SecretString>,
}

fn identifier(value: &str) -> bool {
    value.len() == 26
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}
impl Binding<'_> {
    fn validate(&self) -> Result<(), String> {
        if self.vault.is_empty()
            || !["mainnet", "amoy"].contains(&self.network)
            || !identifier(self.owner)
            || self.creation.len() != 32
            || !self
                .creation
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || self.address.len() != 42
            || !self.address.starts_with("0x")
            || !self.address[2..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("invalid original Polygon signer binding".into());
        }
        Ok(())
    }
    fn tag(&self) -> String {
        format!(
            "erpc-cli/polygon/{}/original-signer/{}",
            self.network, self.owner
        )
    }
    fn title(&self) -> String {
        format!(
            "erpc polygon {} original signer {}",
            self.network, self.owner
        )
    }
    fn fields(&self) -> [(&'static str, &str); 5] {
        [
            ("format", "polygon-original-signer-v1"),
            ("network", self.network),
            ("owner", self.owner),
            ("creation", self.creation),
            ("address", self.address),
        ]
    }
}

fn output(op: &impl OpRunner, args: &[&str]) -> Result<SecretString, String> {
    let result = op
        .run(args, None)
        .map_err(|_| "original Polygon signer read failed")?;
    let _stderr = SecretString::from(result.stderr);
    let value = SecretString::from(result.stdout);
    if !result.success || value.expose_secret().len() > 1024 * 1024 {
        return Err("original Polygon signer read failed".into());
    }
    Ok(value)
}

fn find(op: &impl OpRunner, binding: &Binding<'_>) -> Result<Option<Listed>, String> {
    let raw = output(
        op,
        &[
            "item",
            "list",
            "--vault",
            binding.vault,
            "--tags",
            &binding.tag(),
            "--format",
            "json",
        ],
    )?;
    let listed: Vec<Listed> = serde_json::from_str(raw.expose_secret())
        .map_err(|_| "original Polygon signer listing is invalid")?;
    if listed.len() > 1 {
        return Err("multiple original Polygon signer items require explicit recovery".into());
    }
    let Some(item) = listed.into_iter().next() else {
        return Ok(None);
    };
    if !identifier(&item.id)
        || !identifier(&item.vault.id)
        || item.category != "SECURE_NOTE"
        || item.version == 0
        || item.tags != vec![binding.tag()]
        || (identifier(binding.vault) && item.vault.id != binding.vault)
        || item.title != binding.title()
        || !item.tags.contains(&binding.tag())
    {
        return Err("original Polygon signer item identity differs".into());
    }
    Ok(Some(item))
}

fn read(op: &impl OpRunner, binding: &Binding<'_>, item: &Listed) -> Result<Original, String> {
    let raw = output(
        op,
        &[
            "item",
            "get",
            &item.id,
            "--vault",
            &item.vault.id,
            "--fields",
            "label=format,label=network,label=owner,label=creation,label=address",
            "--format",
            "json",
        ],
    )?;
    let fields: Vec<Field> = serde_json::from_str(raw.expose_secret())
        .map_err(|_| "original Polygon signer public binding is unreadable")?;
    if fields.len() != 5 {
        return Err("original Polygon signer public binding is incomplete".into());
    }
    for (label, wanted) in binding.fields() {
        let found: Vec<_> = fields.iter().filter(|field| field.label == label).collect();
        if found.len() != 1
            || found[0].id != label
            || found[0].kind != "STRING"
            || found[0].value.as_ref().map(ExposeSecret::expose_secret) != Some(wanted)
        {
            return Err("original Polygon signer public binding differs".into());
        }
    }
    let reference = format!("op://{}/{}/signer_secret", item.vault.id, item.id);
    let parsed =
        OpRef::parse(&reference).map_err(|_| "invalid original Polygon signer reference")?;
    let secret = crate::rollup_credentials::read_concealed(op, &parsed)?;
    let key = EvmKey::from_hex(secret.expose_secret())
        .map_err(|_| "original Polygon signer material is invalid")?;
    if key.address().to_string().to_lowercase() != binding.address.to_lowercase() {
        return Err("original Polygon signer does not match its durable public address".into());
    }
    if find(op, binding)?.as_ref() != Some(item) {
        return Err("original Polygon signer changed while reading custody".into());
    }
    Ok(Original { reference, secret })
}

/// `fresh` may be supplied only in the invocation that created and durably read
/// back the fresh public binding. A retry passes None and must recover the
/// existing original; an absent/ambiguous original never authorizes regeneration.
pub(crate) fn original(
    op: &impl OpRunner,
    binding: &Binding<'_>,
    fresh: Option<&SecretString>,
) -> Result<Original, String> {
    binding.validate()?;
    if let Some(item) = find(op, binding)? {
        let original = read(op, binding, &item)?;
        if fresh.is_some_and(|new| new.expose_secret() != original.secret.expose_secret()) {
            return Err("an existing original Polygon signer cannot be replaced".into());
        }
        return Ok(original);
    }
    let secret = fresh.ok_or("original Polygon signer creation is pending or missing; recover the original item, never generate a replacement")?;
    let key =
        EvmKey::from_hex(secret.expose_secret()).map_err(|_| "fresh Polygon signer is invalid")?;
    if key.address().to_string().to_lowercase() != binding.address.to_lowercase() {
        return Err("fresh Polygon signer differs from the durable creation binding".into());
    }
    // Public metadata may use Value. The secret is serialized directly into a
    // zeroizing document, never inserted into a generic Value/object tree.
    let fields: Vec<_> = binding
        .fields()
        .into_iter()
        .map(|(label, value)| json!({"id":label,"label":label,"type":"STRING","value":value}))
        .collect();
    let public =
        serde_json::to_string(&fields).map_err(|_| "cannot encode original signer binding")?;
    let encoded = SecretString::from(
        serde_json::to_string(secret.expose_secret())
            .map_err(|_| "cannot encode original signer material")?,
    );
    let document = SecretString::from(format!(
        "{{\"title\":{},\"category\":\"SECURE_NOTE\",\"tags\":[{}],\"fields\":[{},{{\"id\":\"signer_secret\",\"label\":\"signer_secret\",\"type\":\"CONCEALED\",\"value\":{}}}]}}",
        json!(binding.title()),
        json!(binding.tag()),
        &public[1..public.len() - 1],
        encoded.expose_secret()
    ));
    // Creation output can echo a key even on failure. Never use its untrusted
    // ID or parse the full document; discover the original by its scoped tag.
    if let Ok(result) = op.run(
        &[
            "item",
            "create",
            "-",
            "--vault",
            binding.vault,
            "--format",
            "json",
        ],
        Some(document.expose_secret()),
    ) {
        let _stdout = SecretString::from(result.stdout);
        let _stderr = SecretString::from(result.stderr);
    }
    let item = find(op, binding)?.ok_or("original Polygon signer creation outcome is uncertain; recover the original item before any host transfer")?;
    let original = read(op, binding, &item)?;
    if original.secret.expose_secret() != secret.expose_secret() {
        return Err(
            "original Polygon signer failed exact read-back; no host transfer authorized".into(),
        );
    }
    Ok(original)
}

#[cfg(test)]
mod tests {
    use super::{Binding, original};
    use erpc_auth::store::{
        StoreError,
        one_password::{OpOutput, OpRunner},
    };
    use erpc_wallet::evm::EvmKey;
    use secrecy::{ExposeSecret, SecretString};
    use serde_json::{Value, json};
    use std::cell::{Cell, RefCell};

    struct Fake {
        body: RefCell<Option<Value>>,
        calls: RefCell<Vec<Vec<String>>>,
        fail_create: bool,
        publish: bool,
        duplicate: Cell<bool>,
        damage: Cell<bool>,
        version: Cell<u64>,
        drift: Cell<bool>,
    }
    impl Default for Fake {
        fn default() -> Self {
            Self {
                body: RefCell::default(),
                calls: RefCell::default(),
                fail_create: false,
                publish: true,
                duplicate: Cell::new(false),
                damage: Cell::new(false),
                version: Cell::new(1),
                drift: Cell::new(false),
            }
        }
    }
    impl OpRunner for Fake {
        fn run(&self, args: &[&str], stdin: Option<&str>) -> Result<OpOutput, StoreError> {
            self.calls
                .borrow_mut()
                .push(args.iter().map(|value| (*value).to_owned()).collect());
            let result = match args[1] {
                "list" => {
                    if let Some(body) = self.body.borrow().as_ref() {
                        let item = json!({"id":"b".repeat(26),"title":body["title"],"tags":body["tags"],"vault":{"id":"a".repeat(26)},"category":body["category"],"version":self.version.get()});
                        if self.duplicate.get() {
                            json!([item, item])
                        } else {
                            json!([item])
                        }
                    } else {
                        json!([])
                    }
                }
                "create" => {
                    let value: Value =
                        serde_json::from_str(stdin.expect("private stdin")).expect("template");
                    assert_eq!(value["fields"][5]["type"], "CONCEALED");
                    if self.publish {
                        *self.body.borrow_mut() = Some(value);
                    }
                    if self.fail_create {
                        return Err(StoreError::Corrupt("inert echoed provider failure".into()));
                    }
                    // Intentionally unusable response; identity must come from scoped discovery.
                    json!({"id":"wrong-response-id","fields":"provider may echo secret input"})
                }
                "get" => {
                    let body = self.body.borrow();
                    let fields = body.as_ref().expect("original")["fields"]
                        .as_array()
                        .expect("fields");
                    let selector = args[args
                        .iter()
                        .position(|arg| *arg == "--fields")
                        .expect("field projection")
                        + 1];
                    if selector == "label=signer_secret" {
                        assert!(args.contains(&"--reveal"));
                        if self.drift.get() {
                            self.version.set(self.version.get() + 1);
                        }
                        let mut secret = fields[5].clone();
                        if self.damage.get() {
                            secret["value"] = json!("invalid original fixture");
                        }
                        secret
                    } else {
                        assert!(!args.contains(&"--reveal"));
                        json!(fields[..5])
                    }
                }
                _ => panic!("unexpected custody operation"),
            };
            Ok(OpOutput {
                success: true,
                stdout: result.to_string(),
                stderr: "inert provider diagnostics".into(),
            })
        }
    }
    fn fixture() -> (SecretString, String, String, String) {
        // Deterministic encoding fixture; never invoke key generation or signing.
        let key = SecretString::from("01".repeat(32));
        let address = EvmKey::from_hex(key.expose_secret())
            .expect("encoding fixture")
            .address()
            .to_string()
            .to_lowercase();
        (key, address, "i".repeat(26), "c".repeat(32))
    }
    #[test]
    fn stdin_creation_reads_back_original_before_return_and_retry_never_recreates() {
        let (key, address, owner, creation) = fixture();
        let fake = Fake::default();
        let binding = Binding {
            vault: "a named vault",
            network: "amoy",
            owner: &owner,
            creation: &creation,
            address: &address,
        };
        let first = original(&fake, &binding, Some(&key)).expect("original read-back");
        assert_eq!(first.secret.expose_secret(), key.expose_secret());
        assert_eq!(
            first.reference,
            format!("op://{}/{}/signer_secret", "a".repeat(26), "b".repeat(26))
        );
        let second = original(&fake, &binding, None).expect("recover existing original");
        assert_eq!(second.reference, first.reference);
        assert_eq!(
            fake.calls
                .borrow()
                .iter()
                .filter(|call| call[1] == "create")
                .count(),
            1
        );
        assert!(!format!("{:?}", fake.calls.borrow()).contains(key.expose_secret()));
    }
    #[test]
    fn ambiguous_create_recovers_exact_published_original_without_trusting_response() {
        let (key, address, owner, creation) = fixture();
        let fake = Fake {
            fail_create: true,
            ..Fake::default()
        };
        let binding = Binding {
            vault: "vault",
            network: "amoy",
            owner: &owner,
            creation: &creation,
            address: &address,
        };
        assert_eq!(
            original(&fake, &binding, Some(&key))
                .expect("recover after lost response")
                .secret
                .expose_secret(),
            key.expose_secret()
        );
        assert!(original(&fake, &binding, None).is_ok());
        assert_eq!(
            fake.calls
                .borrow()
                .iter()
                .filter(|call| call[1] == "create")
                .count(),
            1
        );
    }
    #[test]
    fn missing_original_after_uncertain_creation_never_authorizes_a_retry_generation() {
        let (key, address, owner, creation) = fixture();
        let fake = Fake {
            fail_create: true,
            publish: false,
            ..Fake::default()
        };
        let binding = Binding {
            vault: "vault",
            network: "amoy",
            owner: &owner,
            creation: &creation,
            address: &address,
        };
        let error = original(&fake, &binding, Some(&key))
            .err()
            .expect("no read-back");
        assert!(!error.contains(key.expose_secret()));
        assert!(!error.contains("inert echoed"));
        assert!(original(&fake, &binding, None).is_err());
        assert_eq!(
            fake.calls
                .borrow()
                .iter()
                .filter(|call| call[1] == "create")
                .count(),
            1
        );
    }
    #[test]
    fn duplicate_damaged_or_foreign_creation_records_refuse_without_writes() {
        let (key, address, owner, creation) = fixture();
        let fake = Fake::default();
        let binding = Binding {
            vault: "vault",
            network: "amoy",
            owner: &owner,
            creation: &creation,
            address: &address,
        };
        original(&fake, &binding, Some(&key)).expect("fixture original");
        fake.duplicate.set(true);
        assert!(original(&fake, &binding, None).is_err());
        fake.duplicate.set(false);
        fake.damage.set(true);
        assert!(original(&fake, &binding, None).is_err());
        fake.damage.set(false);
        let changed = "d".repeat(32);
        assert!(
            original(
                &fake,
                &Binding {
                    creation: &changed,
                    ..binding
                },
                None
            )
            .is_err()
        );
        assert_eq!(
            fake.calls
                .borrow()
                .iter()
                .filter(|call| call[1] == "create")
                .count(),
            1
        );
    }
    #[test]
    fn metadata_drift_after_concealed_read_never_returns_host_transfer_material() {
        let (key, address, owner, creation) = fixture();
        let fake = Fake::default();
        let binding = Binding {
            vault: "vault",
            network: "amoy",
            owner: &owner,
            creation: &creation,
            address: &address,
        };
        original(&fake, &binding, Some(&key)).unwrap();
        fake.drift.set(true);
        assert!(original(&fake, &binding, None).is_err());
        fake.drift.set(false);
        fake.version.set(0);
        assert!(original(&fake, &binding, None).is_err());
        fake.version.set(3);
        fake.body.borrow_mut().as_mut().unwrap()["category"] = json!("LOGIN");
        assert!(original(&fake, &binding, None).is_err());
        fake.body.borrow_mut().as_mut().unwrap()["category"] = json!("SECURE_NOTE");
        fake.body.borrow_mut().as_mut().unwrap()["tags"]
            .as_array_mut()
            .unwrap()
            .push(json!("unrelated"));
        assert!(original(&fake, &binding, None).is_err());
    }
}
