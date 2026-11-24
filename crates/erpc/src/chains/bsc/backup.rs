// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Concealed, read-back-verified same-owner BSC custody backups.

use erpc_auth::store::one_password::OpRunner;
use erpc_secret::OpRef;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct Identity {
    id: String,
}
#[derive(Serialize)]
struct Field<'a> {
    id: &'static str,
    label: &'static str,
    #[serde(rename = "type")]
    kind: &'static str,
    value: &'a str,
}
#[derive(Serialize)]
struct Template<'a> {
    title: &'a str,
    category: &'static str,
    tags: Vec<&'a str>,
    fields: Vec<Field<'a>>,
}

fn run(
    op: &impl OpRunner,
    args: &[&str],
    input: Option<&SecretString>,
) -> Result<SecretString, String> {
    let out = op
        .run(args, input.map(ExposeSecret::expose_secret))
        .map_err(|_| "BSC custody store operation failed")?;
    let raw = SecretString::from(out.stdout);
    let _stderr = SecretString::from(out.stderr);
    if !out.success || raw.expose_secret().len() > 1024 * 1024 {
        return Err("BSC custody store operation failed".into());
    }
    Ok(raw)
}
fn reference(vault: &str, item: &str) -> Result<OpRef, String> {
    OpRef::parse(&format!("op://{vault}/{item}/custody"))
        .map_err(|_| "invalid custody store identity".into())
}

pub(crate) fn ensure(
    op: &impl OpRunner,
    vault: &str,
    network: &str,
    owner: &str,
    backup: &SecretString,
) -> Result<OpRef, String> {
    if !["mainnet", "chapel"].contains(&network)
        || owner.is_empty()
        || owner.len() > 80
        || !owner
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        || backup.expose_secret().is_empty()
        || backup.expose_secret().len() > 65536
    {
        return Err("invalid bounded BSC custody backup request".into());
    }
    let raw = run(op, &["vault", "get", vault, "--format", "json"], None)?;
    let vault: Identity =
        serde_json::from_str(raw.expose_secret()).map_err(|_| "invalid custody vault response")?;
    // Validate the resolved identifier before using it in any later operation.
    reference(&vault.id, &vault.id)?;
    let tag = format!("erpc.bsc.custody.{network}.{owner}");
    let raw = run(
        op,
        &[
            "item", "list", "--vault", &vault.id, "--tags", &tag, "--format", "json",
        ],
        None,
    )?;
    let mut matches: Vec<Identity> =
        serde_json::from_str(raw.expose_secret()).map_err(|_| "invalid custody item listing")?;
    if matches.len() > 1 {
        return Err("multiple custody backups match this owner; inspect before continuing".into());
    }
    let item = if let Some(item) = matches.pop() {
        item
    } else {
        let template = Template {
            title: &tag,
            category: "SECURE_NOTE",
            tags: vec![&tag],
            fields: vec![Field {
                id: "custody",
                label: "custody",
                kind: "CONCEALED",
                value: backup.expose_secret(),
            }],
        };
        let input = SecretString::from(
            serde_json::to_string(&template).map_err(|_| "cannot encode concealed backup")?,
        );
        let raw = run(
            op,
            &[
                "item", "create", "-", "--vault", &vault.id, "--format", "json",
            ],
            Some(&input),
        )?;
        serde_json::from_str(raw.expose_secret())
            .map_err(|_| "cannot establish created backup identity; retry the same owner")?
    };
    let reference = reference(&vault.id, &item.id)?;
    let back = crate::rollup_credentials::read_concealed(op, &reference)?;
    if back.expose_secret() != backup.expose_secret() {
        return Err("stored custody backup differs from this owner; nothing overwritten".into());
    }
    Ok(reference)
}

#[cfg(test)]
mod tests {
    use super::*;
    use erpc_auth::store::{StoreError, one_password::OpOutput};
    use std::cell::{Cell, RefCell};
    struct Fake {
        present: Cell<bool>,
        ambiguous: Cell<bool>,
        stored: RefCell<SecretString>,
        calls: RefCell<Vec<Vec<String>>>,
    }
    impl OpRunner for Fake {
        fn run(&self, args: &[&str], stdin: Option<&str>) -> Result<OpOutput, StoreError> {
            self.calls
                .borrow_mut()
                .push(args.iter().map(|v| (*v).into()).collect());
            let value = match &args[..2] {
                ["vault", "get"] => serde_json::json!({"id":"a".repeat(26)}),
                ["item", "list"] => {
                    if self.present.get() {
                        serde_json::json!([{"id":"b".repeat(26)}])
                    } else {
                        serde_json::json!([])
                    }
                }
                ["item", "create"] => {
                    let template: serde_json::Value =
                        serde_json::from_str(stdin.expect("stdin template")).expect("template");
                    assert_eq!(template["fields"][0]["type"], "CONCEALED");
                    *self.stored.borrow_mut() = SecretString::from(
                        template["fields"][0]["value"]
                            .as_str()
                            .expect("concealed value")
                            .to_owned(),
                    );
                    self.present.set(true);
                    if self.ambiguous.replace(false) {
                        return Ok(OpOutput {
                            success: false,
                            stdout: "unit-test-backup-placeholder".into(),
                            stderr: "unit-test-backup-placeholder".into(),
                        });
                    }
                    serde_json::json!({"id":"b".repeat(26)})
                }
                ["item", "get"] => {
                    assert!(args.windows(2).any(|p| p == ["--fields", "label=custody"]));
                    serde_json::json!({"id":"custody","label":"custody","type":"CONCEALED","value":self.stored.borrow().expose_secret()})
                }
                _ => panic!("unexpected store command"),
            };
            Ok(OpOutput {
                success: true,
                stdout: value.to_string(),
                stderr: String::new(),
            })
        }
    }
    fn fake() -> Fake {
        Fake {
            present: Cell::new(false),
            ambiguous: Cell::new(false),
            stored: RefCell::new(SecretString::from(String::new())),
            calls: RefCell::default(),
        }
    }
    #[test]
    fn acknowledgement_requires_concealed_readback_and_secrets_never_enter_argv() {
        let op = fake();
        let secret = SecretString::from("unit-test-backup-placeholder".to_owned());
        ensure(&op, "selected-vault", "chapel", "owner", &secret)
            .expect("verified concealed backup");
        ensure(&op, "selected-vault", "chapel", "owner", &secret).expect("idempotent same owner");
        let calls = op.calls.borrow();
        assert_eq!(calls.iter().filter(|v| v[1] == "create").count(), 1);
        assert!(
            calls
                .iter()
                .all(|v| !v.join(" ").contains(secret.expose_secret()))
        );
    }
    #[test]
    fn ambiguous_create_reuses_matching_item_without_replacing_different_material() {
        let op = fake();
        op.ambiguous.set(true);
        let secret = SecretString::from("unit-test-backup-placeholder".to_owned());
        let error = ensure(&op, "selected-vault", "chapel", "owner", &secret)
            .expect_err("ambiguous create");
        assert!(!error.contains(secret.expose_secret()));
        ensure(&op, "selected-vault", "chapel", "owner", &secret).expect("recover exact item");
        assert!(
            ensure(
                &op,
                "selected-vault",
                "chapel",
                "owner",
                &SecretString::from("different fixture".to_owned())
            )
            .is_err()
        );
        assert_eq!(
            op.calls
                .borrow()
                .iter()
                .filter(|v| v[1] == "create")
                .count(),
            1
        );
    }
}
