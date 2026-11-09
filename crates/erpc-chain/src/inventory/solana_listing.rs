// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Public backend selection and summaries, without retrieving host passwords.
use super::{FORMAT, InventoryError, Kind, OpRunner, Store, solana_public::selected_fields};
use secrecy::ExposeSecret as _;
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// The inventory's recorded execution backend, not a host health assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// Dedicated native ownership is present.
    Native,
    /// Existing Solv metadata must keep its original operation path.
    Solv,
    /// No node is reserved in the selected role.
    New,
    /// Original legacy writers and native startup are fenced during explicit migration.
    Migration,
}

fn invalid() -> InventoryError {
    InventoryError::Unreadable("public Solana node summary")
}
impl<R: OpRunner> Store<R> {
    fn summary_fields(
        &self,
        kind: Kind,
        name: &str,
        extra: &[&str],
    ) -> Result<BTreeMap<String, String>, InventoryError> {
        let labels: Vec<_> = ["erpc_format", "name"]
            .into_iter()
            .chain(extra.iter().copied())
            .collect();
        let selector = labels
            .iter()
            .map(|label| format!("label={label}"))
            .collect::<Vec<_>>()
            .join(",");
        let (_, _, result) = self.public_projection(kind, name, &selector, |raw| {
            let fields = selected_fields(raw, &labels)?;
            if fields["erpc_format"].expose_secret() != FORMAT
                || fields["name"].expose_secret() != name
            {
                return Err(invalid());
            }
            Ok(fields
                .into_iter()
                .map(|(key, value)| (key, value.expose_secret().to_owned()))
                .collect())
        })?;
        Ok(result)
    }

    fn reconcile_migrated_native(&self, name: &str) -> Result<(), InventoryError> {
        let original = self.solana_original_migration(name)?;
        self.verify_solana_original_migration(&original)?;
        if self.solana_migration_cutover(&original)?.is_none() {
            return Err(invalid());
        }
        Ok(())
    }

    /// Select an existing backend using exact-scope public metadata only.
    /// # Errors
    /// Refuses duplicate native/legacy reservations, wrong roles and malformed metadata.
    pub fn solana_backend(&self, name: &str, rpc: bool) -> Result<Backend, InventoryError> {
        super::check_name(name)?;
        for migration in self.solana_pending_migrations()? {
            let summary = migration.summary();
            if migration.node.contract.name == name || summary["host_name"] == name {
                if migration.node.contract.is_rpc() != rpc {
                    return Err(invalid());
                }
                return Ok(Backend::Migration);
            }
        }
        let native = self
            .public_names(Kind::NativeHost)?
            .iter()
            .any(|n| n == name);
        let legacy = self
            .public_names(if rpc { Kind::Rpc } else { Kind::Validator })?
            .iter()
            .any(|n| n == name);
        if native {
            let node = self.solana_native_host(name)?;
            if node.contract.is_rpc() != rpc {
                return Err(invalid());
            }
            if rpc && legacy {
                self.reconcile_migrated_native(name)?;
            }
            if !rpc {
                for host in self.public_names(Kind::Host)? {
                    if self.summary_fields(Kind::Host, &host, &["validator"])?["validator"] == name
                    {
                        self.reconcile_migrated_native(name)?;
                        break;
                    }
                }
            }
            return Ok(Backend::Native);
        }
        if legacy && !rpc {
            // A logical registration is not a deployed Solv host. In particular,
            // an interrupted native init can have reserved the registration
            // before its native host record was saved.
            for host in self.public_names(Kind::Host)? {
                if self.summary_fields(Kind::Host, &host, &["validator"])?["validator"] == name {
                    return Ok(Backend::Solv);
                }
            }
            return Ok(Backend::New);
        }
        Ok(if legacy { Backend::Solv } else { Backend::New })
    }

    /// Produce public inventory rows for both backends. This never contacts a node.
    /// Native deployed versions and access policies require `status` / `plan`;
    /// they are deliberately not inferred from the CLI's current catalog.
    /// # Errors
    /// Refuses ambiguous, concealed, malformed or concurrently changed selected fields.
    pub fn solana_node_summaries(&self, rpc: bool) -> Result<Vec<Value>, InventoryError> {
        let pending = self.solana_pending_migrations()?;
        let native = self.solana_native_hosts()?;
        let mut rows = Vec::new();
        if rpc {
            for name in self.public_names(Kind::Rpc)? {
                if let Some(migration) = pending.iter().find(|p| p.node.contract.name == name) {
                    if !migration.node.contract.is_rpc() {
                        return Err(invalid());
                    }
                    self.verify_solana_pending_migration(migration)?;
                    rows.push(migration.summary());
                    continue;
                }
                if native.iter().any(|node| node.contract.name == name) {
                    self.reconcile_migrated_native(&name)?;
                    continue;
                }
                let f = self.summary_fields(
                    Kind::Rpc,
                    &name,
                    &[
                        "address",
                        "client",
                        "rpc_type",
                        "version",
                        "identity_account",
                        "rpc_allow",
                        "last_result",
                    ],
                )?;
                rows.push(json!({"network":self.scope.network,"name":name,"backend":"solv","address":f["address"],"client":f["client"],"type":f["rpc_type"],"version":f["version"],"identity":f["identity_account"],"rpc_allow":f["rpc_allow"].split(',').filter(|s|!s.is_empty()).collect::<Vec<_>>(),"last_result":f["last_result"]}));
            }
            for node in native.iter().filter(|n| n.contract.is_rpc()) {
                rows.push(json!({"network":self.scope.network,"name":node.contract.name,"backend":"native","address":node.address,"client":"agave","type":"native","version":null,"identity":node.contract.identity_account,"rpc_allow":null,"last_result":null}));
            }
        } else {
            let mut hosts = Vec::new();
            for name in self.public_names(Kind::Host)? {
                hosts.push(self.summary_fields(
                    Kind::Host,
                    &name,
                    &["validator", "role", "address", "last_result"],
                )?);
            }
            for name in self.public_names(Kind::Validator)? {
                if let Some(migration) = pending.iter().find(|p| p.node.contract.name == name) {
                    if migration.node.contract.is_rpc() {
                        return Err(invalid());
                    }
                    self.verify_solana_pending_migration(migration)?;
                    rows.push(migration.summary());
                    continue;
                }
                let f = self.summary_fields(
                    Kind::Validator,
                    &name,
                    &["identity_account", "client", "version", "region"],
                )?;
                let native_node = native.iter().find(|n| n.contract.name == name);
                let legacy: Vec<_> = hosts.iter().filter(|h| h["validator"] == name).collect();
                if native_node.is_some_and(|n| n.contract.is_rpc()) {
                    return Err(invalid());
                }
                if native_node.is_some() && !legacy.is_empty() {
                    self.reconcile_migrated_native(&name)?;
                }
                let host_rows = if let Some(node) = native_node {
                    if f["identity_account"] != node.contract.identity_account {
                        return Err(invalid());
                    }
                    vec![
                        json!({"name":node.contract.name,"role":"primary","address":node.address,"last_result":null}),
                    ]
                } else {
                    legacy.iter().map(|h|json!({"name":h["name"],"role":h["role"],"address":h["address"],"last_result":h["last_result"]})).collect()
                };
                // A registration without a host is neither backend's node
                // yet: `solana_backend` gives it as `New`, and the init that
                // stored it before it stopped resumes it.
                let backend = match native_node {
                    Some(_) => json!("native"),
                    None if legacy.is_empty() => Value::Null,
                    None => json!("solv"),
                };
                rows.push(json!({"network":self.scope.network,"name":name,"backend":backend,"identity":f["identity_account"],"client":f["client"],"version":if native_node.is_some(){Value::Null}else{json!(f["version"])},"region":f["region"],"hosts":host_rows}));
            }
            if native
                .iter()
                .filter(|n| !n.contract.is_rpc())
                .any(|n| !rows.iter().any(|row| row["name"] == n.contract.name))
            {
                return Err(invalid());
            }
        }
        rows.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
        Ok(rows)
    }
}
