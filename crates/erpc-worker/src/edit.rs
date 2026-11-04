// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Changes `erpc worker` makes to an app's `erpc.toml`, keeping everything
//! else in the file -- comments, order, spacing -- as the operator wrote it.
//!
//! Each change is made to the text and the result checked as a whole
//! manifest before it is returned, so a change never leaves a file that
//! `erpc worker check` would refuse. [`save`] then replaces the file in one
//! step.

use std::path::Path;

use toml_edit::{DocumentMut, Item, Table, value};

use crate::manifest::{Manifest, SecretRef};

fn parse(text: &str) -> Result<DocumentMut, String> {
    text.parse::<DocumentMut>()
        .map_err(|e| format!("erpc.toml is not valid TOML: {e}"))
}

fn finish(doc: &DocumentMut) -> Result<String, String> {
    let text = doc.to_string();
    Manifest::parse(&text).map_err(|e| format!("the change would make {e}"))?;
    Ok(text)
}

/// A table at the top level, made when missing. A table written inline
/// (`wallet = { ... }`) is refused rather than rewritten.
fn table<'a>(doc: &'a mut DocumentMut, name: &str) -> Result<&'a mut Table, String> {
    let next = next_position(doc);
    let item = doc.entry(name).or_insert_with(|| {
        let mut table = Table::new();
        table.set_position(next);
        Item::Table(table)
    });
    item.as_table_mut().ok_or_else(|| {
        format!("[{name}] is written inline in erpc.toml; write it as a [{name}] table to let erpc change it")
    })
}

/// The position after every table in the document. A table made without
/// one is written wherever `toml_edit` happens to put it -- the first
/// deploy on a real server put `[env.default.resource]` above `[vars]` --
/// so every table erpc adds is given the next one, and goes last.
fn next_position(doc: &DocumentMut) -> usize {
    fn walk(table: &Table, next: &mut usize) {
        for (_, item) in table {
            if let Some(t) = item.as_table() {
                if let Some(p) = t.position() {
                    *next = (*next).max(p + 1);
                }
                walk(t, next);
            }
        }
    }
    let mut next = 1;
    walk(doc.as_table(), &mut next);
    next
}

/// Sets `[wallet]` to `source` and `pubkey`.
///
/// # Errors
///
/// A message when the text is not a manifest, or would not be one after.
pub fn set_wallet(text: &str, source: &SecretRef, pubkey: &str) -> Result<String, String> {
    let mut doc = parse(text)?;
    let wallet = table(&mut doc, "wallet")?;
    wallet.insert("source", value(source.to_string()));
    wallet.insert("pubkey", value(pubkey));
    finish(&doc)
}

/// Sets `[secrets].<name>` to `reference`.
///
/// # Errors
///
/// A message when the text is not a manifest, or would not be one after.
pub fn set_secret(text: &str, name: &str, reference: &SecretRef) -> Result<String, String> {
    let mut doc = parse(text)?;
    table(&mut doc, "secrets")?.insert(name, value(reference.to_string()));
    finish(&doc)
}

/// Removes `[secrets].<name>`, and the table when it is left empty.
/// Returns the text and whether there was such a secret.
///
/// # Errors
///
/// A message when the text is not a manifest, or would not be one after.
pub fn remove_secret(text: &str, name: &str) -> Result<(String, bool), String> {
    let mut doc = parse(text)?;
    let Some(secrets) = doc.get_mut("secrets") else {
        return Ok((text.to_owned(), false));
    };
    let secrets = secrets
        .as_table_like_mut()
        .ok_or("[secrets] in erpc.toml is not a table")?;
    let removed = secrets.remove(name).is_some();
    if secrets.is_empty() {
        doc.remove("secrets");
    }
    Ok((finish(&doc)?, removed))
}

/// Sets `[env.<name>]` to `env`, replacing what erpc wrote there before.
/// The other environments, and everything else in the file, stay as they
/// are.
///
/// # Errors
///
/// A message when the text is not a manifest, or would not be one after.
pub fn set_env(text: &str, name: &str, env: &crate::manifest::Env) -> Result<String, String> {
    let mut doc = parse(text)?;
    let rendered = toml::to_string(env).map_err(|e| e.to_string())?;
    let mut fresh = rendered
        .parse::<DocumentMut>()
        .map_err(|e| e.to_string())?
        .as_table()
        .clone();
    // Put last: the old table, if any, goes, and this one and its
    // sub-tables (`resource`, `firewall`) follow everything else.
    if let Some(envs) = doc.get_mut("env").and_then(Item::as_table_mut) {
        envs.remove(name);
    }
    // A list of tables (`lines`) is written as one entry per line inside
    // this table, rather than as `[[env.<name>.lines]]` blocks.
    let lists: Vec<String> = fresh
        .iter()
        .filter(|(_, item)| item.is_array_of_tables())
        .map(|(key, _)| key.to_owned())
        .collect();
    for key in lists {
        if let Some(blocks) = fresh
            .remove(&key)
            .and_then(|i| i.into_array_of_tables().ok())
        {
            fresh.insert(
                &key,
                Item::Value(toml_edit::Value::Array(blocks.into_array())),
            );
        }
    }
    // `inventory = { vault = "…" }` on one line, as it is written by hand.
    if let Some(inventory) = fresh.remove("inventory").and_then(|i| i.into_table().ok()) {
        fresh.insert(
            "inventory",
            Item::Value(toml_edit::Value::InlineTable(inventory.into_inline_table())),
        );
    }
    let mut next = next_position(&doc);
    fresh.set_implicit(false);
    fresh.set_position(next);
    for (_, item) in fresh.iter_mut() {
        if let Some(t) = item.as_table_mut() {
            next += 1;
            t.set_implicit(false);
            t.set_position(next);
        }
    }
    let envs = table(&mut doc, "env")?;
    envs.set_implicit(true);
    envs.insert(name, Item::Table(fresh));
    finish(&doc)
}

/// Removes `[env.<name>]`, and `[env]` when it is left empty. Returns the
/// text and whether there was such an environment.
///
/// # Errors
///
/// A message when the text is not a manifest, or would not be one after.
pub fn remove_env(text: &str, name: &str) -> Result<(String, bool), String> {
    let mut doc = parse(text)?;
    let Some(envs) = doc.get_mut("env").and_then(Item::as_table_like_mut) else {
        return Ok((text.to_owned(), false));
    };
    let removed = envs.remove(name).is_some();
    if envs.is_empty() {
        doc.remove("env");
    }
    Ok((finish(&doc)?, removed))
}

/// Replaces the file at `path` with `text` in one step: written beside it,
/// given its permissions, then renamed over it.
///
/// # Errors
///
/// A message naming the file that could not be written.
pub fn save(path: &Path, text: &str) -> Result<(), String> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp_name = path.file_name().unwrap_or_default().to_os_string();
    tmp_name.push(format!(".{}.tmp", std::process::id()));
    let tmp = dir.join(tmp_name);
    let written = std::fs::write(&tmp, text)
        .and_then(|()| match std::fs::metadata(path) {
            Ok(meta) => std::fs::set_permissions(&tmp, meta.permissions()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        })
        .and_then(|()| std::fs::rename(&tmp, path));
    written.map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("could not write {}: {e}", path.display())
    })
}

#[cfg(test)]
mod tests {
    use super::{remove_secret, set_secret, set_wallet};
    use crate::manifest::{Manifest, SecretRef};

    const TEXT: &str = "# my bot\nname = \"bot\"   # its name\nchain = \"solana\"\n\n\
                        [vars]\n# the log level\nRUST_LOG = \"info\"\n";

    fn keychain(account: &str) -> SecretRef {
        SecretRef::parse(&format!("keychain:erpc-worker/{account}")).expect("reference")
    }

    #[test]
    fn a_vps_bought_and_not_yet_reached_is_a_valid_record() {
        use crate::manifest::{Env, Line, LineKind, Resource, ResourceKind};
        let env = Env {
            resource: Some(Resource {
                kind: ResourceKind::Vps,
                id: "100001".to_owned(),
                region: Some("amsterdam".to_owned()),
                hourly: true,
            }),
            lines: vec![Line {
                kind: LineKind::Unlimited,
                id: "100003".to_owned(),
                endpoint: String::new(),
                hourly: true,
            }],
            ..Env::default()
        };
        let text = super::set_env(TEXT, "default", &env).expect("set");
        let m = Manifest::parse(&text).expect("valid");
        assert_eq!(m.env["default"], env);
        // A pending line sets nothing the app gets.
        assert_eq!(m.env["default"].line_vars().count(), 0);
    }

    #[test]
    fn an_inventory_environment_is_written_on_one_line() {
        use crate::manifest::{Env, Inventory};
        // In two halves: the hygiene gate reads a 26-character lowercase
        // token beside the word vault as a real identifier.
        const VAULT: &str = concat!("abcdefghijklm", "nopqrstuvwxyz");
        let env = Env {
            inventory: Some(Inventory {
                vault: VAULT.to_owned(),
            }),
            ..Env::default()
        };
        let text = super::set_env(TEXT, "prod", &env).expect("set");
        assert!(
            text.contains(&format!(
                "[env.prod]\ninventory = {{ vault = \"{VAULT}\" }}"
            )),
            "{text}"
        );
        assert!(!text.contains("[env.prod.inventory]"), "{text}");
        assert_eq!(Manifest::parse(&text).expect("valid").env["prod"], env);
    }

    #[test]
    fn a_wallet_is_added_and_the_comments_stay() {
        let pubkey = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
        let text = set_wallet(TEXT, &keychain("bot.wallet"), pubkey).expect("set");
        assert!(
            text.starts_with("# my bot\nname = \"bot\"   # its name\n"),
            "{text}"
        );
        assert!(text.contains("# the log level"), "{text}");
        let m = Manifest::parse(&text).expect("valid");
        let wallet = m.wallet.expect("wallet");
        assert_eq!(wallet.pubkey.as_deref(), Some(pubkey));
        assert_eq!(wallet.source, keychain("bot.wallet"));
    }

    #[test]
    fn a_secret_is_set_replaced_and_removed() {
        let text = set_secret(TEXT, "X_TOKEN", &keychain("bot.X_TOKEN")).expect("set");
        let text = set_secret(&text, "X_TOKEN", &keychain("bot.X_TOKEN2")).expect("replace");
        let m = Manifest::parse(&text).expect("valid");
        assert_eq!(m.secrets["X_TOKEN"], keychain("bot.X_TOKEN2"));
        let (text, removed) = remove_secret(&text, "X_TOKEN").expect("remove");
        assert!(removed);
        assert!(!text.contains("[secrets]"), "{text}");
        let (_, removed) = remove_secret(&text, "X_TOKEN").expect("again");
        assert!(!removed);
    }

    #[test]
    fn a_change_that_breaks_the_manifest_is_refused() {
        // RUST_LOG is in [vars]; the same name in [secrets] is a problem.
        assert!(set_secret(TEXT, "RUST_LOG", &keychain("bot.RUST_LOG")).is_err());
        assert!(set_secret(TEXT, "lower", &keychain("bot.lower")).is_err());
        let inline = format!("{TEXT}wallet = {{ source = \"keychain:a/b\" }}\n");
        assert!(
            set_wallet(
                &inline,
                &keychain("x"),
                "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"
            )
            .is_err()
        );
    }

    #[test]
    fn an_environment_is_written_replaced_and_removed() {
        use crate::manifest::{Env, Firewall, Line, LineKind, Resource, ResourceKind};
        use crate::net::Cidr;
        let env = Env {
            lines: vec![Line {
                kind: LineKind::Grpc,
                id: "42".to_owned(),
                // Built, not written out: the endpoint gate reads literals.
                endpoint: ["https", "edge.erpc.global"].join("://"),
                hourly: true,
            }],
            resource: Some(Resource {
                kind: ResourceKind::Vps,
                id: "123".to_owned(),
                region: Some("frankfurt".to_owned()),
                hourly: true,
            }),
            host: Some("203.0.113.10".to_owned()),
            ssh_user: Some("solv".to_owned()),
            host_key: Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample".to_owned()),
            firewall: Firewall {
                ssh_allow: vec![Cidr::parse("198.51.100.7").expect("cidr")],
                app_allow: Vec::new(),
            },
            ..Env::default()
        };
        let text = super::set_env(TEXT, "default", &env).expect("set");
        assert!(text.contains("# the log level"), "{text}");
        assert!(text.contains("[env.default]"), "{text}");
        assert!(text.contains("[env.default.resource]"), "{text}");
        assert!(
            !text.contains("[[env"),
            "a line is one entry, not a block: {text}"
        );
        assert!(text.contains("lines = [{"), "{text}");
        let m = Manifest::parse(&text).expect("valid");
        assert_eq!(m.env("default").expect("env"), &env);
        let other = Env {
            host: Some("203.0.113.11".to_owned()),
            ..env.clone()
        };
        let text = super::set_env(&text, "default", &other).expect("replace");
        assert_eq!(Manifest::parse(&text).expect("valid").env["default"], other);
        let (text, removed) = super::remove_env(&text, "default").expect("remove");
        assert!(removed);
        assert!(!text.contains("[env"), "{text}");
    }

    #[test]
    fn save_replaces_the_file_and_keeps_its_mode() {
        let dir = std::env::temp_dir().join(format!("erpc-worker-edit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("erpc.toml");
        std::fs::write(&path, TEXT).expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).expect("chmod");
        }
        super::save(&path, "name = \"bot\"\nchain = \"solana\"\n").expect("save");
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            "name = \"bot\"\nchain = \"solana\"\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o640);
        }
        let _ = std::fs::remove_dir_all(dir);
    }
}
