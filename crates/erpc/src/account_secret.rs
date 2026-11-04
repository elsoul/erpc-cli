// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Secrets that belong to the account rather than to one machine, kept in
//! the store `erpc login` chose.
//!
//! - 1Password: an item tagged with the slot's tag in the login vault, and
//!   looked for there only. It is found again by its tag, on this machine
//!   or another, so every machine signed in to the same vault holds the
//!   same secret.
//! - The macOS keychain: a generic password under the slot's service.
//! - The file store: a file beside the config, mode 0600.
//!
//! A secret is never kept where it would not last. The Linux keyring erpc
//! uses is the kernel's, gone after a reboot, so there a slot needs
//! 1Password or a file.

use erpc_auth::store::StoreKind;
use erpc_auth::store::one_password::OpRunner;
use serde_json::{Value, json};
use zeroize::Zeroizing;

/// One secret and the names it is kept under in each store.
pub struct Slot {
    /// The 1Password item's tag.
    pub tag: &'static str,
    /// The 1Password item's title.
    pub title: &'static str,
    /// The note on the 1Password item.
    pub note: &'static str,
    /// The macOS keychain service.
    pub service: &'static str,
    /// The file's name beside the config, for the file store.
    pub file: &'static str,
    /// What the secret is, for messages ("the storage key").
    pub what: &'static str,
    /// What to do where no store lasts, for the message that says so.
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    pub instead: &'static str,
}

impl Slot {
    /// Where the secret is kept, said for a person.
    #[must_use]
    pub fn place(&self, kind: StoreKind) -> String {
        match kind {
            StoreKind::OnePasswordDesktop | StoreKind::OnePasswordServiceAccount => {
                format!("1Password (item \"{}\")", self.title)
            }
            StoreKind::OsKeychain => format!("the macOS keychain (service {})", self.service),
            StoreKind::File => format!("~/.erpc/{}", self.file),
        }
    }

    /// The secret, if one is kept, and the store it is kept in.
    ///
    /// # Errors
    ///
    /// When the store cannot be read.
    pub fn read(&self) -> Result<(Option<Zeroizing<String>>, StoreKind), String> {
        let (kind, vault) = chosen()?;
        let value = match kind {
            StoreKind::OnePasswordDesktop | StoreKind::OnePasswordServiceAccount => {
                let vault = vault.ok_or(
                    "erpc login keeps the session in 1Password but names no vault (credential_vault)",
                )?;
                op_read(self, &crate::node_common::op_runner()?, &vault)?
            }
            StoreKind::OsKeychain => self.keychain_read()?,
            StoreKind::File => self.file_read()?,
        };
        Ok((value.map(Zeroizing::new), kind))
    }

    /// Keeps `value`, then reads it back, so a store that said yes and kept
    /// nothing is caught now and not when the secret is needed. The caller
    /// checks that nothing is kept yet: this adds, it does not replace.
    ///
    /// # Errors
    ///
    /// When `value` holds a character a store could mangle, or the store
    /// cannot be written or read back.
    pub fn write(&self, value: &str) -> Result<StoreKind, String> {
        if value.is_empty()
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-.:".contains(&b))
        {
            return Err(format!(
                "{} holds a character erpc does not keep",
                self.what
            ));
        }
        let (kind, vault) = chosen()?;
        match kind {
            StoreKind::OnePasswordDesktop | StoreKind::OnePasswordServiceAccount => {
                let vault = vault.ok_or(
                    "erpc login keeps the session in 1Password but names no vault (credential_vault)",
                )?;
                op_create(self, &crate::node_common::op_runner()?, &vault, value)?;
            }
            StoreKind::OsKeychain => self.keychain_write(value)?,
            StoreKind::File => self.file_write(value)?,
        }
        match self.read()? {
            (Some(back), _) if back.as_str() == value => Ok(kind),
            _ => Err(format!(
                "{} could not be read back from {}",
                self.what,
                self.place(kind)
            )),
        }
    }

    #[cfg(target_os = "macos")]
    fn keychain_read(&self) -> Result<Option<String>, String> {
        erpc_auth::store::security_cli::read(self.service, &crate::session::local_account())
    }

    #[cfg(target_os = "macos")]
    fn keychain_write(&self, value: &str) -> Result<(), String> {
        // Add only: a second writer racing the first must not replace a
        // key that files or backups were already sealed with.
        erpc_auth::store::security_cli::add(self.service, &crate::session::local_account(), value)
    }

    #[cfg(not(target_os = "macos"))]
    fn keychain_read(&self) -> Result<Option<String>, String> {
        Err(self.no_lasting_keychain())
    }

    #[cfg(not(target_os = "macos"))]
    fn keychain_write(&self, _value: &str) -> Result<(), String> {
        Err(self.no_lasting_keychain())
    }

    #[cfg(not(target_os = "macos"))]
    fn no_lasting_keychain(&self) -> String {
        format!(
            "the keyring erpc uses here does not last past a reboot, and {} must; sign in with \
             `erpc login --store 1password` or `--store file` to keep it{}",
            self.what, self.instead
        )
    }

    fn file_path(&self) -> Result<std::path::PathBuf, String> {
        crate::session::beside_config(self.file)
    }

    fn file_read(&self) -> Result<Option<String>, String> {
        read_private(&self.file_path()?)
    }

    fn file_write(&self, value: &str) -> Result<(), String> {
        write_private(&self.file_path()?, value, false)
    }
}

/// The store `erpc login` chose, and the 1Password vault it uses.
fn chosen() -> Result<(StoreKind, Option<String>), String> {
    let path = crate::session::config_path()?;
    let config = crate::config::load(&path)?;
    let selection = crate::session::plan_store(None, config.credential_store);
    Ok((selection.kind, config.credential_vault))
}

/// A file only its owner may read, trimmed; `None` when there is none.
///
/// # Errors
///
/// When it cannot be read, or others can read it.
pub fn read_private(path: &std::path::Path) -> Result<Option<String>, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let mode = std::fs::metadata(path)
                    .map_err(|e| format!("could not read {}: {e}", path.display()))?
                    .permissions()
                    .mode();
                if mode & 0o077 != 0 {
                    return Err(format!(
                        "{} can be read by other users (mode {:o}); run `chmod 600 {}`",
                        path.display(),
                        mode & 0o777,
                        path.display()
                    ));
                }
            }
            Ok(Some(text.trim().to_owned()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("could not read {}: {e}", path.display())),
    }
}

/// Writes `text` to `path` through a temporary file made 0600 from the
/// start, then renamed: the secret is never in a file anyone else could
/// open, nor in a half-written one. `replace` says whether an existing file
/// may be replaced.
///
/// # Errors
///
/// When the directory or the file cannot be written, or the file exists
/// and `replace` is false.
pub fn write_private(path: &std::path::Path, text: &str, replace: bool) -> Result<(), String> {
    use std::io::Write as _;
    let dir = path.parent().ok_or("the config directory has no parent")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("could not make {}: {e}", dir.display()))?;
    let mut file = tempfile::NamedTempFile::new_in(dir)
        .map_err(|e| format!("could not write in {}: {e}", dir.display()))?;
    file.write_all(text.as_bytes())
        .and_then(|()| file.as_file().sync_all())
        .map_err(|e| format!("could not write {}: {e}", path.display()))?;
    if replace {
        file.persist(path)
            .map_err(|e| format!("could not keep {}: {}", path.display(), e.error))?;
    } else {
        file.persist_noclobber(path)
            .map_err(|e| format!("could not keep {}: {}", path.display(), e.error))?;
    }
    Ok(())
}

fn run<R: OpRunner>(
    runner: &R,
    args: &[&str],
    stdin: Option<&str>,
    what: &str,
) -> Result<String, String> {
    let out = runner
        .run(args, stdin)
        .map_err(|e| format!("1Password could not {what}: {e}"))?;
    if out.success {
        Ok(out.stdout)
    } else {
        Err(format!("1Password could not {what}"))
    }
}

/// The secret from the oldest item tagged with the slot's tag in the login
/// vault. Only that vault: an item with the same tag in a vault shared with
/// others would otherwise become a secret they also hold.
fn op_read<R: OpRunner>(slot: &Slot, runner: &R, vault: &str) -> Result<Option<String>, String> {
    if vault.is_empty() || vault.starts_with('-') {
        return Err("the 1Password vault is its id or its name".to_owned());
    }
    let listed = run(
        runner,
        &[
            "item", "list", "--tags", slot.tag, "--vault", vault, "--format", "json",
        ],
        None,
        &format!("look for {}", slot.what),
    )?;
    let listed: Vec<Value> =
        serde_json::from_str(&listed).map_err(|_| "1Password's listing was unreadable")?;
    let mut items: Vec<&Value> = listed
        .iter()
        .filter(|i| i["id"].as_str().is_some() && i["vault"]["id"].as_str().is_some())
        .collect();
    items.sort_by_key(|i| i["created_at"].as_str().unwrap_or_default().to_owned());
    let Some(item) = items.first() else {
        return Ok(None);
    };
    let (id, vault) = (
        item["id"].as_str().unwrap_or_default(),
        item["vault"]["id"].as_str().unwrap_or_default(),
    );
    let plain = |v: &str| !v.is_empty() && v.bytes().all(|b| b.is_ascii_alphanumeric());
    if !plain(id) || !plain(vault) {
        return Err(format!(
            "1Password listed an item for {} with an unusable id",
            slot.what
        ));
    }
    let reference = format!("op://{vault}/{id}/key");
    let value = run(
        runner,
        &["read", "--no-newline", &reference],
        None,
        &format!("read {}", slot.what),
    )?;
    Ok(Some(value))
}

fn op_create<R: OpRunner>(slot: &Slot, runner: &R, vault: &str, value: &str) -> Result<(), String> {
    if vault.is_empty() || vault.starts_with('-') {
        return Err("the 1Password vault is its id or its name".to_owned());
    }
    // Built around the secret rather than through a serializer, so the one
    // copy of the template is the one that is wiped. `Slot::write` lets
    // through only characters that need no escaping.
    let mut template = Zeroizing::new(String::new());
    let head = json!({ "title": slot.title, "category": "PASSWORD", "tags": ["erpc", slot.tag] })
        .to_string();
    template.push_str(head.trim_end_matches('}'));
    template.push_str(
        ",\"fields\":[{\"id\":\"key\",\"label\":\"key\",\"type\":\"CONCEALED\",\"value\":\"",
    );
    template.push_str(value);
    template.push_str("\"},");
    template.push_str(
        &json!({ "id": "notesPlain", "label": "notesPlain", "type": "STRING", "purpose": "NOTES",
                 "value": slot.note })
        .to_string(),
    );
    template.push_str("]}");
    run(
        runner,
        &["item", "create", "-", "--vault", vault, "--format", "json"],
        Some(&template),
        &format!("store {}", slot.what),
    )
    .map(drop)
}

#[cfg(test)]
mod tests {
    use super::*;
    use erpc_auth::store::StoreError;
    use erpc_auth::store::one_password::OpOutput;
    use std::cell::RefCell;

    const SLOT: Slot = Slot {
        tag: "erpc-test-secret",
        title: "ERPC test secret",
        note: "a test",
        service: "erpc-test-secret",
        file: "test-secret",
        what: "the test secret",
        instead: "",
    };

    const SECRET: &str = "0123456789abcdef0123456789abcdef";

    /// A vault in memory holding at most one item.
    #[derive(Default)]
    struct FakeOp {
        stored: RefCell<Option<String>>,
        secret_on_argv: RefCell<bool>,
    }

    impl OpRunner for FakeOp {
        fn run(&self, args: &[&str], stdin: Option<&str>) -> Result<OpOutput, StoreError> {
            let ok = |stdout: String| {
                Ok(OpOutput {
                    success: true,
                    stdout,
                    stderr: String::new(),
                })
            };
            if args.iter().any(|a| a.contains(SECRET)) {
                *self.secret_on_argv.borrow_mut() = true;
            }
            match args {
                [
                    "item",
                    "list",
                    "--tags",
                    "erpc-test-secret",
                    "--vault",
                    "Private",
                    ..,
                ] => ok(if self.stored.borrow().is_some() {
                    concat!(
                        r#"[{"id":"itemitemitemitemitemitemit","vault":{"id":"vaultvaultvault"#,
                        r#"vaultvaultx"},"created_at":"2026-10-29"}]"#
                    )
                    .to_owned()
                } else {
                    "[]".to_owned()
                }),
                ["item", "create", "-", "--vault", "Private", ..] => {
                    let v: Value =
                        serde_json::from_str(stdin.unwrap_or_default()).expect("template");
                    assert_eq!(v["tags"][1], "erpc-test-secret");
                    *self.stored.borrow_mut() =
                        v["fields"][0]["value"].as_str().map(ToOwned::to_owned);
                    ok("{}".to_owned())
                }
                [
                    "read",
                    "--no-newline",
                    "op://vaultvaultvaultvaultvaultx/itemitemitemitemitemitemit/key",
                ] => ok(self.stored.borrow().clone().unwrap_or_default()),
                other => panic!("unexpected op call {other:?}"),
            }
        }
    }

    #[test]
    fn a_secret_kept_in_1password_is_found_again_by_its_tag() {
        let op = FakeOp::default();
        assert_eq!(op_read(&SLOT, &op, "Private").expect("lists"), None);
        op_create(&SLOT, &op, "Private", SECRET).expect("creates");
        assert_eq!(
            op_read(&SLOT, &op, "Private").expect("reads").as_deref(),
            Some(SECRET)
        );
        assert!(
            !*op.secret_on_argv.borrow(),
            "the secret went on op's command line"
        );
    }

    #[test]
    fn a_vault_that_reads_as_an_option_is_refused() {
        assert!(op_create(&SLOT, &FakeOp::default(), "--vault", "00").is_err());
        assert!(op_read(&SLOT, &FakeOp::default(), "--all").is_err());
    }

    #[test]
    fn a_private_file_is_written_once_and_read_back() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("secret");
        assert_eq!(read_private(&path).expect("absent"), None);
        write_private(&path, SECRET, false).expect("writes");
        assert_eq!(read_private(&path).expect("reads").as_deref(), Some(SECRET));
        assert!(write_private(&path, "other", false).is_err(), "replaced");
        write_private(&path, "other", true).expect("replaces when asked");
        assert_eq!(
            read_private(&path).expect("reads").as_deref(),
            Some("other")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
            assert!(read_private(&path).is_err(), "read a file others can read");
        }
    }
}
