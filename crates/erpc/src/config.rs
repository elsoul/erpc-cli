// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `~/.erpc/config.toml`: the choices the operator has made.
//!
//! Public information only. The session store and the 1Password vault are
//! kept here so that `erpc whoami`, `erpc logout` and `erpc doctor` use the
//! store `erpc login` put the session in, rather than guessing again. A
//! vault id names a vault; it opens nothing.
//!
//! Only the keys this module owns are written. Anything else in the file is
//! read back and kept as it was.

use std::path::Path;

use erpc_auth::store::StoreKind;

/// The keys this build reads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Config {
    /// Where sessions are kept: `credential_store`.
    pub credential_store: Option<StoreKind>,
    /// Which 1Password vault holds them: `credential_vault`.
    pub credential_vault: Option<String>,
}

/// Reads the configuration at `path`. A file that is not there is an empty
/// configuration.
///
/// # Errors
///
/// Returns a message when the file cannot be read, is not TOML, or names a
/// store this build does not know. A configuration that cannot be read is
/// not quietly ignored: it would send the session somewhere the operator
/// did not choose.
pub fn load(path: &Path) -> Result<Config, String> {
    let table = read_table(path)?;
    let credential_store = match table.get("credential_store") {
        None => None,
        Some(toml::Value::String(name)) => Some(StoreKind::parse(name).ok_or_else(|| {
            format!(
                "{}: credential_store = \"{name}\" is not a store erpc knows; use keychain, \
                 1password or file",
                path.display()
            )
        })?),
        Some(_) => {
            return Err(format!(
                "{}: credential_store must be a string",
                path.display()
            ));
        }
    };
    let credential_vault = match table.get("credential_vault") {
        None => None,
        Some(toml::Value::String(id)) if !id.is_empty() => Some(id.clone()),
        Some(_) => {
            return Err(format!(
                "{}: credential_vault must be a 1Password vault id",
                path.display()
            ));
        }
    };
    Ok(Config {
        credential_store,
        credential_vault,
    })
}

/// Records where `erpc login` put the session.
///
/// `vault` is written for a 1Password store and removed for any other, so
/// a vault chosen once does not linger as if it still applied.
///
/// # Errors
///
/// Returns a message when the file cannot be read back or written. A file
/// that is not valid TOML is left alone rather than overwritten, because it
/// may hold the operator's other settings.
pub fn save_store(path: &Path, kind: StoreKind, vault: Option<&str>) -> Result<(), String> {
    let mut table = read_table(path)?;
    table.insert(
        "credential_store".to_owned(),
        toml::Value::String(kind.as_str().to_owned()),
    );
    match vault {
        Some(id) => {
            table.insert(
                "credential_vault".to_owned(),
                toml::Value::String(id.to_owned()),
            );
        }
        None => {
            table.remove("credential_vault");
        }
    }
    let text =
        toml::to_string(&table).map_err(|e| format!("could not write the configuration: {e}"))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("could not create {}: {e}", parent.display()))?;
    }
    // Beside the target and renamed over it, so a reader never sees half
    // a file.
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, text).map_err(|e| format!("could not write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("could not write {}: {e}", path.display()))
}

fn read_table(path: &Path) -> Result<toml::Table, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => text
            .parse::<toml::Table>()
            .map_err(|e| format!("{} is not valid TOML: {}", path.display(), e.message())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(toml::Table::new()),
        Err(e) => Err(format!("could not read {}: {e}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::{Config, load, save_store};
    use erpc_auth::store::StoreKind;

    #[test]
    fn no_file_is_an_empty_configuration() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        assert_eq!(load(&dir.path().join("config.toml")), Ok(Config::default()));
    }

    #[test]
    fn a_choice_is_read_back() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("config.toml");
        save_store(&path, StoreKind::OnePasswordDesktop, Some("vault-id")).expect("saved");
        let config = load(&path).expect("read");
        assert_eq!(config.credential_store, Some(StoreKind::OnePasswordDesktop));
        assert_eq!(config.credential_vault.as_deref(), Some("vault-id"));
    }

    #[test]
    fn choosing_a_store_without_a_vault_forgets_the_old_vault() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("config.toml");
        save_store(&path, StoreKind::OnePasswordDesktop, Some("vault-id")).expect("saved");
        save_store(&path, StoreKind::OsKeychain, None).expect("saved");
        let config = load(&path).expect("read");
        assert_eq!(config.credential_store, Some(StoreKind::OsKeychain));
        assert_eq!(config.credential_vault, None);
    }

    #[test]
    fn other_settings_are_kept() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "default_chain = \"solana\"\nlocale = \"ja\"\n").expect("write");
        save_store(&path, StoreKind::OsKeychain, None).expect("saved");
        let text = std::fs::read_to_string(&path).expect("read");
        assert!(text.contains("default_chain = \"solana\""), "{text}");
        assert!(text.contains("locale = \"ja\""), "{text}");
    }

    #[test]
    fn the_short_name_for_1password_is_understood() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "credential_store = \"op\"\n").expect("write");
        assert_eq!(
            load(&path).expect("read").credential_store,
            Some(StoreKind::OnePasswordDesktop)
        );
    }

    #[test]
    fn an_unknown_store_or_a_broken_file_is_an_error_not_a_default() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "credential_store = \"cloud\"\n").expect("write");
        assert!(load(&path).is_err());
        std::fs::write(&path, "credential_store = [\n").expect("write");
        assert!(load(&path).is_err());
        assert!(
            save_store(&path, StoreKind::OsKeychain, None).is_err(),
            "a broken file is not overwritten"
        );
    }
}
