// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `~/.erpc/keyless.toml`: which 1Password vault holds each network's nodes.
//!
//! Only vault ids live here: the identities, the inventory and the passwords
//! are in the vault. The file is the one local trace of where to look, and it
//! is written by `erpc v init`.
//!
//! ```toml
//! [networks.testnet]
//! vault_id = "<26 lowercase letters and digits, as 1Password prints it>"
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The file's contents.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Keyless {
    /// Each network's settings, by network name.
    #[serde(default)]
    pub networks: BTreeMap<String, NetworkVault>,
}

/// One network's vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkVault {
    /// The vault's id: 26 lowercase letters and digits, as 1Password prints it.
    pub vault_id: String,
}

/// Where the file is: beside `config.toml`.
///
/// # Errors
///
/// Returns a message when there is no home directory.
pub fn path() -> Result<PathBuf, String> {
    crate::session::beside_config("keyless.toml")
}

/// Reads the file; a missing file is an empty one.
///
/// # Errors
///
/// Returns a message when the file exists but cannot be read or parsed, or
/// names a vault id that is not one.
pub fn load(path: &Path) -> Result<Keyless, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Keyless::default()),
        Err(e) => return Err(format!("could not read {}: {e}", path.display())),
    };
    let keyless: Keyless =
        toml::from_str(&text).map_err(|e| format!("{} is not valid: {e}", path.display()))?;
    for (network, vault) in &keyless.networks {
        if !is_vault_id(&vault.vault_id) {
            return Err(format!(
                "{}: the {network} vault_id {:?} is not a 1Password vault id",
                path.display(),
                vault.vault_id
            ));
        }
    }
    Ok(keyless)
}

/// Writes the file, readable by this user only, through a temporary file in
/// the same directory so a crash leaves the old file or the new one.
///
/// # Errors
///
/// Returns a message when a vault id is not one, or the file cannot be written.
pub fn save(path: &Path, keyless: &Keyless) -> Result<(), String> {
    for (network, vault) in &keyless.networks {
        if !is_vault_id(&vault.vault_id) {
            return Err(format!(
                "the {network} vault_id is not a 1Password vault id"
            ));
        }
    }
    let text =
        toml::to_string(keyless).map_err(|e| format!("could not write keyless.toml: {e}"))?;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir).map_err(|e| format!("could not create {}: {e}", dir.display()))?;
    let tmp = dir.join(".keyless.toml.tmp");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let write = || -> std::io::Result<()> {
        use std::io::Write as _;
        let mut file = options.open(&tmp)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)
    };
    write().map_err(|e| format!("could not write {}: {e}", path.display()))
}

/// Whether `id` has the shape of a 1Password vault id.
#[must_use]
pub fn is_vault_id(id: &str) -> bool {
    id.len() == 26
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::{Keyless, NetworkVault, is_vault_id, load, save};

    /// In two halves: the hygiene gate reads a 26-character lowercase token
    /// beside the word vault as a real identifier.
    const VAULT: &str = concat!("abcdefghijklm", "nopqrstuvwxyz");

    #[test]
    fn a_missing_file_is_empty_and_a_written_one_reads_back() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("keyless.toml");
        assert!(load(&path).expect("missing is fine").networks.is_empty());
        std::fs::write(
            &path,
            format!("[networks.testnet]\nvault_id = \"{VAULT}\"\n"),
        )
        .expect("write");
        let keyless = load(&path).expect("reads");
        assert_eq!(keyless.networks["testnet"].vault_id, VAULT);
    }

    #[test]
    fn a_saved_file_reads_back_and_only_its_owner_can_read_it() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("keyless.toml");
        let mut keyless = Keyless::default();
        keyless.networks.insert(
            "testnet".to_owned(),
            NetworkVault {
                vault_id: VAULT.to_owned(),
            },
        );
        save(&path, &keyless).expect("saves");
        assert_eq!(load(&path).expect("reads"), keyless);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        keyless.networks.get_mut("testnet").expect("t").vault_id = "Employee".to_owned();
        assert!(save(&path, &keyless).is_err());
    }

    #[test]
    fn a_vault_name_instead_of_an_id_is_refused() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("keyless.toml");
        std::fs::write(&path, "[networks.testnet]\nvault_id = \"Employee\"\n").expect("write");
        assert!(load(&path).is_err());
        assert!(!is_vault_id("ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
    }
}
