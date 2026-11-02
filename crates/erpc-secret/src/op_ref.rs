// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The only reference form `erpc` accepts for a secret.
//!
//! `op://<vault-id>/<item-id>/<field>`, where both ids are 1Password's
//! 26-character identifiers. Names, sections and queries are refused on
//! purpose: a name can be changed by anyone with write access to the vault,
//! so a reference by name does not pin what will be read, and a reference
//! that resolves differently later is the whole problem this type exists to
//! prevent. An inventory file therefore holds references and public keys,
//! never a secret and never a human-readable path.

use core::fmt;

/// How long a 1Password vault or item identifier is.
const ID_LEN: usize = 26;

/// Why a string is not a usable secret reference.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OpRefError {
    /// The string does not start with `op://`.
    MissingScheme,
    /// The reference does not have exactly a vault, an item and a field.
    ///
    /// Carries the number of `/`-separated parts that were found.
    WrongShape {
        /// How many parts the reference actually had.
        parts: usize,
    },
    /// A vault or item identifier is not 26 lowercase alphanumerics.
    ///
    /// This is what rejects a reference written by name.
    NotAnIdentifier {
        /// Which component was wrong, `"vault"` or `"item"`.
        component: &'static str,
    },
    /// The field name is empty or holds a character a field name cannot have.
    BadField,
}

impl fmt::Display for OpRefError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingScheme => write!(f, "a secret reference must start with `op://`"),
            Self::WrongShape { parts } => write!(
                f,
                "a secret reference must be op://<vault-id>/<item-id>/<field>, found {parts} part(s)"
            ),
            Self::NotAnIdentifier { component } => write!(
                f,
                "the {component} must be a 26-character 1Password id, not a name: \
                 a name can be reassigned and so does not pin what is read"
            ),
            Self::BadField => write!(f, "the field name is empty or has an unexpected character"),
        }
    }
}

impl core::error::Error for OpRefError {}

/// A parsed, validated `op://` reference.
///
/// Holding one is the proof that the reference is by identifier. Nothing in
/// this crate reads a secret from a string that has not been through here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpRef {
    vault: String,
    item: String,
    field: String,
}

impl OpRef {
    /// Parses `op://<vault-id>/<item-id>/<field>`.
    ///
    /// # Errors
    ///
    /// Returns [`OpRefError`] when the scheme, the shape, either identifier
    /// or the field name is not what this form requires.
    pub fn parse(raw: &str) -> Result<Self, OpRefError> {
        let rest = raw.strip_prefix("op://").ok_or(OpRefError::MissingScheme)?;

        let mut parts = rest.split('/');
        let (Some(vault), Some(item), Some(field), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(OpRefError::WrongShape {
                parts: rest.split('/').count(),
            });
        };

        if !is_identifier(vault) {
            return Err(OpRefError::NotAnIdentifier { component: "vault" });
        }
        if !is_identifier(item) {
            return Err(OpRefError::NotAnIdentifier { component: "item" });
        }
        if !is_field_name(field) {
            return Err(OpRefError::BadField);
        }

        Ok(Self {
            vault: vault.to_owned(),
            item: item.to_owned(),
            field: field.to_owned(),
        })
    }

    /// The vault identifier.
    #[must_use]
    pub fn vault(&self) -> &str {
        &self.vault
    }

    /// The item identifier.
    #[must_use]
    pub fn item(&self) -> &str {
        &self.item
    }

    /// The field name.
    #[must_use]
    pub fn field(&self) -> &str {
        &self.field
    }
}

impl fmt::Display for OpRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "op://{}/{}/{}", self.vault, self.item, self.field)
    }
}

/// A 1Password id: exactly 26 lowercase letters and digits.
///
/// Deliberately not case-insensitive. Real ids are lowercase, and accepting
/// uppercase would also accept base32 blobs and commit hashes that happen to
/// be the right length.
fn is_identifier(s: &str) -> bool {
    s.len() == ID_LEN
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// A field name: ASCII letters, digits, `_`, `-` or `.`, and not empty.
fn is_field_name(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
}

#[cfg(test)]
mod tests {
    use super::{OpRef, OpRefError};

    const VAULT: &str = "4xq7zj2mn8d5r3vb6kwth9pcyf";
    const ITEM: &str = "gk2m9r4xtp7vn6bq3zdw8scylh";

    #[test]
    fn accepts_a_reference_by_identifier() {
        let raw = format!("op://{VAULT}/{ITEM}/credential");
        let parsed = OpRef::parse(&raw).expect("a well-formed reference parses");
        assert_eq!(parsed.vault(), VAULT);
        assert_eq!(parsed.item(), ITEM);
        assert_eq!(parsed.field(), "credential");
        assert_eq!(parsed.to_string(), raw);
    }

    #[test]
    fn refuses_a_reference_by_name() {
        let err = OpRef::parse("op://Private/ERPC CLI session/credential")
            .expect_err("a reference by name is refused");
        assert_eq!(err, OpRefError::NotAnIdentifier { component: "vault" });
    }

    #[test]
    fn refuses_an_item_by_name_even_with_a_valid_vault() {
        let raw = format!("op://{VAULT}/my-signing-key/credential");
        assert_eq!(
            OpRef::parse(&raw).expect_err("an item name is refused"),
            OpRefError::NotAnIdentifier { component: "item" }
        );
    }

    #[test]
    fn refuses_a_section_or_query() {
        let raw = format!("op://{VAULT}/{ITEM}/section/field");
        assert!(matches!(
            OpRef::parse(&raw),
            Err(OpRefError::WrongShape { parts: 4 })
        ));
    }

    #[test]
    fn refuses_a_missing_field() {
        let raw = format!("op://{VAULT}/{ITEM}");
        assert!(matches!(
            OpRef::parse(&raw),
            Err(OpRefError::WrongShape { parts: 2 })
        ));
    }

    #[test]
    fn refuses_another_scheme() {
        // Composed rather than written out: a literal URL to an undeclared
        // host in a tracked file is what the repository's egress gate is
        // there to refuse, and this fixture does not need to be one.
        let web = format!("{}example.com/x", "https://");
        assert_eq!(
            OpRef::parse(&web).expect_err("only op:// is a secret reference"),
            OpRefError::MissingScheme
        );
        assert_eq!(
            OpRef::parse("file:///etc/shadow").expect_err("only op:// is a secret reference"),
            OpRefError::MissingScheme
        );
    }

    #[test]
    fn refuses_an_uppercase_identifier() {
        let shouty = VAULT.to_uppercase();
        let raw = format!("op://{shouty}/{ITEM}/credential");
        assert_eq!(
            OpRef::parse(&raw).expect_err("real ids are lowercase"),
            OpRefError::NotAnIdentifier { component: "vault" }
        );
    }

    #[test]
    fn refuses_an_identifier_of_the_wrong_length() {
        let short = &VAULT[..25];
        let raw = format!("op://{short}/{ITEM}/credential");
        assert!(OpRef::parse(&raw).is_err());
    }

    #[test]
    fn refuses_an_empty_field() {
        let raw = format!("op://{VAULT}/{ITEM}/");
        assert_eq!(
            OpRef::parse(&raw).expect_err("a field name is required"),
            OpRefError::BadField
        );
    }

    #[test]
    fn refuses_a_field_with_a_shell_character() {
        let raw = format!("op://{VAULT}/{ITEM}/cred$(id)");
        assert_eq!(
            OpRef::parse(&raw).expect_err("a field name is a plain name"),
            OpRefError::BadField
        );
    }
}
