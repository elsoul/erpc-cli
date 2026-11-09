// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Owned migration-item round trips: unknown user fields remain protected.
//! Never deserialize a whole provider item into an ordinary JSON Value. This
//! visitor protects every string, including unknown notes and concealed fields.
use secrecy::{ExposeSecret as _, SecretString};
use serde::{
    Deserialize, Serialize,
    de::{self, MapAccess, SeqAccess, Visitor},
    ser::{SerializeMap, SerializeSeq},
};
use std::fmt;
use zeroize::{Zeroize as _, Zeroizing};

enum Protected {
    Null,
    Bool(bool),
    Signed(i64),
    Unsigned(u64),
    Decimal(f64),
    Text(SecretString),
    Array(Vec<Self>),
    Object(Vec<(SecretString, Self)>),
}
impl Drop for Protected {
    fn drop(&mut self) {
        match self {
            Self::Bool(value) => value.zeroize(),
            Self::Signed(value) => value.zeroize(),
            Self::Unsigned(value) => value.zeroize(),
            Self::Decimal(value) => value.zeroize(),
            // SecretString handles text; container drops recursively wipe every
            // child, including malformed numeric data in a concealed field.
            Self::Null | Self::Text(_) | Self::Array(_) | Self::Object(_) => {}
        }
    }
}
impl fmt::Debug for Protected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Protected([REDACTED])")
    }
}
impl<'de> Deserialize<'de> for Protected {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ProtectedVisitor;
        impl<'de> Visitor<'de> for ProtectedVisitor {
            type Value = Protected;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("bounded provider metadata")
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(Protected::Null)
            }
            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(Protected::Bool(value))
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(Protected::Signed(value))
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(Protected::Unsigned(value))
            }
            fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
                if !value.is_finite() {
                    return Err(de::Error::custom("nonfinite provider number"));
                }
                Ok(Protected::Decimal(value))
            }
            fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(Protected::Text(value.into()))
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                self.visit_string(value.into())
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element()? {
                    if values.len() >= 4096 {
                        return Err(de::Error::custom("protected array exceeds its bound"));
                    }
                    values.push(value);
                }
                Ok(Protected::Array(values))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut values: Vec<(SecretString, Protected)> = Vec::new();
                while let Some(raw) = map.next_key::<String>()? {
                    let key: SecretString = raw.into();
                    if values
                        .iter()
                        .any(|(old, _)| old.expose_secret() == key.expose_secret())
                    {
                        return Err(de::Error::custom("duplicate protected field"));
                    }
                    if values.len() >= 4096 {
                        return Err(de::Error::custom("protected object exceeds its bound"));
                    }
                    values.push((key, map.next_value()?));
                }
                Ok(Protected::Object(values))
            }
        }
        deserializer.deserialize_any(ProtectedVisitor)
    }
}
impl Serialize for Protected {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Null => serializer.serialize_unit(),
            Self::Bool(value) => serializer.serialize_bool(*value),
            Self::Signed(value) => serializer.serialize_i64(*value),
            Self::Unsigned(value) => serializer.serialize_u64(*value),
            Self::Decimal(value) => serializer.serialize_f64(*value),
            Self::Text(value) => serializer.serialize_str(value.expose_secret()),
            Self::Array(values) => {
                let mut seq = serializer.serialize_seq(Some(values.len()))?;
                for v in values {
                    seq.serialize_element(v)?;
                }
                seq.end()
            }
            Self::Object(values) => {
                let mut map = serializer.serialize_map(Some(values.len()))?;
                for (k, v) in values {
                    map.serialize_entry(k.expose_secret(), v)?;
                }
                map.end()
            }
        }
    }
}
impl Protected {
    fn object(&self) -> Result<&[(SecretString, Self)], &'static str> {
        match self {
            Self::Object(value) => Ok(value),
            _ => Err("protected item object required"),
        }
    }
    fn get(&self, name: &str) -> Result<&Self, &'static str> {
        self.object()?
            .iter()
            .find(|(key, _)| key.expose_secret() == name)
            .map(|(_, value)| value)
            .ok_or("protected item field missing")
    }
    fn text(&self) -> Result<&str, &'static str> {
        match self {
            Self::Text(value) => Ok(value.expose_secret()),
            _ => Err("protected string required"),
        }
    }
    fn put(&mut self, name: &str, value: Self) -> Result<(), &'static str> {
        let Self::Object(values) = self else {
            return Err("protected item object required");
        };
        if let Some((_, old)) = values
            .iter_mut()
            .find(|(key, _)| key.expose_secret() == name)
        {
            *old = value;
        } else {
            values.push((name.to_owned().into(), value));
        }
        Ok(())
    }
}

// Provider numeric metadata includes floating-point password entropy. Preserve
// finite IEEE values, but refuse oversized integer tokens rather than silently
// rounding an unknown identifier into a float. Numbers in secret strings are
// never parsed by this lexical guard.
fn bounded_integers(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    let mut index = 0;
    let mut quoted = false;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
            index += 1;
            continue;
        }
        if byte == b'"' {
            quoted = true;
            index += 1;
            continue;
        }
        if byte == b'-' || byte.is_ascii_digit() {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_digit() || b"-+eE.".contains(&bytes[index]))
            {
                index += 1;
            }
            let token = &raw[start..index];
            if !token.bytes().any(|v| b".eE".contains(&v))
                && (if token.starts_with('-') {
                    token.parse::<i64>().is_err()
                } else {
                    token.parse::<u64>().is_err()
                })
            {
                return false;
            }
        } else {
            index += 1;
        }
    }
    true
}

/// Only one exact, independently projected migration note can be edited.
pub(super) struct MigrationItem(Protected);
impl fmt::Debug for MigrationItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MigrationItem([REDACTED])")
    }
}
impl MigrationItem {
    pub(super) fn parse(
        raw: &SecretString,
        id: &str,
        version: u64,
        vault: &str,
        title: &str,
    ) -> Result<Self, &'static str> {
        if raw.expose_secret().len() > 1_048_576 || !bounded_integers(raw.expose_secret()) {
            return Err("owned migration item exceeds its bound");
        }
        let value: Protected = serde_json::from_str(raw.expose_secret())
            .map_err(|_| "invalid protected migration item")?;
        if value.get("id")?.text() != Ok(id)
            || value.get("title")?.text() != Ok(title)
            || value.get("category")?.text() != Ok("SECURE_NOTE")
            || value.get("vault")?.get("id")?.text() != Ok(vault)
            || !matches!(value.get("version")?,Protected::Unsigned(v) if *v==version)
        {
            return Err("owned migration item identity or version changed");
        }
        // CLI JSON templates cannot preserve passkeys. Unknown binary files or
        // attachment envelopes are never silently removed or reinterpreted.
        for name in ["files", "passkeys"] {
            if let Ok(value) = value.get(name)
                && !matches!(value,Protected::Array(v) if v.is_empty())
                && !matches!(value, Protected::Null)
            {
                return Err(
                    "owned migration item has unsupported binary data; retain it unchanged",
                );
            }
        }
        Ok(Self(value))
    }
    pub(super) fn field(&self, label: &str, kind: &str) -> Result<&str, &'static str> {
        let Protected::Array(fields) = self.0.get("fields")? else {
            return Err("owned item fields missing");
        };
        let mut matches = fields
            .iter()
            .filter(|field| field.get("label").and_then(Protected::text) == Ok(label));
        let field = matches.next().ok_or("owned item field missing")?;
        if matches.next().is_some()
            || field.get("type")?.text() != Ok(kind)
            || field
                .get("section")
                .is_ok_and(|section| !matches!(section, Protected::Null))
        {
            return Err("owned item field is ambiguous");
        }
        field.get("value")?.text()
    }
    pub(super) fn optional_field(
        &self,
        label: &str,
        kind: &str,
    ) -> Result<Option<&str>, &'static str> {
        let Protected::Array(fields) = self.0.get("fields")? else {
            return Err("owned item fields missing");
        };
        if !fields
            .iter()
            .any(|field| field.get("label").and_then(Protected::text) == Ok(label))
        {
            return Ok(None);
        }
        self.field(label, kind).map(Some)
    }
    pub(super) fn preserves(&self, other: &Self, managed: &[&str]) -> Result<bool, &'static str> {
        fn equal(left: &Protected, right: &Protected) -> bool {
            match (left, right) {
                (Protected::Null, Protected::Null) => true,
                (Protected::Bool(a), Protected::Bool(b)) => a == b,
                (Protected::Signed(a), Protected::Signed(b)) => a == b,
                (Protected::Unsigned(a), Protected::Unsigned(b)) => a == b,
                (Protected::Decimal(a), Protected::Decimal(b)) => a.to_bits() == b.to_bits(),
                (Protected::Text(a), Protected::Text(b)) => a.expose_secret() == b.expose_secret(),
                (Protected::Array(a), Protected::Array(b)) => {
                    a.len() == b.len() && a.iter().zip(b).all(|(a, b)| equal(a, b))
                }
                (Protected::Object(a), Protected::Object(b)) => {
                    a.len() == b.len()
                        && a.iter().all(|(key, a)| {
                            b.iter()
                                .find(|(k, _)| k.expose_secret() == key.expose_secret())
                                .is_some_and(|(_, b)| equal(a, b))
                        })
                }
                _ => false,
            }
        }
        fn retained<'a>(fields: &'a [Protected], managed: &[&str]) -> Vec<&'a Protected> {
            fields
                .iter()
                .filter(|field| {
                    !field
                        .get("label")
                        .and_then(Protected::text)
                        .is_ok_and(|label| managed.contains(&label))
                })
                .collect()
        }
        for (key, value) in self.0.object()? {
            let name = key.expose_secret();
            if ["version", "updated_at", "last_edited_by"].contains(&name) {
                continue;
            }
            let after = other.0.get(name)?;
            if name == "fields" {
                let (Protected::Array(before), Protected::Array(after)) = (value, after) else {
                    return Err("owned field list differs");
                };
                let before = retained(before, managed);
                let after = retained(after, managed);
                if before.len() != after.len()
                    || !before.into_iter().zip(after).all(|(a, b)| equal(a, b))
                {
                    return Ok(false);
                }
            } else if !equal(value, after) {
                return Ok(false);
            }
        }
        Ok(true)
    }
    pub(super) fn set_field(
        &mut self,
        label: &str,
        kind: &str,
        value: SecretString,
    ) -> Result<(), &'static str> {
        if !matches!(kind, "STRING" | "CONCEALED") {
            return Err("unsupported owned field type");
        }
        let Protected::Object(object) = &mut self.0 else {
            return Err("owned item object missing");
        };
        let Protected::Array(fields) = &mut object
            .iter_mut()
            .find(|(key, _)| key.expose_secret() == "fields")
            .ok_or("owned item fields missing")?
            .1
        else {
            return Err("owned item fields missing");
        };
        let matches: Vec<_> = fields
            .iter()
            .enumerate()
            .filter(|(_, field)| field.get("label").and_then(Protected::text) == Ok(label))
            .map(|(index, _)| index)
            .collect();
        if let Some(index) = matches.first().copied() {
            if matches.len() != 1
                || fields[index].get("type")?.text() != Ok(kind)
                || fields[index]
                    .get("section")
                    .is_ok_and(|section| !matches!(section, Protected::Null))
            {
                return Err("owned item field is ambiguous");
            }
            fields[index].put("value", Protected::Text(value))?;
        } else {
            if fields
                .iter()
                .any(|field| field.get("id").and_then(Protected::text) == Ok(label))
            {
                return Err("owned item field ID conflicts");
            }
            fields.push(Protected::Object(vec![
                ("id".into(), Protected::Text(label.to_owned().into())),
                ("label".into(), Protected::Text(label.to_owned().into())),
                ("type".into(), Protected::Text(kind.to_owned().into())),
                ("value".into(), Protected::Text(value)),
            ]));
        }
        Ok(())
    }
    pub(super) fn promote_title_and_tag(
        &mut self,
        title: &str,
        old: &str,
        new: &str,
    ) -> Result<(), &'static str> {
        let Protected::Object(object) = &mut self.0 else {
            return Err("owned note object missing");
        };
        let Protected::Array(tags) = &mut object
            .iter_mut()
            .find(|(key, _)| key.expose_secret() == "tags")
            .ok_or("owned tags missing")?
            .1
        else {
            return Err("owned tags missing");
        };
        if tags.iter().filter(|tag| tag.text() == Ok(old)).count() != 1
            || tags.iter().any(|tag| tag.text() == Ok(new))
        {
            return Err("owned scope tags changed");
        }
        for tag in tags {
            if tag.text() == Ok(old) {
                *tag = Protected::Text(new.to_owned().into());
            }
        }
        self.0
            .put("title", Protected::Text(title.to_owned().into()))
    }

    pub(super) fn serialize(&self) -> Result<SecretString, &'static str> {
        let mut output = Zeroizing::new(Vec::new());
        serde_json::to_writer(&mut *output, &self.0)
            .map_err(|_| "cannot encode protected migration update")?;
        if output.len() > 1_048_576 {
            return Err("protected update exceeds its bound");
        }
        let text = match String::from_utf8(std::mem::take(&mut *output)) {
            Ok(text) => text,
            Err(error) => {
                let _wipe = Zeroizing::new(error.into_bytes());
                return Err("invalid protected output encoding");
            }
        };
        Ok(text.into())
    }
}

impl<R: super::OpRunner> super::Store<R> {
    pub(super) fn protected_native_note(
        &self,
        kind: super::Kind,
        name: &str,
        id: &str,
        version: u64,
    ) -> Result<(MigrationItem, String), super::InventoryError> {
        let invalid = || super::InventoryError::Unreadable("owned native note update");
        if !matches!(kind, super::Kind::NativeHost | super::Kind::NativeMigration) {
            return Err(invalid());
        }
        let vault = self.public_item_vault(kind, name, id, version)?;
        let output = self
            .runner
            .run(
                &[
                    "item", "get", id, "--vault", &vault, "--format", "json", "--reveal",
                ],
                None,
            )
            .map_err(|_| invalid())?;
        let _stderr = SecretString::from(output.stderr);
        let raw = SecretString::from(output.stdout);
        if !output.success {
            return Err(invalid());
        }
        let note = MigrationItem::parse(&raw, id, version, &vault, &self.title(kind, name))
            .map_err(|_| invalid())?;
        if self.public_item_vault(kind, name, id, version)? != vault {
            return Err(invalid());
        }
        Ok((note, vault))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> SecretString {
        serde_json::json!({"id":"a".repeat(26),"version":1,"title":"owned","category":"SECURE_NOTE",
            "vault":{"id":"v".repeat(26)},"tags":["user-kept"],"fields":[
                {"id":"other","label":"other","type":"CONCEALED","value":"INERT_UNKNOWN_SECRET","entropy":118.283_493_041_992_19}
            ]}).to_string().into()
    }
    fn read(raw: &SecretString) -> Result<MigrationItem, &'static str> {
        MigrationItem::parse(raw, &"a".repeat(26), 1, &"v".repeat(26), "owned")
    }
    #[test]
    fn unknown_secrets_and_finite_provider_numbers_roundtrip_without_debug_disclosure() {
        let mut item = read(&fixture()).unwrap();
        assert!(!format!("{item:?}").contains("INERT"));
        item.set_field("migration_identity", "CONCEALED", "INERT_ORIGINAL".into())
            .unwrap();
        let serialized = item.serialize().unwrap();
        let other = read(&serialized).unwrap();
        assert_eq!(
            other.field("other", "CONCEALED").unwrap(),
            "INERT_UNKNOWN_SECRET"
        );
        assert_eq!(
            other.field("migration_identity", "CONCEALED").unwrap(),
            "INERT_ORIGINAL"
        );
        assert!(item.preserves(&other, &["migration_identity"]).unwrap());
    }
    #[test]
    fn duplicate_fields_binary_payload_and_inexact_integers_refuse_without_content_errors() {
        let original = fixture();
        for replacement in [
            original.expose_secret().replacen(
                '{',
                "{\"files\":[{\"content\":\"INERT_PRIVATE\"}],",
                1,
            ),
            original
                .expose_secret()
                .replacen('{', "{\"passkeys\":[\"INERT_PRIVATE\"],", 1),
            original.expose_secret().replacen('{', "{\"version\":1,", 1),
            original
                .expose_secret()
                .replacen('{', "{\"unknown_number\":18446744073709551616,", 1),
        ] {
            let error = read(&replacement.into()).unwrap_err();
            assert!(!error.contains("INERT"));
        }
        let mut item = read(&original).unwrap();
        assert!(
            item.set_field("other", "STRING", "INERT_REPLACEMENT".into())
                .is_err()
        );
        assert_eq!(
            item.field("other", "CONCEALED").unwrap(),
            "INERT_UNKNOWN_SECRET"
        );
    }
}
