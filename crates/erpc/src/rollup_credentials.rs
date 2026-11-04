// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Read the explicitly selected concealed L1 field without exposing provider text.

use erpc_auth::store::one_password::OpRunner;
use erpc_chain_rollup::upstreams::Credential;
use erpc_secret::OpRef;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

#[derive(Deserialize)]
struct Field {
    id: String,
    #[serde(default)]
    label: String,
    #[serde(rename = "type")]
    kind: String,
    value: Option<SecretString>,
}

/// Resolve only one explicitly selected field label. The caller still owns its
/// secret-profile authorization and content validation (provider JSON, key file,
/// and so on). This helper never grants signing or deployment authority.
pub(crate) fn read_concealed(
    op: &impl OpRunner,
    reference: &OpRef,
) -> Result<SecretString, String> {
    let selector = format!("label={}", reference.field());
    let output = op
        .run(
            &[
                "item",
                "get",
                reference.item(),
                "--vault",
                reference.vault(),
                "--fields",
                &selector,
                "--format",
                "json",
                "--reveal",
            ],
            None,
        )
        .map_err(|_| "cannot read the selected concealed field")?;
    let _stderr = SecretString::from(output.stderr);
    let raw = SecretString::from(output.stdout);
    if !output.success || raw.expose_secret().len() > 1024 * 1024 {
        return Err("cannot read the selected concealed field".into());
    }
    // Deserialize directly into concealed values instead of an untagged
    // intermediate that can clone credential strings while trying variants.
    let text = raw.expose_secret().trim_start();
    let fields: Vec<Field> = if text.starts_with('[') {
        serde_json::from_str(text).map_err(|_| "invalid selected field projection")?
    } else if text.starts_with('{') {
        vec![serde_json::from_str(text).map_err(|_| "invalid selected field projection")?]
    } else {
        return Err("invalid selected field projection".into());
    };
    let mut fields = fields.into_iter();
    let field = fields.next().ok_or("selected concealed field is missing")?;
    if fields.next().is_some()
        || field.kind != "CONCEALED"
        || field.label != reference.field()
        || field.id.is_empty()
    {
        return Err("selected field label must be unique and concealed".into());
    }
    let value = field.value.ok_or("selected concealed field is empty")?;
    if value.expose_secret().is_empty() || value.expose_secret().len() > 65_536 {
        return Err("selected concealed field is empty or exceeds 64 KiB".into());
    }
    Ok(value)
}

pub(crate) fn read(op: &impl OpRunner, reference: &OpRef) -> Result<Credential, String> {
    Credential::parse(read_concealed(op, reference)?)
        .map_err(|_| "invalid concealed L1 upstream configuration".into())
}

#[cfg(test)]
mod tests {
    use super::{read, read_concealed};
    use erpc_auth::store::{
        StoreError,
        one_password::{OpOutput, OpRunner},
    };
    use erpc_secret::OpRef;
    use secrecy::ExposeSecret;
    use std::cell::RefCell;

    struct Fake {
        output: String,
        success: bool,
        calls: RefCell<Vec<Vec<String>>>,
    }
    impl OpRunner for Fake {
        fn run(&self, args: &[&str], _: Option<&str>) -> Result<OpOutput, StoreError> {
            self.calls
                .borrow_mut()
                .push(args.iter().map(|s| (*s).into()).collect());
            Ok(OpOutput {
                success: self.success,
                stdout: self.output.clone(),
                stderr: "unit-test-provider-placeholder".into(),
            })
        }
    }
    fn reference() -> OpRef {
        OpRef::parse(&format!(
            "op://{}/{}/upstreams",
            "a".repeat(26),
            "b".repeat(26)
        ))
        .expect("reference")
    }
    fn fake(kind: &str) -> Fake {
        let credential = serde_json::json!({"execution":{"url":"https://github.com","headers":{"Authorization":"unit-test-provider-placeholder"}},"beacon":{"url":"https://github.com"}}).to_string();
        Fake { output: serde_json::json!({"id":"upstreams","label":"upstreams","type":kind,"value":credential}).to_string(), success: true, calls: RefCell::default() }
    }
    #[test]
    fn credential_is_selected_by_reference_and_never_added_to_process_arguments() {
        let op = fake("CONCEALED");
        let value = read(&op, &reference()).unwrap_or_else(|_| panic!("valid concealed field"));
        assert!(
            value
                .secret()
                .expose_secret()
                .contains("unit-test-provider-placeholder")
        );
        assert!(!format!("{:?}", op.calls.borrow()).contains("unit-test-provider-placeholder"));
        let calls = op.calls.borrow();
        assert!(
            calls[0]
                .windows(2)
                .any(|pair| pair == ["--fields", "label=upstreams"])
        );
        assert!(calls[0].contains(&"--reveal".into()));
    }
    #[test]
    fn generic_selected_field_has_a_bound_and_does_not_assume_provider_json() {
        let mut op = fake("CONCEALED");
        op.output = serde_json::json!({"id":"field","label":"upstreams","type":"CONCEALED","value":"synthetic node input"}).to_string();
        assert_eq!(
            read_concealed(&op, &reference())
                .expect("selected field")
                .expose_secret(),
            "synthetic node input"
        );
        assert!(
            read(&op, &reference()).is_err(),
            "the rollup wrapper still validates its schema"
        );
        op.output = serde_json::json!({"id":"field","label":"upstreams","type":"CONCEALED","value":"x".repeat(65_537)}).to_string();
        assert!(read_concealed(&op, &reference()).is_err());
    }

    #[test]
    fn plain_fields_errors_and_ambiguous_fields_do_not_reveal_provider_text() {
        let mut op = fake("STRING");
        assert!(read(&op, &reference()).is_err());
        op = fake("CONCEALED");
        op.success = false;
        let error = read(&op, &reference()).err().expect("failed read");
        assert!(!error.contains("unit-test-provider-placeholder"));
        op = fake("CONCEALED");
        let body: serde_json::Value = serde_json::from_str(&op.output).expect("fixture");
        op.output = serde_json::json!([body, body]).to_string();
        assert!(read(&op, &reference()).is_err());
        op = fake("CONCEALED");
        let field: serde_json::Value = serde_json::from_str(&op.output).expect("field");
        op.output = serde_json::json!({"fields":[field]}).to_string();
        assert!(
            read(&op, &reference()).is_err(),
            "never fall back to parsing an unfiltered item"
        );
    }
}
