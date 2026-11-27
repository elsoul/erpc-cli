// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Operator-confirmed, fixed-price-version reports for the account's own rental.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use erpc_ai::session::Access as _;
use erpc_auth::client::JsonResponseLimits;
use erpc_auth::credential::Audience;
use erpc_core::endpoints::SECURITY_CHECK_REPORT_URL;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::{Account, Posture, Server};
use crate::account::commands::Outcome;

const MODEL: &str = "claude-mythos-5-2";
const METER: &str = "posture1";
const BASE: u32 = 512;
const WEIGHT_IN: u32 = 3;
const WEIGHT_OUT: u32 = 12;
const MAX_IN: u32 = 8192;
const MAX_OUT: u32 = 256;
const REPORT_LIMITS: JsonResponseLimits = JsonResponseLimits {
    timeout: Duration::from_secs(120),
    ok_bytes: 16 * 1024,
    other_bytes: 1024,
};
const MAXIMUM: u32 = BASE + MAX_IN * WEIGHT_IN + MAX_OUT * WEIGHT_OUT;

fn expected_quote() -> Value {
    json!({
        "model": MODEL, "meterVersion": METER, "currency": "ai_credits", "baseCredits": BASE,
        "weights": {"input": WEIGHT_IN, "output": WEIGHT_OUT},
        "limits": {"input": MAX_IN, "output": MAX_OUT}, "maximumCredits": MAXIMUM,
    })
}

pub(super) fn valid_quote(body: &str) -> bool {
    body.len() <= 4096 && serde_json::from_str::<Value>(body).ok() == Some(expected_quote())
}

fn quote_prompt() -> String {
    format!(
        "{}\n{}",
        t!("node_check.billing_scope"),
        t!(
            "node_check.quote_confirm",
            maximum = MAXIMUM,
            base = BASE,
            input = WEIGHT_IN,
            output = WEIGHT_OUT,
            model = MODEL
        )
    )
}

fn request_notice(request: &str) -> String {
    t!("node_check.billing_request", request = request)
}

fn uuid_v7(now: SystemTime, mut bytes: [u8; 16]) -> Option<String> {
    let millis = now.duration_since(UNIX_EPOCH).ok()?.as_millis();
    if millis >= 1 << 48 {
        return None;
    }

    // RFC 9562 §5.7, with all 74 payload bits taken from OS entropy.
    bytes[..6].copy_from_slice(&millis.to_be_bytes()[10..]);
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = format!("{:032x}", u128::from_be_bytes(bytes));
    Some(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}

fn report_request(id: &str, rental: Server, posture: &Posture) -> Value {
    json!({
        "requestId": id,
        "server": rental.canonical_id(),
        "meterVersion": METER,
        "maximumCredits": MAXIMUM,
        "posture": posture.billing_facts(),
    })
}

pub(super) struct ApprovedReport {
    request_id: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum SettlementState {
    NoCharge,
    Unconfirmed,
}

impl SettlementState {
    pub(super) fn message(self, request: &str) -> String {
        match self {
            Self::NoCharge => t!("node_check.rules_only_free"),
            Self::Unconfirmed => t!("node_check.billing_unconfirmed", request = request),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum FailureCode {
    AccessUnavailable,
    RequestTimeout,
    RequestTransport,
    Interrupted,
    InvalidReceipt,
    UnknownResponse,
    InvalidPostureReport,
    PostureReportDenied,
    PostureReportNotFunded,
    NotFound,
    SecurityCheckTargetUnavailable,
    PostureRequestExpired,
    PostureAlreadyAttempted,
    PostureReportReconciliationRequired,
    PostureReportNoActionableCandidates,
    PostureReportUnavailable,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ReportFailure {
    pub(super) settlement: SettlementState,
    code: FailureCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    http_status: Option<u16>,
}

impl ReportFailure {
    const fn local(settlement: SettlementState, code: FailureCode) -> Self {
        Self {
            settlement,
            code,
            http_status: None,
        }
    }

    const fn timeout() -> Self {
        Self::local(SettlementState::Unconfirmed, FailureCode::RequestTimeout)
    }

    fn invalid_receipt() -> Self {
        Self {
            settlement: SettlementState::Unconfirmed,
            code: FailureCode::InvalidReceipt,
            http_status: Some(200),
        }
    }

    pub(super) fn from_response(status: u16, body: &str) -> Self {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ErrorBody {
            error: FailureCode,
        }
        use FailureCode as Code;
        let code = if body.len() <= REPORT_LIMITS.other_bytes {
            serde_json::from_str::<ErrorBody>(body).map_or(Code::UnknownResponse, |reply| {
                match (status, reply.error) {
                    (400, code @ Code::InvalidPostureReport)
                    | (403, code @ (Code::PostureReportDenied | Code::PostureReportNotFunded))
                    | (404, code @ (Code::NotFound | Code::SecurityCheckTargetUnavailable))
                    | (
                        409,
                        code @ (Code::PostureRequestExpired
                        | Code::PostureAlreadyAttempted
                        | Code::PostureReportReconciliationRequired
                        | Code::PostureReportNoActionableCandidates),
                    )
                    | (503, code @ Code::PostureReportUnavailable) => code,
                    _ => Code::UnknownResponse,
                }
            })
        } else {
            Code::UnknownResponse
        };
        let settlement = match code {
            Code::PostureReportNoActionableCandidates | Code::PostureReportNotFunded => {
                SettlementState::NoCharge
            }
            _ => SettlementState::Unconfirmed,
        };
        Self {
            settlement,
            code,
            http_status: Some(status),
        }
    }

    pub(super) fn message(self, request: &str) -> String {
        let summary = self.settlement.message(request);
        let code = serde_json::to_value(self.code).unwrap_or_default();
        let code = code.as_str().unwrap_or("unknown_response");
        if let Some(status) = self.http_status {
            format!("{summary}\nHTTP {status} ({code})")
        } else {
            format!("{summary}\n[{code}]")
        }
    }
}

impl ApprovedReport {
    /// Missing route, entitlement, unavailable ledger or a price revision all stop before spending.
    pub(super) fn from_quote(
        body: &str,
        confirm: impl FnOnce(String) -> Result<bool, Outcome>,
    ) -> Result<Option<Self>, Outcome> {
        let unavailable = || Outcome::Failed(t!("node_check.quote_unavailable"));
        if !valid_quote(body) {
            return Err(unavailable());
        }
        if !confirm(quote_prompt())? {
            return Ok(None);
        }
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| unavailable())?;
        let request_id = uuid_v7(SystemTime::now(), bytes).ok_or_else(unavailable)?;
        Ok(Some(Self { request_id }))
    }

    pub(super) fn submission(self, rental: Server, posture: &Posture) -> ReportSubmission {
        let body = report_request(&self.request_id, rental, posture)
            .to_string()
            .into_bytes();
        ReportSubmission {
            idempotency_key: self.request_id,
            body,
        }
    }
}

pub(super) struct ReportSubmission {
    pub(super) idempotency_key: String,
    pub(super) body: Vec<u8>,
}

impl ReportSubmission {
    pub(super) async fn submit(self, account: &Account) -> Result<Receipt, ReportFailure> {
        let token = account.access.access_token().await.map_err(|_| {
            ReportFailure::local(SettlementState::NoCharge, FailureCode::AccessUnavailable)
        })?;
        // The body and idempotency header share the ID for this approval.
        eprintln!("{}", request_notice(&self.idempotency_key));
        let (status, body) = account
            .client
            .post_with_token_bounded(
                Audience::AuthApi,
                SECURITY_CHECK_REPORT_URL,
                &token,
                self.body,
                &self.idempotency_key,
                REPORT_LIMITS,
            )
            .await
            .map_err(|error| match error {
                erpc_auth::HttpError::Timeout { .. } => ReportFailure::timeout(),
                erpc_auth::HttpError::ResponseLimit { status: 200, .. } => {
                    ReportFailure::invalid_receipt()
                }
                erpc_auth::HttpError::ResponseLimit { status, .. } => {
                    ReportFailure::from_response(status, "")
                }
                _ => ReportFailure::local(
                    SettlementState::Unconfirmed,
                    FailureCode::RequestTransport,
                ),
            })?;
        let body = Zeroizing::new(body);
        if status != 200 {
            return Err(ReportFailure::from_response(status, &body));
        }
        let receipt: Receipt =
            serde_json::from_str(&body).map_err(|_| ReportFailure::invalid_receipt())?;
        if !receipt.valid() {
            return Err(ReportFailure::invalid_receipt());
        }
        Ok(receipt)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Billing {
    meter_version: String,
    charged_credits: u32,
    base_credits: u32,
    input_tokens: u32,
    output_tokens: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Receipt {
    status: String,
    model: String,
    findings: Vec<FindingId>,
    billing: Billing,
}

impl Receipt {
    fn valid(&self) -> bool {
        let b = &self.billing;
        self.status == "completed"
            && self.model == MODEL
            && b.meter_version == METER
            && b.base_credits == BASE
            && (1..=MAX_IN).contains(&b.input_tokens)
            && (1..=MAX_OUT).contains(&b.output_tokens)
            && b.charged_credits == BASE + WEIGHT_IN * b.input_tokens + WEIGHT_OUT * b.output_tokens
            && self.findings.len() <= 32
            && self
                .findings
                .iter()
                .enumerate()
                .all(|(i, id)| !self.findings[..i].contains(id))
    }

    pub(super) fn summary(&self) -> String {
        let priorities = self
            .findings
            .iter()
            .enumerate()
            .map(|(index, id)| format!("{}. {}", index + 1, id.label()))
            .collect::<Vec<_>>()
            .join("\n");
        t!(
            "node_check.billing_settled",
            charged = self.billing.charged_credits,
            base = BASE,
            input = self.billing.input_tokens,
            output = self.billing.output_tokens,
            findings = priorities
        )
    }
}

/// Display IDs selected by the Worker from the fixed catalogue.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FindingId {
    ReviewListenerBindings,
    ReviewSshAuthentication,
    ReviewInputFilter,
    ReviewSshJail,
    ReviewFilePermissions,
    ReviewAvailableUpdates,
    VerifyUnobservedPosture,
    ReviewEnvFileUse,
    ReviewRedisBinding,
    IdentifyUnclassifiedListener,
}

impl FindingId {
    fn label(self) -> String {
        match self {
            Self::ReviewListenerBindings => t!("node_check.review_listener_bindings"),
            Self::ReviewSshAuthentication => t!("node_check.review_ssh_authentication"),
            Self::ReviewInputFilter => t!("node_check.review_input_filter"),
            Self::ReviewSshJail => t!("node_check.review_ssh_jail"),
            Self::ReviewFilePermissions => t!("node_check.review_file_permissions"),
            Self::ReviewAvailableUpdates => t!("node_check.review_available_updates"),
            Self::VerifyUnobservedPosture => t!("node_check.verify_unobserved_posture"),
            Self::ReviewEnvFileUse => t!("node_check.review_env_file_use"),
            Self::ReviewRedisBinding => t!("node_check.review_redis_binding"),
            Self::IdentifyUnclassifiedListener => t!("node_check.identify_unclassified_listener"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example() -> Value {
        json!({"status":"completed","model":MODEL,"findings":["review_ssh_jail"],
            "billing":{"meterVersion":METER,"baseCredits":512,"inputTokens":413,
                "outputTokens":55,"chargedCredits":2411}})
    }

    #[test]
    fn uuid_v7_matches_the_rfc_vector_and_keeps_the_random_payload() {
        // RFC 9562 Appendix A.6, normalized to lowercase canonical text.
        let now = UNIX_EPOCH + Duration::from_secs(1_645_557_742);
        let random = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc, 0xc3, 0xd8, 0xc4, 0xdc, 0x0c, 0x0c, 0x07,
            0x39, 0x8f,
        ];
        assert_eq!(
            uuid_v7(now, random).as_deref(),
            Some("017f22e2-79b0-7cc3-98c4-dc0c0c07398f")
        );
        assert_eq!(
            uuid_v7(now, [0; 16]).as_deref(),
            Some("017f22e2-79b0-7000-8000-000000000000")
        );
    }

    #[test]
    fn uuid_v7_rejects_out_of_range_time_without_wrapping() {
        let before_epoch = UNIX_EPOCH - Duration::from_millis(1);
        let max_time = UNIX_EPOCH + Duration::from_millis((1 << 48) - 1);
        let overflow = UNIX_EPOCH + Duration::from_millis(1 << 48);
        assert!(uuid_v7(before_epoch, [0; 16]).is_none());
        assert!(uuid_v7(overflow, [0; 16]).is_none());
        assert_eq!(
            uuid_v7(max_time, [0xff; 16]).as_deref(),
            Some("ffffffff-ffff-7fff-bfff-ffffffffffff")
        );
    }

    #[test]
    fn displays_numeric_quote_and_settlement_without_percent_prefixes() {
        use erpc_core::i18n::Lang;

        let receipt: Receipt = serde_json::from_value(example()).expect("valid receipt");
        for language in [Lang::En, Lang::Ja, Lang::Ru, Lang::Zh] {
            crate::cli::i18n::speaking(language, || {
                let quote = quote_prompt();
                let summary = receipt.summary();
                let quote_numbers = quote
                    .split(|c: char| !c.is_ascii_digit())
                    .collect::<Vec<_>>();
                for expected in ["28160", "512", "3", "12"] {
                    assert!(quote_numbers.contains(&expected), "{quote}");
                }
                let receipt_numbers = summary
                    .split(|c: char| !c.is_ascii_digit())
                    .collect::<Vec<_>>();
                for expected in ["2411", "512", "413", "55"] {
                    assert!(receipt_numbers.contains(&expected), "{summary}");
                }
                let request = "fixture-request";
                for rendered in [
                    quote,
                    summary,
                    request_notice(request),
                    SettlementState::Unconfirmed.message(request),
                ] {
                    assert!(!rendered.contains('%'), "{rendered}");
                    assert!(!rendered.contains('{'), "{rendered}");
                }
                assert!(request_notice(request).contains(request));
                assert!(
                    SettlementState::Unconfirmed
                        .message(request)
                        .contains(request)
                );
            });
        }
    }

    #[test]
    fn reports_only_allowlisted_exact_status_and_body_pairs() {
        let denied = ReportFailure::from_response(403, r#"{"error":"posture_report_not_funded"}"#);
        assert_eq!(
            serde_json::to_value(denied).expect("sanitized failure"),
            json!({"settlement":"no_charge","code":"posture_report_not_funded","httpStatus":403})
        );
        let offline =
            ReportFailure::from_response(503, r#"{"error":"posture_report_unavailable"}"#);
        assert_eq!(offline.settlement, SettlementState::Unconfirmed);
        assert!(
            offline
                .message("fixture-request")
                .contains("HTTP 503 (posture_report_unavailable)")
        );
        for body in [
            r#"{"error":"posture_report_unavailable"}"#,
            r#"{"error":"posture_report_not_funded","message":"private peer diagnostic"}"#,
            r#"{"error":"posture_report_not_funded","error":"posture_report_not_funded"}"#,
            r#"{"error":"private peer diagnostic"}"#,
        ] {
            let unexpected = ReportFailure::from_response(403, body);
            assert_eq!(unexpected.settlement, SettlementState::Unconfirmed);
            assert_eq!(unexpected.code, FailureCode::UnknownResponse);
            assert!(!unexpected.message("fixture-request").contains("private"));
        }
    }

    #[test]
    fn reconciles_the_receipt_locally_and_refuses_unquoted_billing() {
        let ok = |v: Value| serde_json::from_value::<Receipt>(v).is_ok_and(|r| r.valid());
        assert!(ok(example()));
        for (key, numeric) in [
            ("chargedCredits", 2412),
            ("inputTokens", 8193),
            ("outputTokens", 0),
            ("baseCredits", 0),
        ] {
            let mut value = example();
            value["billing"][key] = json!(numeric);
            assert!(!ok(value));
        }
        let mut duplicate = example();
        duplicate["findings"] = json!(["review_ssh_jail", "review_ssh_jail"]);
        assert!(!ok(duplicate));
        let mut arbitrary = example();
        arbitrary["findings"] = json!(["unreviewed"]);
        assert!(!ok(arbitrary));
        let mut raw = example();
        raw["message"] = json!("untrusted text");
        assert!(!ok(raw));
        assert_eq!(expected_quote()["maximumCredits"], 28160);
    }
}
