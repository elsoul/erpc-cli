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

const METER: &str = "posture1";
const BASE: u32 = 512;
const MAX_IN: u32 = 8192;
const MAX_OUT: u32 = 256;
const REPORT_LIMITS: JsonResponseLimits = JsonResponseLimits {
    timeout: Duration::from_secs(120),
    ok_bytes: 16 * 1024,
    other_bytes: 1024,
};
const CONSENT_HEADER: &str = "x-erpc-security-check-consent";
const CONSENT_VERSION: &str = "security-check-local-posture-v1";
const FALLBACK_HEADER: &str = "x-erpc-security-check-fallback";

#[derive(Clone, Copy)]
struct Price {
    model: &'static str,
    input: u32,
    output: u32,
}

impl Price {
    const PRIMARY: Self = Self {
        model: "claude-mythos-5-2",
        input: 3,
        output: 12,
    };
    const FALLBACK: Self = Self {
        model: "claude-sonnet-5-5",
        input: 1,
        output: 3,
    };

    const fn credits(self, input: u32, output: u32) -> u32 {
        BASE + self.input * input + self.output * output
    }

    const fn maximum(self) -> u32 {
        self.credits(MAX_IN, MAX_OUT)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Consent {
    #[default]
    Internal,
    ExternalV1,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Terms {
    consent: Consent,
    fallback: bool,
}

fn external_consent<'de, D: serde::Deserializer<'de>>(value: D) -> Result<Consent, D::Error> {
    let version = String::deserialize(value)?;
    if version == CONSENT_VERSION {
        Ok(Consent::ExternalV1)
    } else {
        Err(serde::de::Error::custom(
            "unknown Security Check consent version",
        ))
    }
}

// Untagged struct variants require JSON objects and still reject duplicate fields.
#[derive(Deserialize, PartialEq, Eq)]
#[serde(untagged, deny_unknown_fields)]
enum Tokens {
    Pair { input: u32, output: u32 },
}

#[derive(Deserialize)]
#[serde(untagged, rename_all_fields = "camelCase", deny_unknown_fields)]
enum Quote {
    Fixed {
        model: String,
        meter_version: String,
        currency: String,
        base_credits: u32,
        weights: Tokens,
        limits: Tokens,
        maximum_credits: u32,
        #[serde(default, deserialize_with = "external_consent")]
        consent_version: Consent,
        #[serde(default, deserialize_with = "fallback_quote")]
        fallback: Option<Box<Quote>>,
    },
}

fn fallback_quote<'de, D: serde::Deserializer<'de>>(
    value: D,
) -> Result<Option<Box<Quote>>, D::Error> {
    Box::deserialize(value).map(Some)
}

impl Quote {
    fn valid_for(&self, price: Price) -> bool {
        let Self::Fixed {
            model,
            meter_version,
            currency,
            base_credits,
            weights,
            limits,
            maximum_credits,
            ..
        } = self;
        model == price.model
            && meter_version == METER
            && currency == "ai_credits"
            && *base_credits == BASE
            && *weights
                == (Tokens::Pair {
                    input: price.input,
                    output: price.output,
                })
            && *limits
                == (Tokens::Pair {
                    input: MAX_IN,
                    output: MAX_OUT,
                })
            && *maximum_credits == price.maximum()
    }
}

fn parse_quote(body: &str) -> Option<Terms> {
    if body.len() > 4096 {
        return None;
    }
    let quote: Quote = serde_json::from_str(body).ok()?;
    if !quote.valid_for(Price::PRIMARY) {
        return None;
    }
    let Quote::Fixed {
        consent_version,
        fallback,
        ..
    } = quote;
    let fallback = match (consent_version, fallback) {
        (_, None) => false,
        (Consent::ExternalV1, Some(quote))
            if matches!(
                *quote,
                Quote::Fixed {
                    fallback: None,
                    consent_version: Consent::Internal,
                    ..
                }
            ) && quote.valid_for(Price::FALLBACK) =>
        {
            true
        }
        _ => return None,
    };
    Some(Terms {
        consent: consent_version,
        fallback,
    })
}

fn quote_prompt(terms: Terms, rental: Server) -> String {
    let scope = match terms.consent {
        Consent::Internal => t!("node_check.billing_scope"),
        Consent::ExternalV1 => t!(
            "node_check.external_consent",
            server = rental.canonical_id()
        ),
    };
    let price = t!(
        "node_check.quote_confirm",
        maximum = Price::PRIMARY.maximum(),
        base = BASE,
        input = Price::PRIMARY.input,
        output = Price::PRIMARY.output,
        model = Price::PRIMARY.model
    );
    if !terms.fallback {
        return format!("{scope}\n{price}");
    }
    let fallback = t!(
        "node_check.quote_fallback",
        model = Price::FALLBACK.model,
        maximum = Price::FALLBACK.maximum(),
        base = BASE,
        input = Price::FALLBACK.input,
        output = Price::FALLBACK.output
    );
    format!("{scope}\n{price}\n{fallback}")
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
        "maximumCredits": Price::PRIMARY.maximum(),
        "posture": posture.billing_facts(),
    })
}

pub(super) struct ApprovedReport {
    request_id: String,
    rental: Server,
    terms: Terms,
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
    PostureReportConsentRequired,
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
                    | (
                        403,
                        code @ (Code::PostureReportDenied
                        | Code::PostureReportConsentRequired
                        | Code::PostureReportNotFunded),
                    )
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
        rental: Server,
        confirm: impl FnOnce(String) -> Result<bool, Outcome>,
    ) -> Result<Option<Self>, Outcome> {
        let unavailable = || Outcome::Failed(t!("node_check.quote_unavailable"));
        let terms = parse_quote(body).ok_or_else(unavailable)?;
        if !confirm(quote_prompt(terms, rental))? {
            return Ok(None);
        }
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| unavailable())?;
        let request_id = uuid_v7(SystemTime::now(), bytes).ok_or_else(unavailable)?;
        Ok(Some(Self {
            request_id,
            rental,
            terms,
        }))
    }

    pub(super) fn submission(self, posture: &Posture) -> ReportSubmission {
        let body = report_request(&self.request_id, self.rental, posture)
            .to_string()
            .into_bytes();
        ReportSubmission {
            idempotency_key: self.request_id,
            body,
            terms: self.terms,
        }
    }
}

pub(super) struct ReportSubmission {
    pub(super) idempotency_key: String,
    pub(super) body: Vec<u8>,
    terms: Terms,
}

impl Terms {
    fn headers(self, idempotency_key: &str) -> Vec<(&str, &str)> {
        let mut headers = vec![("idempotency-key", idempotency_key)];
        if self.consent == Consent::ExternalV1 {
            headers.push((CONSENT_HEADER, CONSENT_VERSION));
            if self.fallback {
                headers.push((FALLBACK_HEADER, Price::FALLBACK.model));
            }
        }
        headers
    }

    fn receipt(self, status: u16, body: &str) -> Result<Receipt, ReportFailure> {
        if status != 200 {
            return Err(ReportFailure::from_response(status, body));
        }
        let receipt: Receipt =
            serde_json::from_str(body).map_err(|_| ReportFailure::invalid_receipt())?;
        if !receipt.valid(self) {
            return Err(ReportFailure::invalid_receipt());
        }
        Ok(receipt)
    }
}

impl ReportSubmission {
    #[cfg(test)]
    pub(super) fn headers(&self) -> Vec<(&str, &str)> {
        self.terms.headers(&self.idempotency_key)
    }

    #[cfg(test)]
    pub(super) fn fixture_receipt(&self, body: &str) -> Result<Receipt, ReportFailure> {
        self.terms.receipt(200, body)
    }

    pub(super) async fn submit(self, account: &Account) -> Result<Receipt, ReportFailure> {
        let token = account.access.access_token().await.map_err(|_| {
            ReportFailure::local(SettlementState::NoCharge, FailureCode::AccessUnavailable)
        })?;
        // The body and idempotency header share the ID for this approval.
        eprintln!("{}", request_notice(&self.idempotency_key));
        let headers = self.terms.headers(&self.idempotency_key);
        let (status, body) = account
            .client
            .post_with_token_bounded_and_headers(
                Audience::AuthApi,
                SECURITY_CHECK_REPORT_URL,
                &token,
                self.body,
                &headers,
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
        self.terms.receipt(status, &body)
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
    fn valid(&self, terms: Terms) -> bool {
        let price = if self.model == Price::PRIMARY.model {
            Price::PRIMARY
        } else if terms.consent == Consent::ExternalV1
            && terms.fallback
            && self.model == Price::FALLBACK.model
        {
            Price::FALLBACK
        } else {
            return false;
        };
        let b = &self.billing;
        self.status == "completed"
            && b.meter_version == METER
            && b.base_credits == BASE
            && (1..=MAX_IN).contains(&b.input_tokens)
            && (1..=MAX_OUT).contains(&b.output_tokens)
            && b.charged_credits == price.credits(b.input_tokens, b.output_tokens)
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
            model = &self.model,
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

    const EXTERNAL: Terms = Terms {
        consent: Consent::ExternalV1,
        fallback: false,
    };
    const WITH_FALLBACK: Terms = Terms {
        consent: Consent::ExternalV1,
        fallback: true,
    };

    fn example() -> Value {
        json!({"status":"completed","model":Price::PRIMARY.model,"findings":["review_ssh_jail"],
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

        let rental = Server {
            kind: super::super::Kind::Vps,
            id: 42,
        };
        let receipt: Receipt = serde_json::from_value(example()).expect("valid receipt");
        for language in [Lang::En, Lang::Ja, Lang::Ru, Lang::Zh] {
            crate::cli::i18n::speaking(language, || {
                let quote = quote_prompt(Terms::default(), rental);
                let external = quote_prompt(EXTERNAL, rental);
                let fallback = quote_prompt(WITH_FALLBACK, rental);
                assert!(!quote.contains("vps:42"));
                assert!(external.contains("vps:42"), "{external}");
                assert!(external.contains("90"), "{external}");
                assert!(external.contains("28160"), "{external}");
                assert!(!external.contains(Price::FALLBACK.model), "{external}");
                assert!(fallback.contains(Price::FALLBACK.model), "{fallback}");
                for expected in ["28160", "9472"] {
                    assert!(fallback.contains(expected), "{fallback}");
                }
                let summary = receipt.summary();
                assert!(summary.contains(Price::PRIMARY.model), "{summary}");
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
                    external,
                    fallback,
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
    fn customer_consent_discloses_provider_identifiers_and_audit_retention() {
        use erpc_core::i18n::Lang;

        let rental = Server {
            kind: super::super::Kind::Vps,
            id: 42,
        };
        for (language, profile, actor, provider, audit) in [
            (
                Lang::En,
                "Anthropic customer profile ID",
                "stable pseudonymous actor ID",
                "Anthropic's standard retention",
                "ERPC separately keeps",
            ),
            (
                Lang::Ja,
                "Anthropic の顧客プロファイル ID",
                "実行をまたいで同じユーザーを識別する固定の仮名 ID",
                "Anthropic の標準保持方針",
                "ERPC は別途",
            ),
            (
                Lang::Ru,
                "идентификатор профиля клиента Anthropic",
                "устойчивый псевдонимизированный идентификатор пользователя",
                "стандартные условия хранения Anthropic",
                "ERPC отдельно хранит",
            ),
            (
                Lang::Zh,
                "Anthropic 客户档案 ID",
                "固定的操作者假名 ID",
                "Anthropic 的标准保留政策",
                "ERPC 会另外",
            ),
        ] {
            crate::cli::i18n::speaking(language, || {
                let internal = quote_prompt(Terms::default(), rental);
                for terms in [EXTERNAL, WITH_FALLBACK] {
                    let prompt = quote_prompt(terms, rental);
                    for label in [profile, actor, provider, audit] {
                        assert!(prompt.contains(label), "{prompt}");
                        assert!(!internal.contains(label), "{internal}");
                    }
                    assert!(prompt.contains("90"), "{prompt}");
                }
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
        let ok = |v: Value| {
            serde_json::from_value::<Receipt>(v).is_ok_and(|r| r.valid(Terms::default()))
        };
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
        assert_eq!(Price::PRIMARY.maximum(), 28160);
        assert_eq!(Price::FALLBACK.maximum(), 9472);
    }

    #[test]
    fn quote_requires_the_exact_price_and_approved_consent_version() {
        let internal = r#"{"model":"claude-mythos-5-2","meterVersion":"posture1","currency":"ai_credits","baseCredits":512,"weights":{"input":3,"output":12},"limits":{"input":8192,"output":256},"maximumCredits":28160}"#;
        let fallback = r#"{"model":"claude-sonnet-5-5","meterVersion":"posture1","currency":"ai_credits","baseCredits":512,"weights":{"input":1,"output":3},"limits":{"input":8192,"output":256},"maximumCredits":9472}"#;
        let consent = r#""consentVersion":"security-check-local-posture-v1""#;
        let with = |fields: &str| format!("{},{fields}}}", internal.trim_end_matches('}'));
        assert_eq!(parse_quote(internal), Some(Terms::default()));
        assert_eq!(parse_quote(&with(consent)), Some(EXTERNAL));
        assert_eq!(
            parse_quote(&with(&format!(r#"{consent},"fallback":{fallback}"#))),
            Some(WITH_FALLBACK)
        );
        for invalid in [
            with(r#""consentVersion":"security-check-local-posture-v2""#),
            with(r#""consentVersion":null"#),
            with(
                r#""consentVersion":"security-check-local-posture-v1","consentVersion":"security-check-local-posture-v1""#,
            ),
            with(r#""maximumCredits":28160"#),
            with(r#""extra":false"#),
            with(&format!(r#""fallback":{fallback}"#)),
            with(&format!(r#"{consent},"fallback":null"#)),
            with(&format!(
                r#"{consent},"fallback":{}"#,
                fallback.replace("9472", "9473")
            )),
            with(&format!(
                r#"{consent},"fallback":{{{},{consent}}}"#,
                fallback.trim_matches(['{', '}'])
            )),
            internal.replace("28160", "28161"),
            internal.replace(r#"{"input":3,"output":12}"#, "[3,12]"),
            internal.replace(r#""output":12"#, r#""output":12,"output":12"#),
            format!("{internal}{}", " ".repeat(4096)),
        ] {
            assert_eq!(parse_quote(&invalid), None, "{invalid}");
        }
    }

    #[test]
    fn approved_report_preserves_idempotency_and_only_sends_approved_consent_and_fallback() {
        let mut approval = ReportSubmission {
            idempotency_key: "request-id".to_owned(),
            body: Vec::new(),
            terms: Terms::default(),
        };
        assert_eq!(approval.headers(), [("idempotency-key", "request-id")]);
        approval.terms = EXTERNAL;
        assert_eq!(
            approval.headers(),
            [
                ("idempotency-key", "request-id"),
                (
                    "x-erpc-security-check-consent",
                    "security-check-local-posture-v1"
                ),
            ]
        );
        approval.terms = WITH_FALLBACK;
        assert_eq!(
            approval.headers(),
            [
                ("idempotency-key", "request-id"),
                (
                    "x-erpc-security-check-consent",
                    "security-check-local-posture-v1"
                ),
                ("x-erpc-security-check-fallback", "claude-sonnet-5-5"),
            ]
        );
    }

    #[test]
    fn reconciles_fallback_only_after_approval_and_at_the_actual_model_rate() {
        let mut response = example();
        response["model"] = json!("claude-sonnet-5-5");
        let incorrect: Receipt = serde_json::from_value(response.clone()).expect("receipt");
        assert!(!incorrect.valid(WITH_FALLBACK));
        response["billing"]["chargedCredits"] = json!(1090);
        let fallback: Receipt = serde_json::from_value(response).expect("receipt");
        assert!(!fallback.valid(Terms::default()));
        assert!(!fallback.valid(EXTERNAL));
        assert!(fallback.valid(WITH_FALLBACK));
        let summary = fallback.summary();
        assert!(summary.contains("claude-sonnet-5-5"), "{summary}");
        assert!(summary.contains("1090"), "{summary}");
        let primary: Receipt = serde_json::from_value(example()).expect("receipt");
        assert!(primary.valid(WITH_FALLBACK));
    }
}
