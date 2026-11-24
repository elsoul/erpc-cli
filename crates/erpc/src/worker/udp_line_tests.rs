// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! What erpc asks user-api about a UDP Forwarding line, and what it does
//! with each answer, against a loopback stub ([`super::stub`]): the list
//! read before a start, the first sight of a line after one, and the wait
//! that points it at the server.

use std::cell::RefCell;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use erpc_worker::manifest::{LineKind, Start};
use serde_json::{Value, json};

use super::stub::{Request, Stub};
use super::{LineTarget, Pace, UDP_FAMILIES};
use crate::node_common::Say;

const STANDARD_MY: &str = "/v3/udp-forwarding/my";
const PREMIUM_MY: &str = "/v3/udp-forwarding-premium/my";
const STANDARD_DESTINATION: &str = "/v3/udp-forwarding/destination";
const PREMIUM_DESTINATION: &str = "/v3/udp-forwarding-premium/destination";
const CATALOG: &str = "/v3/billing/hourly-catalog";

const QUIET: Say = Say { quiet: true };

/// A line's record kept in memory, as erpc.toml keeps one: the start's
/// request on it, and the lines user-api named.
#[derive(Default)]
struct Kept {
    start: Option<Start>,
    named: Vec<String>,
}

impl super::StartRecord for Kept {
    fn pending(&self) -> Option<Start> {
        self.start.clone()
    }

    fn begin(&mut self, start: &Start) -> Result<(), String> {
        self.start = Some(start.clone());
        Ok(())
    }

    fn settle(&mut self) -> Result<(), String> {
        self.start = None;
        Ok(())
    }

    fn stays_hint(&self, _: super::Stays) -> String {
        "run the same command again".to_owned()
    }
}

impl super::LineRecord for Kept {
    fn named(&mut self, id: &str) -> Result<(), crate::cli::error::CliError> {
        self.start = None;
        self.named.push(id.to_owned());
        Ok(())
    }
}

fn target() -> LineTarget {
    LineTarget {
        ip: Ipv4Addr::new(203, 0, 113, 10),
        udp_port: Some(10001),
        region: Some("tokyo".to_owned()),
    }
}

/// A wait short enough for a test: 40 looks, 5 ms apart, and 20 ms for an
/// active line to name its addresses.
const QUICK: Pace = Pace {
    wait: Duration::from_millis(200),
    poll: Duration::from_millis(5),
    grace: Duration::from_millis(20),
};

fn list(rows: &[Value]) -> (u16, Value) {
    (
        200,
        json!({ "success": true, "totalCount": rows.len(), "data": rows }),
    )
}

fn catalog() -> (u16, Value) {
    (
        200,
        json!({ "families": [
            { "family": "udp-forwarding",
              "plans": [{ "productId": "prod_standard", "hourlyCents": 69.0 }] },
            { "family": "udp-forwarding-premium",
              "plans": [{ "productId": "prod_premium", "hourlyCents": 139.0 }] },
        ] }),
    )
}

/// user-api's answer for a route it does not open to the CLI's sign-in.
fn closed() -> (u16, Value) {
    (
        403,
        json!({
            "success": false,
            "message": "this route is not open to erpc-cli",
            "code": "ROUTE_NOT_ALLOWED",
        }),
    )
}

/// What was told while waiting, in order.
fn telling() -> (Arc<Mutex<Vec<String>>>, impl Fn(String)) {
    let told = Arc::new(Mutex::new(Vec::new()));
    let kept = told.clone();
    (told, move |text| kept.lock().expect("told").push(text))
}

/// A stub that keeps one Standard line as user-api would: pointing it sets
/// its region and destination, and each read of its list after that moves
/// it one step along `then` (the statuses it goes through), giving it
/// `source` once it is active.
async fn standard_line(then: &'static [&'static str], source: Value) -> Stub {
    let mut row = json!({
        "id": 7, "productKey": "one_hop_direct", "billingCycle": "hourly",
        "status": "provisioning", "region": null, "destination": null, "sourceIp": null,
    });
    let mut reads_since_pointed = 0;
    Stub::serve(move |request: &Request| match request.path.as_str() {
        STANDARD_MY => {
            if !row["destination"].is_null() {
                let step = then[reads_since_pointed.min(then.len() - 1)];
                reads_since_pointed += 1;
                row["status"] = json!(step);
                if step == "active" {
                    row["sourceIp"] = source.clone();
                }
            }
            list(std::slice::from_ref(&row))
        }
        PREMIUM_MY => list(&[]),
        STANDARD_DESTINATION if request.method == "PUT" => {
            row["region"] = request.body["region"].clone();
            row["destination"] = request.body["destination"].clone();
            row["status"] = json!("applying");
            (200, json!({ "success": true, "subscription": row }))
        }
        _ => (404, json!({ "message": "no such route" })),
    })
    .await
}

fn puts(stub: &Stub) -> Vec<Request> {
    stub.seen()
        .into_iter()
        .filter(|r| r.method == "PUT")
        .collect()
}

#[tokio::test]
async fn a_start_whose_list_user_api_refuses_starts_nothing_and_says_so_in_its_words() {
    // Production today: the CLI's sign-in may start a Standard line and may
    // not read its list. The list is read first, so the refusal comes
    // before anything is charged.
    let stub = Stub::serve(|request: &Request| match request.path.as_str() {
        CATALOG => catalog(),
        STANDARD_MY | PREMIUM_MY => closed(),
        _ => (404, json!({})),
    })
    .await;
    let mut kept = Kept::default();
    let refused = super::start_line(
        &stub.api(),
        LineKind::Udp,
        &target(),
        None,
        " --env staging",
        &QUIET,
        &mut kept,
    )
    .await
    .expect_err("refused before the start");
    assert!(
        refused
            .message
            .contains("this route is not open to erpc-cli (ROUTE_NOT_ALLOWED)"),
        "{}",
        refused.message
    );
    // Reached after the server was bought: it says no UDP line was
    // started, and nothing of what else is charged.
    assert!(
        refused
            .message
            .contains("no UDP Forwarding line was started"),
        "{}",
        refused.message
    );
    // Signing in again would change nothing, and is not suggested.
    let shown = format!(
        "{} {}",
        refused.message,
        refused.shown_hint().unwrap_or_default()
    );
    assert!(!shown.contains("erpc login"), "{shown}");
    // Nothing was started, and nothing went on record.
    assert!(kept.named.is_empty() && kept.start.is_none());
    assert_eq!(
        stub.asked(),
        [format!("GET {CATALOG}"), format!("GET {STANDARD_MY}")]
    );
}

#[tokio::test]
async fn a_start_with_its_list_readable_goes_on_to_ask_the_person() {
    // The list answers: the start itself is next, and it is the person's
    // to confirm. A stubbed session has no one to ask, so it stops there,
    // having sent nothing that starts a line.
    let stub = Stub::serve(|request: &Request| match request.path.as_str() {
        CATALOG => catalog(),
        STANDARD_MY => list(&[]),
        _ => (404, json!({})),
    })
    .await;
    let mut kept = Kept::default();
    let stopped = super::start_line(
        &stub.api(),
        LineKind::Udp,
        &target(),
        None,
        "",
        &QUIET,
        &mut kept,
    )
    .await
    .expect_err("no one to ask");
    assert!(
        stopped
            .message
            .contains("nobody is at a terminal to say yes"),
        "{}",
        stopped.message
    );
    // Nothing went on record: the request is put there only as it leaves.
    assert!(kept.start.is_none() && kept.named.is_empty());
    assert!(stub.asked().contains(&format!("GET {STANDARD_MY}")));
    assert!(stub.seen().iter().all(|r| r.method == "GET"));
}

#[tokio::test]
async fn a_line_just_started_is_seen_in_the_list_of_its_product() {
    let stub = Stub::serve(|request: &Request| match request.path.as_str() {
        STANDARD_MY => list(&[json!({ "id": 6, "productKey": "one_hop_direct" })]),
        PREMIUM_MY => list(&[json!({ "id": 8, "productKey": "udp_forwarding_premium" })]),
        _ => (404, json!({})),
    })
    .await;
    let line = super::first_sight(&stub.api(), LineKind::Udp, "8", true, "")
        .await
        .expect("listed");
    // Pending: on record, pointed nowhere yet, opening nothing.
    assert!(line.is_pending() && line.hourly && line.sources.is_empty());
    assert_eq!((line.kind, line.id.as_str()), (LineKind::Udp, "8"));
    // Standard's list first, then Premium's.
    assert_eq!(
        stub.asked(),
        [format!("GET {STANDARD_MY}"), format!("GET {PREMIUM_MY}")]
    );
}

#[tokio::test]
async fn a_line_no_list_shows_is_looked_for_again_and_then_given_up_on() {
    let stub = Stub::serve(|_: &Request| list(&[])).await;
    let patience = (3, Duration::from_millis(1));
    let gone = super::first_sight_within(
        &stub.api(),
        LineKind::Udp,
        "7",
        true,
        " --env staging",
        patience,
    )
    .await
    .expect_err("never listed");
    assert!(gone.message.contains("line 7"), "{}", gone.message);
    // It is on record and charged: the hint says how to carry on or end it.
    let hint = gone.hint.unwrap_or_default();
    assert!(
        hint.contains("`erpc worker delete --release-server --env staging`"),
        "{hint}"
    );
    // Both lists, three times.
    assert_eq!(stub.asked().len(), 6);
}

#[tokio::test]
async fn a_list_refused_after_a_start_is_user_apis_refusal_not_a_refused_session() {
    let stub = Stub::serve(|_: &Request| closed()).await;
    let refused = super::first_sight(&stub.api(), LineKind::Udp, "7", true, "")
        .await
        .expect_err("refused");
    assert!(
        refused.message.contains("UDP Forwarding Standard")
            && refused.message.contains("ROUTE_NOT_ALLOWED"),
        "{}",
        refused.message
    );
    assert!(
        !format!(
            "{} {}",
            refused.message,
            refused.shown_hint().unwrap_or_default()
        )
        .contains("erpc login")
    );
    // Asked once: a refusal is not waited out.
    assert_eq!(stub.asked(), [format!("GET {STANDARD_MY}")]);
}

#[tokio::test]
async fn a_line_is_pointed_at_the_server_once_and_taken_with_its_sources_when_active() {
    let stub = standard_line(&["applying", "active"], json!("198.51.100.20")).await;
    let (told, tell) = telling();
    let line = super::wait_udp_line(&stub.api(), "7", &target(), true, QUICK, &tell)
        .await
        .expect("active");
    assert_eq!(line.endpoint, "0.0.0.0:10001");
    assert_eq!(line.sources, [Ipv4Addr::new(198, 51, 100, 20)]);
    assert!(line.hourly && !line.is_pending());
    // Pointed once, at the server's address and port, from its region.
    let puts = puts(&stub);
    assert_eq!(puts.len(), 1, "{puts:?}");
    assert_eq!(puts[0].path, STANDARD_DESTINATION);
    assert_eq!(
        puts[0].body,
        json!({ "subscriptionId": 7, "region": "tokyo", "destination": "203.0.113.10:10001" })
    );
    let told = told.lock().expect("told").join("\n");
    assert!(
        told.contains("line 7 is being pointed at 203.0.113.10:10001 from tokyo"),
        "{told}"
    );
}

#[tokio::test]
async fn a_line_that_stays_pending_is_given_up_on_and_says_why_it_waited() {
    // A Standard line with no free node in its region: it keeps its
    // destination and never becomes active.
    let mut pointed = false;
    let stub = Stub::serve(move |request: &Request| match request.path.as_str() {
        STANDARD_MY => {
            let mut row = json!({
                "id": 7, "productKey": "one_hop_direct", "status": "provisioning",
                "region": null, "destination": null, "sourceIp": null,
            });
            if pointed {
                row["region"] = json!("tokyo");
                row["destination"] = json!("203.0.113.10:10001");
                row["lastAllocationOutcome"] = json!("region_unavailable");
                row["lastError"] =
                    json!("no eligible node with a free slot in the selected region");
            }
            list(&[row])
        }
        PREMIUM_MY => list(&[]),
        STANDARD_DESTINATION => {
            pointed = true;
            (200, json!({ "success": true }))
        }
        _ => (404, json!({})),
    })
    .await;
    let (told, tell) = telling();
    // Long enough for several looks where a timer is coarse (about 16 ms
    // on Windows).
    let pace = Pace {
        wait: Duration::from_millis(300),
        ..QUICK
    };
    let waited = super::wait_udp_line(&stub.api(), "7", &target(), true, pace, &tell)
        .await
        .expect_err("never active");
    assert!(
        waited.message.contains("did not become active") && waited.message.contains("provisioning"),
        "{}",
        waited.message
    );
    // Pointed once however long it waited, and the reason said once.
    assert_eq!(puts(&stub).len(), 1);
    let told = told.lock().expect("told").clone();
    let capacity: Vec<&String> = told
        .iter()
        .filter(|t| t.contains("waiting for capacity"))
        .collect();
    assert_eq!(capacity.len(), 1, "{told:?}");
    assert!(
        stub.asked().len() > 4,
        "it kept looking: {:?}",
        stub.asked()
    );
}

#[tokio::test]
async fn an_active_line_that_names_no_source_is_taken_with_none_after_the_grace() {
    let stub = standard_line(&["active"], Value::Null).await;
    let (_, tell) = telling();
    let started = std::time::Instant::now();
    let line = super::wait_udp_line(&stub.api(), "7", &target(), true, QUICK, &tell)
        .await
        .expect("active");
    // With its port, and no address: what the port is opened to is then
    // the deploy's to decide (closed, unless --udp-any-source).
    assert_eq!(line.endpoint, "0.0.0.0:10001");
    assert!(line.sources.is_empty());
    assert!(started.elapsed() >= QUICK.grace);
}

#[tokio::test]
async fn an_active_line_whose_source_is_not_ipv4_is_an_error_that_names_it() {
    let stub = standard_line(&["active"], json!("2001:db8::20")).await;
    let (_, tell) = telling();
    let refused = super::wait_udp_line(&stub.api(), "7", &target(), true, QUICK, &tell)
        .await
        .expect_err("not an IPv4 address");
    assert!(
        refused.message.contains("`2001:db8::20`") && refused.message.contains("line 7"),
        "{}",
        refused.message
    );
}

#[tokio::test]
async fn a_premium_line_is_pointed_by_its_own_route_and_sends_from_every_source() {
    let mut row = json!({
        "id": 8, "productKey": "udp_forwarding_premium", "status": "provisioning",
        "region": null, "destination": null, "sourceIps": [],
    });
    // The first change is refused while user-api applies an earlier one.
    let mut refusals = 1;
    let stub = Stub::serve(move |request: &Request| match request.path.as_str() {
        STANDARD_MY => list(&[]),
        PREMIUM_MY => {
            if !row["destination"].is_null() {
                row["status"] = json!("active");
                row["sourceIps"] = json!(["198.51.100.21", "198.51.100.20"]);
            }
            list(std::slice::from_ref(&row))
        }
        PREMIUM_DESTINATION if refusals > 0 => {
            refusals -= 1;
            (
                409,
                json!({ "message": "a change is being applied",
                        "code": "UDP_FORWARDING_PREMIUM_APPLY_IN_PROGRESS" }),
            )
        }
        PREMIUM_DESTINATION => {
            row["region"] = request.body["region"].clone();
            row["destination"] = request.body["destination"].clone();
            (200, json!({ "success": true }))
        }
        _ => (404, json!({})),
    })
    .await;
    let (_, tell) = telling();
    let line = super::wait_udp_line(&stub.api(), "8", &target(), true, QUICK, &tell)
        .await
        .expect("active");
    assert_eq!(
        line.sources,
        [
            Ipv4Addr::new(198, 51, 100, 20),
            Ipv4Addr::new(198, 51, 100, 21)
        ]
    );
    // Refused once, tried again the next round, and not a third time.
    let puts = puts(&stub);
    assert_eq!(puts.len(), 2, "{puts:?}");
    assert!(puts.iter().all(|p| p.path == PREMIUM_DESTINATION));
}

#[tokio::test]
async fn a_pointing_user_api_refuses_stops_the_wait_with_its_reason() {
    let stub = Stub::serve(|request: &Request| match request.path.as_str() {
        STANDARD_MY => list(&[json!({
            "id": 7, "productKey": "one_hop_direct", "status": "provisioning",
            "region": null, "destination": null,
        })]),
        STANDARD_DESTINATION => closed(),
        _ => list(&[]),
    })
    .await;
    let (_, tell) = telling();
    let refused = super::wait_udp_line(&stub.api(), "7", &target(), true, QUICK, &tell)
        .await
        .expect_err("refused");
    assert!(
        refused.message.contains("could not point")
            && refused.message.contains("ROUTE_NOT_ALLOWED"),
        "{}",
        refused.message
    );
    assert!(
        !refused.message.contains("erpc login"),
        "{}",
        refused.message
    );
    assert_eq!(puts(&stub).len(), 1);
    // A route closed to the sign-in comes back the same.
    let hint = refused.hint.unwrap_or_default();
    assert!(hint.contains("comes back the same"), "{hint}");
    // A region's may pass later: deploying again.
    let stub = Stub::serve(|request: &Request| match request.path.as_str() {
        STANDARD_MY => list(&[json!({
            "id": 7, "productKey": "one_hop_direct", "status": "provisioning",
            "region": null, "destination": null,
        })]),
        STANDARD_DESTINATION => (
            503,
            json!({ "success": false, "code": "UDP_FORWARDING_REGION_UNAVAILABLE",
                    "message": "the region is not taking lines now" }),
        ),
        _ => list(&[]),
    })
    .await;
    let refused = super::wait_udp_line(&stub.api(), "7", &target(), true, QUICK, &tell)
        .await
        .expect_err("refused");
    let hint = refused.hint.unwrap_or_default();
    assert!(
        hint.starts_with("deploy again"),
        "{}\n{hint}",
        refused.message
    );
    // The destination's: trying again does not change it.
    let stub = Stub::serve(|request: &Request| match request.path.as_str() {
        STANDARD_MY => list(&[json!({
            "id": 7, "productKey": "one_hop_direct", "status": "provisioning",
            "region": null, "destination": null,
        })]),
        STANDARD_DESTINATION => (
            400,
            json!({ "success": false, "code": "INVALID_DESTINATION",
                    "message": "destination is not allowed" }),
        ),
        _ => list(&[]),
    })
    .await;
    let refused = super::wait_udp_line(&stub.api(), "7", &target(), true, QUICK, &tell)
        .await
        .expect_err("refused");
    let hint = refused.hint.unwrap_or_default();
    assert!(
        hint.contains("comes back the same") && !hint.contains("deploy again"),
        "{}\n{hint}",
        refused.message
    );
}

#[tokio::test]
async fn the_sources_a_line_sends_from_now_are_read_from_its_list() {
    let stub = Stub::serve(|request: &Request| match request.path.as_str() {
        STANDARD_MY => list(&[json!({ "id": 7, "sourceIp": "198.51.100.30" })]),
        _ => list(&[]),
    })
    .await;
    let api = stub.api();
    assert_eq!(
        super::udp_sources_now(&api, "7").await.expect("read"),
        Some(vec![Ipv4Addr::new(198, 51, 100, 30)])
    );
    // A line neither list has is not "a line with no sources".
    assert_eq!(super::udp_sources_now(&api, "9").await.expect("read"), None);
}

/// A person who answers a confirmation as told, and keeps what was asked.
struct Person {
    yes: bool,
    asked: RefCell<Vec<String>>,
}

impl erpc_ai::confirm::Confirm for Person {
    fn confirm<'a>(
        &'a self,
        ask: &'a erpc_ai::confirm::Confirmation,
    ) -> std::pin::Pin<Box<dyn Future<Output = bool> + 'a>> {
        self.asked.borrow_mut().push(ask.text());
        Box::pin(async move { self.yes })
    }
}

#[tokio::test]
async fn an_unpointed_standard_line_is_taken_up_only_on_the_persons_yes() {
    use super::{Answerer, Unpointed};
    let standard = &UDP_FAMILIES[0];
    let to = ("203.0.113.10:10001", "tokyo");
    let person = |yes| Person {
        yes,
        asked: RefCell::new(Vec::new()),
    };
    let yes = person(true);
    assert!(super::take_up_unpointed(&yes, standard, "42", to).await);
    let asked = yes.asked.borrow().join("\n");
    assert!(
        asked.contains("line 42") && asked.contains("203.0.113.10:10001 from tokyo"),
        "{asked}"
    );
    // No: nothing is taken up, and the start is asked next.
    let no = person(false);
    assert!(!super::take_up_unpointed(&no, standard, "42", to).await);
    assert_eq!(no.asked.borrow().len(), 1);
    // Who answers decides whether it is asked at all: the person is;
    // --yes refuses, since whose line it is is no price to accept; with
    // nobody the start that follows refuses.
    assert_eq!(Unpointed::by(Some(Answerer::Person)), Unpointed::Ask);
    assert_eq!(Unpointed::by(Some(Answerer::Yes)), Unpointed::Refuse);
    assert_eq!(Unpointed::by(None), Unpointed::Pass);
}

/// The account's Standard list with line 42 in it, charged by the hour
/// and pointed nowhere: what a deploy that stopped before pointing it, or
/// a start from the dashboard, leaves.
async fn with_an_unpointed_line() -> Stub {
    Stub::serve(|request: &Request| match request.path.as_str() {
        CATALOG => catalog(),
        STANDARD_MY => list(&[json!({
            "id": 42, "billingCycle": "hourly", "status": "provisioning", "destination": null,
        })]),
        PREMIUM_MY => list(&[]),
        _ => (404, json!({})),
    })
    .await
}

fn bought(start: super::UdpStart) -> (&'static str, String) {
    match start {
        super::UdpStart::Buy(family, product) => (family.family, product),
        super::UdpStart::TakenUp(id) => panic!("took up {id}"),
    }
}

#[tokio::test]
async fn under_yes_an_unpointed_line_is_named_and_neither_taken_up_nor_bought_beside() {
    let stub = with_an_unpointed_line().await;
    let mut kept = Kept::default();
    let api = stub.api().accepting(true);
    let refused = super::udp_start(&api, &target(), None, &mut kept, &QUIET)
        .await
        .err()
        .expect("refused");
    assert!(
        refused.message.contains("UDP Forwarding Standard line 42")
            && refused.message.contains("--yes does not decide"),
        "{}",
        refused.message
    );
    assert!(
        refused
            .hint
            .as_deref()
            .is_some_and(|h| h.contains("at a terminal") && h.contains("line 42")),
        "{:?}",
        refused.hint
    );
    assert!(kept.named.is_empty() && kept.start.is_none());
}

#[tokio::test]
async fn a_start_on_record_is_sent_again_and_no_unpointed_line_is_offered_for_it() {
    let stub = with_an_unpointed_line().await;
    // A start an earlier deploy sent and got no answer to: the line it may
    // have made is listed unpointed too. Even under --yes nothing is
    // refused or taken up: the start is sent again with its key.
    let mut kept = Kept {
        start: Some(Start {
            key: "0a".repeat(16),
            family: "udp-forwarding".to_owned(),
            product: "prod_standard".to_owned(),
            region: None,
            ip: None,
        }),
        named: Vec::new(),
    };
    let api = stub.api().accepting(true);
    let start = super::udp_start(&api, &target(), None, &mut kept, &QUIET)
        .await
        .expect("goes on to the start");
    assert_eq!(
        bought(start),
        ("udp-forwarding", "prod_standard".to_owned())
    );
    assert!(kept.named.is_empty() && kept.start.is_some());
}

#[tokio::test]
async fn with_nobody_to_answer_the_unpointed_line_is_left_to_the_start_to_refuse() {
    let stub = with_an_unpointed_line().await;
    let mut kept = Kept::default();
    let start = super::udp_start(&stub.api(), &target(), None, &mut kept, &QUIET)
        .await
        .expect("nothing is asked yet");
    // The plan asked for names the product, whatever the line listed.
    assert_eq!(
        bought(start),
        ("udp-forwarding", "prod_standard".to_owned())
    );
    assert!(kept.named.is_empty());
    let premium = super::udp_start(
        &stub.api(),
        &target(),
        Some("prod_premium"),
        &mut kept,
        &QUIET,
    )
    .await
    .expect("Premium");
    assert_eq!(
        bought(premium),
        ("udp-forwarding-premium", "prod_premium".to_owned())
    );
}

/// What `deploy --udp` checks before it buys anything.
fn before() -> super::UdpCheck<'static> {
    super::UdpCheck {
        nothing_bought: true,
        ..super::UdpCheck::default()
    }
}

/// `deploy --udp` asks what the start would be refused for before the
/// server and the other lines are bought: a list user-api refuses, and,
/// under --yes, a line pointed nowhere. A start on record is sent again,
/// and is not stopped for such a line; at a terminal the person is asked
/// later, when the line is started.
#[tokio::test]
async fn what_a_udp_start_would_be_refused_for_is_asked_before_anything_is_bought() {
    let refused = Stub::serve(|request: &Request| match request.path.as_str() {
        CATALOG => catalog(),
        STANDARD_MY | PREMIUM_MY => closed(),
        _ => (404, json!({})),
    })
    .await;
    let e = super::udp_ready(&refused.api().accepting(true), &before())
        .await
        .expect_err("refused");
    assert!(
        e.message.contains("this deploy started nothing"),
        "{}",
        e.message
    );
    // Under --yes, an unpointed Standard line stops it before anything.
    let unpointed = with_an_unpointed_line().await;
    let e = super::udp_ready(&unpointed.api().accepting(true), &before())
        .await
        .expect_err("named");
    assert!(e.message.contains("line 42"), "{}", e.message);
    // Not with a start on record, nor with nobody to answer, nor for
    // Premium, which is charged only once it is pointed.
    let api = unpointed.api().accepting(true);
    assert!(
        super::udp_ready(
            &api,
            &super::UdpCheck {
                pending: true,
                ..before()
            }
        )
        .await
        .is_ok()
    );
    // Nor for the environment's own line on record, which it takes up.
    assert!(
        super::udp_ready(
            &api,
            &super::UdpCheck {
                on_record: Some("42"),
                ..before()
            }
        )
        .await
        .is_ok()
    );
    assert!(super::udp_ready(&unpointed.api(), &before()).await.is_ok());
    assert!(
        super::udp_ready(
            &api,
            &super::UdpCheck {
                plan: Some("prod_premium"),
                ..before()
            }
        )
        .await
        .is_ok()
    );
    // A plan the catalogue does not offer is refused here too.
    let unknown = super::UdpCheck {
        plan: Some("prod_x"),
        ..before()
    };
    assert!(super::udp_ready(&api, &unknown).await.is_err());
    // A region the product does not send from (sydney is a VPS region, and
    // neither product's): refused before anything is bought, saying which.
    let sydney = super::UdpCheck {
        region: Some("sydney"),
        ..before()
    };
    let e = super::udp_ready(&api, &sydney).await.expect_err("sydney");
    assert!(e.message.contains("sydney"), "{}", e.message);
    // Dublin is Premium's: its plan is named.
    let dublin = super::UdpCheck {
        region: Some("dublin"),
        ..before()
    };
    let e = super::udp_ready(&api, &dublin).await.expect_err("dublin");
    assert!(
        e.hint
            .as_deref()
            .is_some_and(|h| h.contains("prod_premium")),
        "{:?}",
        e.hint
    );
    // Only reads: nothing was sent that starts or points a line.
    for stub in [&refused, &unpointed] {
        assert!(stub.seen().iter().all(|r| r.method == "GET"));
    }
}

/// The environment's own line on record, when the account lists it, is
/// taken up: no start is judged, and its region is checked against its
/// own product. A Premium line in dublin is not refused for Standard's
/// regions, nor stopped for another line pointed nowhere.
#[tokio::test]
async fn the_line_on_record_is_judged_by_its_own_product_and_starts_nothing() {
    let stub = Stub::serve(|request: &Request| match request.path.as_str() {
        CATALOG => catalog(),
        STANDARD_MY => list(&[json!({
            "id": 42, "billingCycle": "hourly", "status": "provisioning", "destination": null,
        })]),
        PREMIUM_MY => list(&[json!({
            "id": 8, "productKey": "udp_forwarding_premium", "status": "active",
            "destination": "203.0.113.10:10001", "region": "dublin",
        })]),
        _ => (404, json!({})),
    })
    .await;
    let api = stub.api().accepting(true);
    let own = |region| super::UdpCheck {
        on_record: Some("8"),
        region,
        ..before()
    };
    assert!(super::udp_ready(&api, &own(Some("dublin"))).await.is_ok());
    let e = super::udp_ready(&api, &own(Some("sydney")))
        .await
        .expect_err("sydney");
    assert!(
        e.message.contains("UDP Forwarding Premium") && e.message.contains("sydney"),
        "{}",
        e.message
    );
    // A plan of the other product is refused: the line keeps its own.
    let standard = super::UdpCheck {
        plan: Some("prod_standard"),
        scope: " --env staging",
        ..own(Some("dublin"))
    };
    let e = super::udp_ready(&api, &standard)
        .await
        .expect_err("other product");
    assert!(
        e.message.contains("line 8") && e.message.contains("UDP Forwarding Standard"),
        "{}",
        e.message
    );
    assert!(
        e.hint
            .as_deref()
            .is_some_and(|h| h.contains("`erpc worker deploy --env staging --udp`")
                && h.contains("`erpc worker deploy --env staging --forget-line 8 --udp")),
        "{:?}",
        e.hint
    );
    let premium = super::UdpCheck {
        plan: Some("prod_premium"),
        ..own(Some("dublin"))
    };
    assert!(super::udp_ready(&api, &premium).await.is_ok());
    // A plan the catalogue does not offer is refused all the same.
    let unknown = super::UdpCheck {
        plan: Some("prod_x"),
        ..own(Some("dublin"))
    };
    assert!(super::udp_ready(&api, &unknown).await.is_err());
    // A VPS about to be bought in a region the plan does not send from.
    assert!(super::udp_region_ready(&api, None, "sydney").await.is_err());
    assert!(
        super::udp_region_ready(&api, None, "frankfurt")
            .await
            .is_ok()
    );
    assert!(
        super::udp_region_ready(&api, Some("prod_premium"), "dublin")
            .await
            .is_ok()
    );
    assert!(stub.seen().iter().all(|r| r.method == "GET"));
}

/// The environment's own line, when it ended or was suspended, sends
/// nothing: refused before anything is bought, not at the UDP step.
#[tokio::test]
async fn an_own_line_that_ended_or_was_suspended_is_refused_before_anything_is_bought() {
    for (status, said) in [("cancelled", "line 8"), ("suspended", "suspended")] {
        let stub = Stub::serve(move |request: &Request| match request.path.as_str() {
            CATALOG => catalog(),
            STANDARD_MY => list(&[]),
            PREMIUM_MY => list(&[json!({
                "id": 8, "productKey": "udp_forwarding_premium", "status": status,
                "destination": "203.0.113.10:10001", "region": "dublin",
            })]),
            _ => (404, json!({})),
        })
        .await;
        let check = super::UdpCheck {
            on_record: Some("8"),
            region: Some("dublin"),
            ..before()
        };
        let e = super::udp_ready(&stub.api(), &check)
            .await
            .expect_err(status);
        assert!(e.message.contains(said), "{status}: {}", e.message);
    }
}
