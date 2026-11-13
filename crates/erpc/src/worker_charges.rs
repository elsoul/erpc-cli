// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! What an environment costs by the hour, as `erpc worker status` shows it.
//!
//! `erpc.toml` records what was started for an environment: its server and
//! its data lines. What each costs now is the account's to say: the credit
//! snapshot lists what the account is charged for, with the credit left and
//! how long it lasts. The status shows each item on record with its price
//! from that list.
//!
//! An item that is not on the list is said to be not on it, and no more.
//! The snapshot is cached for up to a minute, so something just started is
//! missing from it for a while, and whether a line is gone is decided
//! elsewhere, by a stricter rule ([`crate::worker_vps::is_gone`]). The
//! status ends nothing and takes nothing off the record.

use erpc_api::account;
use erpc_worker::manifest::{Env, ResourceKind};
use serde_json::{Value, json};
use unicode_width::UnicodeWidthStr as _;

use crate::worker_vps::{Api, is_product_of};

/// What the account's list of charges says of one item on record.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Charge {
    /// On the list, at this many cents an hour.
    At(f64),
    /// On the list, with no price given.
    Unpriced,
    /// Not on the list as the snapshot has it now. Not the same as ended:
    /// the list can be a minute behind a start.
    NotListed,
    /// Not looked up: its id on record is not a number, and the list names
    /// products by number.
    NotLookedUp,
}

impl Charge {
    /// Whether the account is charged for it, where the list says.
    const fn charged(self) -> Option<bool> {
        match self {
            Self::At(_) | Self::Unpriced => Some(true),
            Self::NotListed => Some(false),
            Self::NotLookedUp => None,
        }
    }

    const fn cents(self) -> Option<f64> {
        match self {
            Self::At(cents) => Some(cents),
            _ => None,
        }
    }
}

/// One thing on record for the environment that is billed by the hour.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Item {
    /// What it is, as the status names it: `VPS 100001`, `gRPC line 200002`.
    pub(crate) label: String,
    /// Whether it is a data line; the rest is the server.
    pub(crate) line: bool,
    pub(crate) charge: Charge,
}

/// The account's credit, and how fast all it runs spends it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Credit {
    pub(crate) balance_cents: f64,
    /// Cents an hour over everything the account runs; zero when nothing
    /// is charged by the hour, and `None` when the snapshot does not give
    /// a rate (none, not a number, or below zero): then nothing is said of
    /// the rate, least of all that nothing is spent.
    pub(crate) burn_cents: Option<f64>,
    /// Whole hours the credit lasts at that rate; `None` when nothing is
    /// known to be spent by the hour, or when the snapshot does not say.
    pub(crate) hours: Option<u64>,
}

/// What the environment is charged, and the account's credit.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Charges {
    pub(crate) items: Vec<Item>,
    pub(crate) credit: Option<Credit>,
}

/// What the list `rows` says of product `id`, among the rows `is_ours`
/// picks by their product type.
fn charge_of(rows: &[Value], id: &str, is_ours: impl Fn(&str) -> bool) -> Charge {
    let Ok(id) = id.parse::<i64>() else {
        return Charge::NotLookedUp;
    };
    let row = rows.iter().find(|row| {
        row["userProductId"].as_i64() == Some(id)
            && row["productType"].as_str().is_some_and(&is_ours)
    });
    match row {
        None => Charge::NotListed,
        Some(row) => row["hourlyCents"]
            .as_f64()
            .filter(|cents| cents.is_finite() && *cents >= 0.0)
            .map_or(Charge::Unpriced, Charge::At),
    }
}

/// The account's credit as the snapshot's `message` gives it. Hours are
/// said only while something is spent by the hour.
fn credit_of(message: &Value) -> Option<Credit> {
    let balance_cents = message["balance"]["balanceCents"].as_f64()?;
    let burn_cents = message["burnRateCentsPerHour"]
        .as_f64()
        .filter(|burn| burn.is_finite() && *burn >= 0.0);
    let spends = burn_cents.is_some_and(|burn| burn > 0.0);
    let hours = message["timeToZeroHours"]
        .as_f64()
        .filter(|hours| spends && hours.is_finite() && *hours >= 0.0)
        .map(|hours| {
            #[allow(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "checked finite and not negative; whole hours are what is said"
            )]
            let whole = hours.floor() as u64;
            whole
        });
    Some(Credit {
        balance_cents,
        burn_cents,
        hours,
    })
}

/// What `env` has on record that is billed by the hour, each with what the
/// credit `snapshot` says of it.
pub(crate) fn of(env: &Env, snapshot: &Value) -> Charges {
    let message = &snapshot["message"];
    let rows = message["hourlyResources"]
        .as_array()
        .map_or(&[][..], Vec::as_slice);
    let mut items = Vec::new();
    if let Some(server) = env
        .resource
        .as_ref()
        .filter(|r| r.hourly && !r.id.is_empty())
    {
        let product = match server.kind {
            ResourceKind::BareMetal => "bare_metal",
            _ => "vps",
        };
        items.push(Item {
            label: t!(
                "worker_remote.hourly.server",
                kind = server.kind.as_str(),
                id = server.id
            ),
            line: false,
            charge: charge_of(rows, &server.id, |t| t == product),
        });
    }
    for line in env.lines.iter().filter(|l| l.hourly) {
        items.push(Item {
            label: t!(
                "worker_remote.hourly.line",
                kind = line.kind.label(),
                id = line.id
            ),
            line: true,
            charge: charge_of(rows, &line.id, |t| is_product_of(line.kind, t)),
        });
    }
    Charges {
        items,
        credit: credit_of(message),
    }
}

/// [`of`], when `env` has something billed by the hour and `snapshot` has
/// the list of charges. Without the list nothing can be said of an item,
/// and saying "not on the list" of each would be untrue.
pub(crate) fn from_snapshot(env: &Env, snapshot: &Value) -> Option<Charges> {
    let hourly = env
        .resource
        .as_ref()
        .is_some_and(|r| r.hourly && !r.id.is_empty())
        || env.lines.iter().any(|l| l.hourly);
    if !hourly {
        return None;
    }
    snapshot["message"]["hourlyResources"].as_array()?;
    Some(of(env, snapshot))
}

/// An amount of cents in euros: two decimals, more only when a price has
/// them.
pub(crate) fn euros(cents: f64) -> String {
    let text = format!("{:.4}", cents / 100.0);
    let trimmed = text.trim_end_matches('0');
    let decimals = trimmed.len() - trimmed.find('.').map_or(trimmed.len(), |dot| dot + 1);
    if decimals >= 2 {
        trimmed.to_owned()
    } else {
        format!("{:.2}", cents / 100.0)
    }
}

impl Charges {
    /// What the items with a price cost together. Never `-0.0`.
    fn total(&self) -> f64 {
        self.items
            .iter()
            .filter_map(|i| i.charge.cents())
            .fold(0.0, |sum, cents| sum + cents)
    }

    /// The same for a program: each item with whether the account's list
    /// has it (`null` when it was not looked up) and its price or `null`,
    /// the total of the prices, and the account's credit (its rate is
    /// `null` when the snapshot gives none).
    pub(crate) fn json(&self) -> Value {
        json!({
            "items": self.items.iter().map(|i| json!({
                "name": i.label,
                "charged": i.charge.charged(),
                "cents_per_hour": i.charge.cents(),
            })).collect::<Vec<_>>(),
            "cents_per_hour": self.total(),
            "credit": self.credit.map(|c| json!({
                "balance_cents": c.balance_cents,
                "account_cents_per_hour": c.burn_cents,
                "hours_left": c.hours,
            })),
        })
    }

    /// The lines under the status: each item and what the account's list
    /// says of it, the total when more than one has a price, the credit,
    /// how to end what is charged, and what "not on the list" means.
    pub(crate) fn lines(&self, scope: &str) -> Vec<String> {
        let mut out = vec![t!("worker_remote.charges.title")];
        let total = t!("worker_remote.charges.total");
        let width = self
            .items
            .iter()
            .map(|i| i.label.width())
            .chain(std::iter::once(total.width()))
            .max()
            .unwrap_or(0);
        // Padded by what a terminal shows, not by characters: a label in
        // Japanese or Chinese is twice as wide as it is long.
        let row = |label: &str, what: String| {
            let pad = width.saturating_sub(label.width());
            format!("  {label}{}  {what}", " ".repeat(pad))
        };
        let price = |cents: f64| t!("worker_remote.charges.price", price = euros(cents));
        for item in &self.items {
            out.push(row(
                &item.label,
                match item.charge {
                    Charge::At(cents) => price(cents),
                    Charge::Unpriced => t!("worker_remote.charges.unpriced"),
                    Charge::NotListed => t!("worker_remote.charges.not_listed"),
                    Charge::NotLookedUp => t!("worker_remote.charges.not_looked_up"),
                },
            ));
        }
        let priced = self
            .items
            .iter()
            .filter(|i| i.charge.cents().is_some())
            .count();
        if priced > 1 {
            out.push(row(&total, price(self.total())));
        }
        if let Some(credit) = self.credit {
            let balance = euros(credit.balance_cents);
            out.push(match (credit.burn_cents, credit.hours) {
                // No rate in the snapshot: the balance, and no word on
                // what is spent.
                (None, _) => t!("worker_remote.charges.credit_alone", balance),
                (Some(burn), Some(hours)) => {
                    let burn = euros(burn);
                    tn!("worker_remote.charges.credit", hours, balance, burn)
                }
                (Some(burn), None) if burn > 0.0 => {
                    t!(
                        "worker_remote.charges.credit_rate",
                        balance,
                        burn = euros(burn)
                    )
                }
                (Some(_), None) => t!("worker_remote.charges.credit_idle", balance),
            });
        }
        if self.items.iter().any(|i| i.charge.charged() == Some(true)) {
            out.push(t!("worker_remote.charges.end", scope));
        }
        let unlisted = |line: bool| {
            self.items
                .iter()
                .any(|i| i.line == line && i.charge == Charge::NotListed)
        };
        if unlisted(true) || unlisted(false) {
            out.push(t!("worker_remote.charges.behind"));
        }
        if unlisted(true) {
            out.push(t!("worker_remote.charges.forget_line", scope));
        }
        out
    }
}

/// What `env` is charged now, read from the account. `None` when nothing
/// on record is billed by the hour, and when the account cannot be read
/// (not signed in, user-api away, an answer without the list): the status
/// then says what is on record.
pub(crate) async fn read(env: &Env) -> Option<Charges> {
    // Asked before the session is opened: an environment with nothing
    // billed by the hour reads nothing of the account.
    from_snapshot(env, &json!({ "message": { "hourlyResources": [] } }))?;
    let api = Api::open().await.ok()?;
    let snapshot = api.read(account::CREDIT_SNAPSHOT_URL).await.ok()?;
    from_snapshot(env, &snapshot)
}

#[cfg(test)]
mod tests {
    use erpc_worker::manifest::{Env, Manifest};
    use serde_json::{Value, json};
    use unicode_width::UnicodeWidthStr as _;

    use super::{Charge, Credit, euros, from_snapshot, of};

    /// An environment with a server and two lines on record, all billed by
    /// the hour. The ids are made up.
    fn env_with(server_kind: &str, server_id: &str) -> Env {
        let text = format!(
            r#"
            name = "bot"
            chain = "solana"
            [run]
            port = 3000
            [env.prod]
            host = "203.0.113.10"
            lines = [
              {{ kind = "grpc", id = "200002", endpoint = "g", hourly = true }},
              {{ kind = "shreds", id = "300003", endpoint = "s", hourly = true }},
            ]
            [env.prod.resource]
            kind = "{server_kind}"
            id = "{server_id}"
            region = "frankfurt"
            hourly = true
            "#
        );
        let m: Manifest = toml::from_str(&text).expect("manifest");
        m.env["prod"].clone()
    }

    fn env() -> Env {
        env_with("vps", "100001")
    }

    fn snapshot(rows: &Value) -> Value {
        json!({ "message": {
            "balance": { "balanceCents": 1234 },
            "hourlyResources": rows,
            "burnRateCentsPerHour": 48,
            "timeToZeroHours": 25,
        } })
    }

    fn all_three() -> Value {
        json!([
            { "productType": "vps", "userProductId": 100_001, "hourlyCents": 7 },
            { "productType": "grpc", "userProductId": 200_002, "hourlyCents": 34 },
            { "productType": "shreds", "userProductId": 300_003, "hourlyCents": 34 },
        ])
    }

    fn charges_of(charges: &super::Charges) -> Vec<Charge> {
        charges.items.iter().map(|i| i.charge).collect()
    }

    #[test]
    fn each_item_on_record_gets_the_price_the_account_is_charged() {
        let charges = of(&env(), &snapshot(&all_three()));
        assert_eq!(
            charges_of(&charges),
            [Charge::At(7.0), Charge::At(34.0), Charge::At(34.0)]
        );
        assert_eq!(
            charges.credit,
            Some(Credit {
                balance_cents: 1234.0,
                burn_cents: Some(48.0),
                hours: Some(25)
            })
        );
        let text = charges.lines(" --env prod").join("\n");
        assert!(text.contains("VPS 100001"), "{text}");
        assert!(text.contains("€0.07 per hour"), "{text}");
        assert!(text.contains("€0.34 per hour"), "{text}");
        assert!(text.contains("together"), "{text}");
        assert!(
            text.contains("€0.75 per hour"),
            "the three together: {text}"
        );
        assert!(
            text.contains("€12.34") && text.contains("€0.48 per hour") && text.contains("25 hours"),
            "{text}"
        );
        assert!(
            text.contains("delete --release-server --env prod"),
            "{text}"
        );
        // Everything is on the list: nothing is said of the list being
        // behind, or of a line to take off the record.
        assert!(!text.contains("--forget-line"), "{text}");
        assert!(!text.contains("a minute"), "{text}");

        let json = charges.json();
        assert_eq!(json["items"][0]["charged"], json!(true));
        assert_eq!(json["items"][0]["cents_per_hour"], json!(7.0));
        assert_eq!(json["cents_per_hour"], json!(75.0));
        assert_eq!(json["credit"]["hours_left"], json!(25));
    }

    #[test]
    fn an_item_that_is_not_on_the_list_is_said_to_be_not_on_it_and_no_more() {
        // A line that is on record and not in the snapshot: ended somewhere
        // else, or started a moment ago. A product of another kind with
        // the same id is not this line.
        let charges = of(
            &env(),
            &snapshot(&json!([
                { "productType": "vps", "userProductId": 100_001, "hourlyCents": 7 },
                { "productType": "erpc_plan", "userProductId": 200_002, "hourlyCents": 7 },
            ])),
        );
        assert_eq!(
            charges_of(&charges),
            [Charge::At(7.0), Charge::NotListed, Charge::NotListed]
        );
        let text = charges.lines(" --env prod").join("\n");
        assert!(
            text.contains("not among the account's charges now"),
            "{text}"
        );
        // No item is called ended: the list can be a minute behind a
        // start, and the status has not asked what user-api lists.
        let rows = charges.lines(" --env prod");
        assert!(
            rows[1..=3].iter().all(|row| !row.contains("ended")),
            "{rows:#?}"
        );
        assert!(text.contains("a minute"), "{text}");
        // How a line that was ended elsewhere leaves the record, as the
        // guide has it. No such thing is said of a server.
        assert!(
            text.contains("erpc worker deploy --forget-line <ID> --env prod"),
            "{text}"
        );
        // One item has a price: no total of one.
        assert!(!text.contains("together"), "{text}");
        let json = charges.json();
        assert_eq!(json["items"][1]["charged"], json!(false));
        assert_eq!(json["items"][1]["cents_per_hour"], json!(null));
        assert_eq!(json["cents_per_hour"], json!(7.0));

        // The server alone not on the list: the list may be behind, and
        // no line is named to forget.
        let charges = of(
            &env(),
            &snapshot(&json!([
                { "productType": "grpc", "userProductId": 200_002, "hourlyCents": 34 },
                { "productType": "shreds", "userProductId": 300_003, "hourlyCents": 34 },
            ])),
        );
        let text = charges.lines("").join("\n");
        assert!(text.contains("a minute"), "{text}");
        assert!(!text.contains("--forget-line"), "{text}");
    }

    #[test]
    fn a_server_is_looked_up_as_the_product_it_is() {
        // A bare-metal server and a VPS can have the same number.
        let as_vps = json!([{ "productType": "vps", "userProductId": 100_001, "hourlyCents": 7 }]);
        let as_metal =
            json!([{ "productType": "bare_metal", "userProductId": 100_001, "hourlyCents": 90 }]);
        let metal = env_with("bare-metal", "100001");
        assert_eq!(
            charges_of(&of(&metal, &snapshot(&as_vps)))[0],
            Charge::NotListed
        );
        assert_eq!(
            charges_of(&of(&metal, &snapshot(&as_metal)))[0],
            Charge::At(90.0)
        );
        assert_eq!(
            charges_of(&of(&env(), &snapshot(&as_metal)))[0],
            Charge::NotListed
        );
        assert_eq!(
            charges_of(&of(&env(), &snapshot(&as_vps)))[0],
            Charge::At(7.0)
        );
    }

    #[test]
    fn what_cannot_be_looked_up_or_has_no_price_is_said_as_that() {
        // An id that is not a number is not looked up, and is not called
        // uncharged.
        for id in ["vps-100001", "100001 ", "1e5"] {
            let charges = of(&env_with("vps", id), &snapshot(&all_three()));
            assert_eq!(charges_of(&charges)[0], Charge::NotLookedUp, "{id:?}");
            let text = charges.lines("").join("\n");
            assert!(text.contains("not looked up"), "{text}");
            assert_eq!(charges.json()["items"][0]["charged"], json!(null));
        }
        // A row without a price, or with one that is not a number, is
        // charged, and is not shown as costing nothing.
        for cents in [json!(null), json!("7"), json!(-1)] {
            let rows = json!([
                { "productType": "vps", "userProductId": 100_001, "hourlyCents": cents },
            ]);
            let charges = of(&env(), &snapshot(&rows));
            assert_eq!(charges_of(&charges)[0], Charge::Unpriced, "{cents}");
            let text = charges.lines("").join("\n");
            assert!(text.contains("its price is not given"), "{text}");
            assert!(!text.contains("€0.00 per hour"), "{text}");
            let json = charges.json();
            assert_eq!(json["items"][0]["charged"], json!(true));
            assert_eq!(json["items"][0]["cents_per_hour"], json!(null));
            // It is charged, so how to end it is said.
            assert!(text.contains("delete --release-server"), "{text}");
        }
        // A row whose id came as text is not this product's row.
        let rows = json!([{ "productType": "vps", "userProductId": "100001", "hourlyCents": 7 }]);
        assert_eq!(
            charges_of(&of(&env(), &snapshot(&rows)))[0],
            Charge::NotListed
        );
    }

    #[test]
    fn the_credit_line_says_hours_only_when_it_has_them_and_idle_only_when_nothing_is_spent() {
        let with = |burn: Value, hours: Value| {
            let snapshot = json!({ "message": {
                "balance": { "balanceCents": 500 },
                "hourlyResources": all_three(),
                "burnRateCentsPerHour": burn,
                "timeToZeroHours": hours,
            } });
            let charges = of(&env(), &snapshot);
            (
                charges.credit.expect("credit"),
                charges.lines("").join("\n"),
            )
        };
        // Spent by the hour, and how long it lasts: whole hours, whether
        // the snapshot gives a whole number or not.
        for hours in [json!(15), json!(15.0), json!(15.9)] {
            let (credit, text) = with(json!(48), hours);
            assert_eq!(credit.hours, Some(15));
            assert!(text.contains("about 15 hours"), "{text}");
        }
        let (_, text) = with(json!(48), json!(1));
        assert!(text.contains("about 1 hour."), "{text}");
        // Spent by the hour, with no duration given: the rate, and not
        // "nothing spends it".
        for hours in [json!(null), json!("15"), json!(-3)] {
            let (credit, text) = with(json!(48), hours);
            assert_eq!(credit.hours, None);
            assert!(text.contains("€0.48 per hour"), "{text}");
            assert!(!text.contains("nothing spends"), "{text}");
            assert!(!text.contains("about"), "{text}");
        }
        // Nothing spent by the hour: said so, whatever the snapshot has
        // for hours.
        for burn in [json!(0), json!(0.0)] {
            let (credit, text) = with(burn, json!(15));
            assert_eq!((credit.burn_cents, credit.hours), (Some(0.0), None));
            assert!(text.contains("nothing spends it by the hour"), "{text}");
            assert!(text.contains("€5.00"), "{text}");
        }
        // No rate the snapshot can be taken at its word for: the balance
        // alone. "Nothing spends it" would be a guess, and a wrong one for
        // an account that runs something.
        for burn in [json!(null), json!("48"), json!(-5)] {
            let (credit, text) = with(burn, json!(15));
            assert_eq!((credit.burn_cents, credit.hours), (None, None));
            assert!(text.contains("The account has €5.00 of credit."), "{text}");
            assert!(!text.contains("nothing spends"), "{text}");
            assert!(!text.contains("per hour on all"), "{text}");
            assert!(!text.contains("about"), "{text}");
        }
        let unsaid = of(
            &env(),
            &json!({ "message": {
                "balance": { "balanceCents": 500 },
                "hourlyResources": all_three(),
            } }),
        );
        let credit = &unsaid.json()["credit"];
        assert_eq!(credit["balance_cents"], json!(500.0));
        assert_eq!(credit["account_cents_per_hour"], json!(null));
        assert_eq!(credit["hours_left"], json!(null));
        // No balance in the snapshot: no credit line at all.
        let charges = of(
            &env(),
            &json!({ "message": { "hourlyResources": all_three() } }),
        );
        assert_eq!(charges.credit, None);
        assert!(!charges.lines("").join("\n").contains("credit"));
    }

    #[test]
    fn nothing_on_the_list_names_no_end_and_sums_to_zero() {
        let charges = of(&env(), &snapshot(&json!([])));
        assert!(charges.items.iter().all(|i| i.charge == Charge::NotListed));
        let text = charges.lines("").join("\n");
        assert!(!text.contains("delete --release-server"), "{text}");
        // A sum of nothing is zero, and is written as zero.
        let json = charges.json();
        assert_eq!(json["cents_per_hour"].to_string(), "0.0");
    }

    #[test]
    fn without_the_list_or_anything_hourly_nothing_is_said() {
        // An answer without the list of charges says nothing of any item.
        for answer in [
            json!({}),
            json!({ "message": {} }),
            json!({ "message": { "hourlyResources": null } }),
            json!({ "message": { "hourlyResources": "none" } }),
            json!({ "success": false, "message": "Unauthorized" }),
        ] {
            assert_eq!(from_snapshot(&env(), &answer), None, "{answer}");
        }
        assert!(from_snapshot(&env(), &snapshot(&all_three())).is_some());
        // An environment with nothing billed by the hour is not looked up.
        let own: Manifest = toml::from_str(
            "name = \"bot\"\nchain = \"solana\"\n[env.prod]\nhost = \"203.0.113.10\"\n",
        )
        .expect("manifest");
        assert_eq!(
            from_snapshot(&own.env["prod"], &snapshot(&all_three())),
            None
        );
    }

    #[test]
    fn the_prices_line_up_by_what_a_terminal_shows() {
        // Labels of different lengths, as Japanese has them: each price
        // starts at the same column, counted in terminal cells.
        let mut charges = of(&env(), &snapshot(&all_three()));
        charges.items[0].label = "サーバー 100001".to_owned();
        charges.items[1].label = "gRPC 回線 200002".to_owned();
        let lines = charges.lines("");
        let column = |line: &str| {
            let at = line.find('€').expect("a price");
            line[..at].width()
        };
        let columns: Vec<usize> = lines[1..=4].iter().map(|l| column(l)).collect();
        assert!(
            columns.windows(2).all(|pair| pair[0] == pair[1]),
            "{lines:#?}"
        );
    }

    #[test]
    fn euros_keep_two_decimals_and_a_price_its_own() {
        assert_eq!(euros(7.0), "0.07");
        assert_eq!(euros(741.0), "7.41");
        assert_eq!(euros(100.0), "1.00");
        assert_eq!(euros(0.5), "0.005");
        assert_eq!(euros(0.0), "0.00");
    }
}
