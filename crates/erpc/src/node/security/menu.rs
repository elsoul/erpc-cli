// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc ai --security-check`: pick one of the account's servers, confirm
//! the terms, read this server, then wait for the check and show its report.
//! Every choice is from a list this program draws; nothing typed goes to
//! ERPC.

use std::io::IsTerminal as _;
use std::time::{Duration, Instant};

use erpc_ai::session::Access as _;
use erpc_api::security_check::{self, Error, FailReason, Inventory, Keys, Poll, Refusal, Server};
use erpc_auth::AuthClient;

use crate::account::commands::{Outcome, Said};
use crate::cli::prompt::Spinner;

pub(crate) const SUPPORTED: bool = cfg!(target_os = "linux");

const POLL_EVERY: Duration = Duration::from_secs(3);
const GIVE_UP_AFTER: Duration = Duration::from_mins(10);
// A dropped connection while waiting is retried this many times in a row.
const TRANSIENT_RETRIES: u32 = 3;

pub(crate) async fn menu(json: bool) -> Outcome {
    if !SUPPORTED {
        return Outcome::Failed(t!("security_check.unsupported"));
    }
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        return Outcome::NeedsTerminal(t!("security_check.terminal_required"));
    }
    match run(json).await {
        Ok(outcome) | Err(outcome) => outcome,
    }
}

fn failed() -> Outcome {
    Outcome::Failed(t!("security_check.request_failed"))
}

fn sign_in() -> Outcome {
    Outcome::NoSession(t!("security_check.sign_in"))
}

fn refused(error: &Error) -> Outcome {
    let message = match error {
        Error::Api(erpc_api::ApiError::Unauthorized) => return sign_in(),
        Error::Api(_) | Error::Refused(Refusal::Invalid) => return failed(),
        Error::Refused(Refusal::Denied) => t!("security_check.refused.denied"),
        Error::Refused(Refusal::SourceMismatch) => t!("security_check.refused.source_mismatch"),
        Error::Refused(Refusal::NotEligible) => t!("security_check.refused.not_eligible"),
        Error::Refused(Refusal::Active) => t!("security_check.refused.active"),
        Error::Refused(Refusal::Limited) => t!("security_check.refused.limited"),
        Error::Refused(Refusal::Unavailable) => t!("security_check.refused.unavailable"),
        Error::Refused(Refusal::NotFound) => t!("security_check.refused.not_found"),
    };
    Outcome::Failed(message)
}

async fn run(json: bool) -> Result<Outcome, Outcome> {
    let client = AuthClient::new().map_err(|_| failed())?;
    let access = crate::ai::StoreAccess::open(client.clone()).map_err(|_| sign_in())?;
    let token = access.access_token().await.map_err(|_| sign_in())?;
    let servers = security_check::servers(&client, &token)
        .await
        .map_err(|e| refused(&e))?;
    if servers.is_empty() {
        return Err(Outcome::Failed(t!("security_check.no_servers")));
    }
    let Some(server) = pick(&servers)? else {
        return Ok(Outcome::Done(String::new()));
    };
    if !agreed()? {
        return Ok(Outcome::Done(String::new()));
    }

    let spinner = Spinner::start(&t!("security_check.reading"));
    let inventory = read_this_server().await.ok_or_else(|| failed())?;
    spinner.stop(&t!(
        "security_check.read",
        listeners = inventory.listeners.items().len(),
        packages = inventory.packages.items().len()
    ));
    if !inventory.privileged {
        let _ = cliclack::log::warning(t!("security_check.not_root"));
    }

    let id = security_check::start(&client, &token, &server.id, &inventory)
        .await
        .map_err(|e| refused(&e))?;
    let spinner = Spinner::start(&t!("security_check.waiting"));
    let started = Instant::now();
    let mut transient = 0;
    loop {
        tokio::time::sleep(POLL_EVERY).await;
        let token = access.access_token().await.map_err(|_| sign_in())?;
        match security_check::poll(&client, &token, &id, &server.id, &inventory).await {
            Ok(Poll::Running) if started.elapsed() < GIVE_UP_AFTER => transient = 0,
            Ok(Poll::Running) => {
                spinner.error(&t!("security_check.timeout"));
                return Err(Outcome::Failed(t!("security_check.timeout")));
            }
            Ok(Poll::Done(report)) => {
                spinner.done();
                return Ok(if json {
                    Said::Json(super::report::json(&report, &server.id)).done()
                } else {
                    Outcome::Done(super::report::render(&report, server, &inventory))
                });
            }
            Ok(Poll::Failed(reason)) => {
                let message = match reason {
                    FailReason::Unavailable => t!("security_check.failed.unavailable"),
                    FailReason::Cancelled => t!("security_check.failed.cancelled"),
                    FailReason::ScanFailed => t!("security_check.failed.scan_failed"),
                };
                spinner.error(&message);
                return Err(Outcome::Failed(message));
            }
            Err(Error::Api(erpc_api::ApiError::Http(_))) if transient < TRANSIENT_RETRIES => {
                transient += 1;
            }
            Err(e) => {
                spinner.done();
                return Err(refused(&e));
            }
        }
    }
}

/// The server picked, `None` to cancel.
fn pick(servers: &[Server]) -> Result<Option<&Server>, Outcome> {
    let mut select = cliclack::select(t!("security_check.pick"));
    for (index, server) in servers.iter().enumerate() {
        select = select.item(
            Some(index),
            t!(
                "security_check.server",
                label = server.label.as_str(),
                address = server.address,
                region = server.region.as_str()
            ),
            server.kind.wire(),
        );
    }
    let mut select = select
        .item(None, t!("security_check.cancel"), "")
        .initial_value(None);
    match select.interact() {
        Ok(choice) => Ok(choice.and_then(|index| servers.get(index))),
        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => Ok(None),
        Err(_) => Err(Outcome::Failed(t!("security_check.menu_failed"))),
    }
}

/// Whether the customer confirmed the terms; the request says so only then.
fn agreed() -> Result<bool, Outcome> {
    match cliclack::confirm(t!("security_check.terms"))
        .initial_value(false)
        .interact()
    {
        Ok(yes) => Ok(yes),
        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => Ok(false),
        Err(_) => Err(Outcome::Failed(t!("security_check.menu_failed"))),
    }
}

#[cfg(target_os = "linux")]
async fn read_this_server() -> Option<Inventory> {
    tokio::task::spawn_blocking(|| super::collect(&super::Host::this_machine(), Keys::unreadable()))
        .await
        .ok()
}

#[cfg(not(target_os = "linux"))]
async fn read_this_server() -> Option<Inventory> {
    let _ = Keys::unreadable();
    None
}
