// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The first `erpc worker deploy` that starts a new server makes the app
//! an ERPC Worker in the ERPC account: the environment is kept there
//! (`account = true`), its server is started through the account
//! ([`crate::worker::server::for_deploy`]), and the deploy then goes on as
//! a deploy to an environment kept there goes: it waits for the server,
//! logs in to it once at a terminal ([`crate::worker::first_login`]), asks
//! whether to trust what the account then has, and deploys.
//!
//! It is the way for an environment `erpc.toml` has nothing for yet (no
//! `[env.<name>]`, or an empty one) when `--new-server` asks for a new
//! server or the person picks one at the terminal. Everything else goes
//! as before: an environment with anything in `erpc.toml`, `--host`,
//! `--server`, a server of the account picked at the terminal, and
//! `--inline` or `--vault`, which name where a new environment is kept.
//! So does a deploy that asks for what an environment kept in the account
//! does not take yet (a UDP Forwarding line, `--forget-line`), and it says
//! why. A gRPC, Shreds or Unlimited line asked is started in the account
//! ([`crate::worker::line_start`]), and `--plan` at the cores its name
//! says ([`sized_start`]). An app whose `erpc.toml` names a wallet goes the
//! account way too: its record is made with the wallet's public side, and
//! its key is handed over at the terminal as on any deploy.
//!
//! Everything that would refuse the deploy is asked before anything is
//! written or bought: a terminal and no `--json` (the first login is asked
//! there only), what the deploy needs on this machine, the sign-in, each
//! line's plan in the hourly catalogue. The account's records of the app
//! and the environment are made when missing (free, said on stderr); the
//! server's price is said and asked, then each line's (`--yes` says them on
//! stderr instead); then the lines asked are kept on this machine, owed,
//! `erpc.toml` gets `account = true`, and only then is the start sent,
//! under a key kept on this machine.
//!
//! A run that stopped is run again: an environment `erpc.toml` keeps in the
//! account whose record names no server, no address, no line and no
//! deploy goes the same way, a start kept on this machine or open in the
//! account first, and buys no second server. There `--yes` answers the
//! prices only with `--new-server`, and takes only the size `--plan`
//! names. One whose record names a server and no deploy, with a line asked
//! or kept on this machine for it, has its lines started before the deploy
//! ([`First::Owed`]). One the account signed in to has no record of at all
//! (another account's, or deleted: a first deploy makes the records before
//! it writes `account = true`) is refused as before, unless `--new-server`
//! asks for a new server in the account signed in to.

use std::path::{Path, PathBuf};

use erpc_api::worker::{Code as AccountCode, EnvDetail, WorkerError};
use erpc_worker::manifest::{Env, LineKind, Manifest};

use crate::cli::error::{CliError, Code};
use crate::node::common::Say;
use crate::worker::App;
use crate::worker::account::{self as kept, Account};
use crate::worker::deploy::{Picked, Where};
use crate::worker::line_start::Owing;
use crate::worker::server::{Region, Size};

fn failed(message: String) -> CliError {
    CliError::new(Code::Failed, message)
}

/// What the deploy does next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum First {
    /// As before.
    AsBefore,
    /// Deploy to this server of the account, picked at the terminal, as
    /// `--server` would.
    Picked(i64),
    /// `erpc.toml` keeps the environment in the account, and its server is
    /// on the account's record: the deploy to it follows, the data lines
    /// asked started first ([`crate::worker::line_start`]).
    Started,
    /// A first deploy that stopped after its server was started, or an
    /// environment moved into the account, before its first deploy there:
    /// the data lines asked, and those kept on this machine for it, are
    /// started, then the deploy to it follows.
    Owed,
}

/// Why a first deploy keeps the environment in `erpc.toml`, as before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Why {
    /// A UDP Forwarding line (or its options) asked for, or `--forget-line`.
    Lines,
}

/// Which way a deploy goes, from `erpc.toml` and the command line alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Way {
    /// As before.
    AsBefore,
    /// As before, and said why.
    Said(Why),
    /// A new server in the account: asked for with `--new-server`
    /// (`asked`), or offered at the terminal beside the account's.
    New { asked: bool },
    /// Kept in the account already: what the account has decides.
    Resume,
    /// Refused before anything: the first login is asked at a terminal.
    NeedsTerminal,
}

/// Which way the deploy of environment `env` (`None`: `erpc.toml` has no
/// table for it) goes, asked as `at` asks, under `--json` or not, at a
/// terminal or not.
fn way(env: Option<&Env>, at: &Where, (json, terminal): (bool, bool)) -> Way {
    match env {
        Some(env) if *env == crate::worker::EnvRecord::kept_in_account() => return Way::Resume,
        Some(env) if *env != Env::default() => return Way::AsBefore,
        _ => {}
    }
    // Where it goes, or where it is kept, is named.
    if at.host.is_some() || at.vps.is_some() || at.inline || at.vault.is_some() {
        return Way::AsBefore;
    }
    // Nobody to pick, nothing asked for: refused as before.
    if !at.new_vps && !terminal {
        return Way::AsBefore;
    }
    // The account's deploy takes no UDP Forwarding line yet; the other
    // data lines are started in the account.
    if udp_or_forget(at) {
        return Way::Said(Why::Lines);
    }
    if json || !terminal {
        return Way::NeedsTerminal;
    }
    Way::New { asked: at.new_vps }
}

/// Whether `at` asks for a UDP Forwarding line, or one of its options, or
/// forgets a line: what a deploy the account way does not take yet.
fn udp_or_forget(at: &Where) -> bool {
    at.lines.iter().any(|(kind, _)| *kind == LineKind::Udp)
        || at.udp_port.is_some()
        || at.udp_region.is_some()
        || at.udp_any_source
        || !at.forget_lines.is_empty()
}

/// Why, as the note says it.
fn why_said(why: Why) -> String {
    match why {
        Why::Lines => t!("worker_first_deploy.why_lines"),
    }
}

/// Whether the account's `record` names a server, an address, a line or a
/// deploy: then it is deployed to as before, and nothing is started.
fn names_something(record: &EnvDetail) -> bool {
    !record.servers.is_empty()
        || record.facts.host.is_some()
        || !record.lines.is_empty()
        || record.deployed.is_some()
}

/// The region of the new server: `--region`, one the account names, else
/// the one nearest this machine by its time zone.
fn region(at: &Where) -> Result<Region<'_>, CliError> {
    let regions = crate::worker::vps::REGIONS;
    match at.region.as_deref() {
        Some(r) if regions.contains(&r) => Ok(Region::Asked(r)),
        Some(r) => Err(CliError::new(
            Code::Usage,
            t!(
                "worker_vps.buy.bad_region",
                region = r,
                regions = regions.join(", ")
            ),
        )),
        None => Ok(Region::Else(crate::worker::vps::nearest_region())),
    }
}

/// `e`, with `more` after its hint.
fn and_hint(e: CliError, more: String) -> CliError {
    let hint = match &e.hint {
        Some(hint) => format!("{hint}; {more}"),
        None => more,
    };
    e.hint(hint)
}

/// Writes `account = true` for environment `app.env` of the app named
/// `name` to `erpc.toml` at `path`, unless it is there already; refused
/// when the environment has anything else there now.
fn keep_in_account(path: &Path, app: &App, name: &str) -> Result<(), CliError> {
    let env = app.env.as_str();
    let now = Manifest::load(path).map_err(|e| failed(e.to_string()))?;
    let unwritten = |error: String| failed(t!("worker_first_deploy.not_written", env, error));
    match now.env.get(env) {
        Some(e) if *e == crate::worker::EnvRecord::kept_in_account() => return Ok(()),
        Some(e) if *e != Env::default() => {
            return Err(unwritten(t!("worker_first_deploy.file_changed", env)));
        }
        _ => {}
    }
    crate::worker::EnvRecord {
        path,
        app: name,
        env,
    }
    .save(&crate::worker::EnvRecord::kept_in_account(), None)
    .map_err(unwritten)
}

/// What a first deploy reaches beyond `erpc.toml`: this machine, the
/// sign-in, the account, the terminal. The real one is [`Live`]; a test
/// brings a stand-in.
pub(crate) trait Reach {
    /// What a deploy needs on this machine, and `erpc.toml` with where it
    /// is ([`crate::worker::deploy::ready_to_start`]).
    fn ready(&self, app: &App, at: &Where) -> Result<(PathBuf, Manifest), CliError>;
    /// Signs in.
    async fn sign_in(&self) -> Result<(), CliError>;
    /// The account's record of environment `app.env` of the app named
    /// `name`; `None` when it has no record of the app or the environment.
    async fn record(&self, app: &App, name: &str) -> Result<Option<EnvDetail>, CliError>;
    /// Which server the environment runs on, asked at the terminal, a new
    /// one offered last as `offer` says ([`crate::worker::deploy::pick`]).
    async fn pick(&self, offer: String) -> Result<Picked, CliError>;
    /// Starts its server of `size` in `region`
    /// ([`crate::worker::server::for_deploy`]), `yes` answering the price,
    /// `agreed` run after the yes and before the start is sent; what the
    /// account then keeps, said.
    async fn start(
        &self,
        app: &App,
        m: &Manifest,
        asked: (Region<'_>, bool, Size<'_>),
        agreed: impl FnOnce() -> Result<(), CliError>,
    ) -> Result<String, CliError>;
    /// The name of `--plan`'s product and the cores it says
    /// ([`crate::worker::vps::plan_cores`]).
    async fn plan_cores(&self, plan: &str) -> Result<(String, Option<u16>), CliError>;
    /// What is free to be rented now, by cores and region
    /// ([`crate::worker::vps::stock`]).
    async fn stock(&self) -> Result<Vec<(u16, &'static str)>, CliError>;
    /// The lines `lines` asks for, each one's plan read, and those kept on
    /// this machine for environment `app.env` of the app named `name`
    /// ([`crate::worker::line_start::owing`]); `fresh` when `erpc.toml` has
    /// nothing for it.
    async fn owing(
        &self,
        app_name: (&App, &str),
        lines: &[(LineKind, Option<String>)],
        fresh: bool,
    ) -> Result<Owing, CliError>;
    /// Asks `question` at the terminal.
    fn confirm(&self, question: &str) -> Result<bool, String>;
}

/// This machine, its sign-in, the ERPC account and the terminal.
#[derive(Default)]
pub(crate) struct Live {
    signed: core::cell::OnceCell<kept::Signed>,
}

impl Live {
    fn signed(&self) -> Result<&kept::Signed, CliError> {
        self.signed.get().ok_or_else(|| {
            CliError::new(Code::NotSignedIn, t!("worker_vps.no_session"))
                .hint(t!("worker_vps.login_hint"))
        })
    }
}

impl Reach for Live {
    fn ready(&self, app: &App, at: &Where) -> Result<(PathBuf, Manifest), CliError> {
        crate::worker::deploy::ready_to_start(app, at)
    }

    async fn sign_in(&self) -> Result<(), CliError> {
        if self.signed.get().is_none() {
            let _ = self.signed.set(kept::Signed::open().await?);
        }
        Ok(())
    }

    async fn record(&self, app: &App, name: &str) -> Result<Option<EnvDetail>, CliError> {
        match Account::env(self.signed()?, name, &app.env).await {
            Ok(record) => Ok(Some(record)),
            Err(WorkerError::Refused(r))
                if matches!(
                    r.code,
                    Some(AccountCode::WorkerNotFound | AccountCode::EnvNotFound)
                ) =>
            {
                Ok(None)
            }
            Err(e) => Err(kept::worker_error(name, app, &e)),
        }
    }

    async fn pick(&self, offer: String) -> Result<Picked, CliError> {
        let api = crate::worker::vps::Api::open().await?;
        crate::worker::deploy::pick(&api, offer).await
    }

    async fn start(
        &self,
        app: &App,
        m: &Manifest,
        asked: (Region<'_>, bool, Size<'_>),
        agreed: impl FnOnce() -> Result<(), CliError>,
    ) -> Result<String, CliError> {
        crate::worker::server::for_deploy(self.signed()?, app, m, asked, agreed).await
    }

    async fn plan_cores(&self, plan: &str) -> Result<(String, Option<u16>), CliError> {
        let api = crate::worker::vps::Api::open().await?;
        crate::worker::vps::plan_cores(&api, plan).await
    }

    async fn stock(&self) -> Result<Vec<(u16, &'static str)>, CliError> {
        let api = crate::worker::vps::Api::open().await?;
        crate::worker::vps::stock(&api).await
    }

    async fn owing(
        &self,
        (app, name): (&App, &str),
        lines: &[(LineKind, Option<String>)],
        fresh: bool,
    ) -> Result<Owing, CliError> {
        crate::worker::line_start::owing(self.signed()?, (app, name), lines, fresh).await
    }

    fn confirm(&self, question: &str) -> Result<bool, String> {
        crate::node::common::confirm(question)
    }
}

/// The deploy's first step: [`First`] says what follows. Refused before
/// anything is written or bought when a first deploy cannot go through.
pub(crate) async fn first(json: bool, app: &App, at: &Where, yes: bool) -> Result<First, CliError> {
    let Ok((_, m)) = crate::worker::load(&app.dir) else {
        // Said by the deploy, as before.
        return Ok(First::AsBefore);
    };
    let asking = (json, crate::account::session::has_terminal());
    Box::pin(first_with(&Live::default(), app, (at, yes), &m, asking)).await
}

/// [`first`] through `reach`, for `m` as `erpc.toml` has it, under
/// `--json` or not, at a terminal or not (`asking`).
async fn first_with(
    reach: &impl Reach,
    app: &App,
    (at, yes): (&Where, bool),
    m: &Manifest,
    (json, terminal): (bool, bool),
) -> Result<First, CliError> {
    let env = app.env.as_str();
    match way(m.env.get(env), at, (json, terminal)) {
        Way::AsBefore => Ok(First::AsBefore),
        Way::Said(why) => {
            Say { quiet: false }.line(&format!(
                "note: {}",
                t!("worker_first_deploy.as_before", env, why = why_said(why))
            ));
            Ok(First::AsBefore)
        }
        Way::NeedsTerminal => Err(CliError::new(
            Code::NeedsTerminal,
            t!("worker_first_deploy.needs_terminal", env),
        )
        .hint(t!(
            "worker_first_deploy.needs_terminal_hint",
            scope = app.scope()
        ))),
        Way::New { asked } => new_server(reach, app, (at, yes), asked).await,
        Way::Resume => resume(reach, app, (at, yes), m, (json, terminal)).await,
    }
}

/// A new server for an environment `erpc.toml` has nothing for: what the
/// deploy needs here checked, the sign-in, the server picked (unless
/// `asked` for with `--new-server`), then started in the account, with
/// `account = true` written after the yes.
async fn new_server(
    reach: &impl Reach,
    app: &App,
    (at, yes): (&Where, bool),
    asked: bool,
) -> Result<First, CliError> {
    let region = region(at)?;
    let (path, m) = reach.ready(app, at)?;
    // What the account keeps of the app is checked for a server started
    // there only: one picked at the terminal is deployed to as before.
    if asked {
        crate::worker::deploy_account::deployed_app(&m)?;
    }
    reach.sign_in().await?;
    if !asked {
        let near = match region {
            Region::Asked(r) | Region::Else(r) => r,
        };
        let offer = t!("worker_first_deploy.new_option", region = near);
        if let Picked::Server(id) = reach.pick(offer).await? {
            return Ok(First::Picked(id));
        }
        crate::worker::deploy_account::deployed_app(&m)?;
    }
    // Each line's plan read, before anything is made or bought.
    let owing = reach.owing((app, &m.name), &at.lines, true).await?;
    let written = core::cell::Cell::new(false);
    // After the server's yes: each line's price asked, the lines kept,
    // owed, then erpc.toml written.
    let agreed = || {
        if !written.get() {
            owing.agree(&|q| reach.confirm(q), yes)?;
            keep_in_account(&path, app, &m.name)?;
            written.set(true);
        }
        Ok(())
    };
    let started = sized_start(
        reach,
        app,
        (&m, at.plan.as_deref()),
        (region, yes, yes),
        &agreed,
    )
    .await;
    let text = match started {
        Ok(text) => text,
        // Once erpc.toml keeps it in the account, a stop says the deploy
        // goes on from there.
        Err(e) if written.get() => return Err(and_hint(e, kept_now(app, at))),
        Err(e) => return Err(e),
    };
    // A start this machine kept that went through before this run sends
    // nothing and asks nothing: erpc.toml is made to say so now, and the
    // lines asked are kept, to be asked when they are started.
    if !written.get() {
        owing.keep(false)?;
    }
    keep_in_account(&path, app, &m.name)?;
    Say { quiet: false }.line(&text);
    Ok(First::Started)
}

/// What a stop says once `erpc.toml` keeps the environment in the account:
/// the deploy goes on from there, at the `--plan` asked.
fn kept_now(app: &App, at: &Where) -> String {
    let plan = at.plan.as_deref().map_or_else(String::new, |p| {
        format!(" --plan {}", crate::storage::clean(p))
    });
    t!(
        "worker_first_deploy.kept_now_hint",
        env = app.env.as_str(),
        plan = plan.as_str(),
        scope = app.scope()
    )
}

/// An environment `erpc.toml` keeps in the account: started for as a new
/// one is when the account's record names no server, no address, no line
/// and no deploy, or, with `--new-server`, when the account has no record
/// of it; its lines started before the deploy when the record names a
/// server and no deploy, and a line is asked or kept on this machine for
/// it; refused as before when it has none and nothing asked for a new
/// server; as before otherwise.
async fn resume(
    reach: &impl Reach,
    app: &App,
    (at, yes): (&Where, bool),
    m: &Manifest,
    (json, terminal): (bool, bool),
) -> Result<First, CliError> {
    let mut start = at.clone();
    after_started(&mut start);
    // What a deploy there does not take is refused as before, unread; a
    // UDP Forwarding line among them.
    if udp_or_forget(at) || crate::worker::deploy_account::refuse_options(&start, app).is_err() {
        return Ok(First::AsBefore);
    }
    let region = region(at)?;
    reach.sign_in().await?;
    let env = app.env.as_str();
    let needs_terminal = || {
        CliError::new(
            Code::NeedsTerminal,
            t!("worker_first_deploy.resume_needs_terminal", env),
        )
        .hint(t!(
            "worker_first_deploy.resume_needs_terminal_hint",
            scope = app.scope()
        ))
    };
    let record = reach.record(app, &m.name).await?;
    // Its server there, never deployed to (a first deploy that stopped
    // after its start, or one moved in), nothing else for a server asked:
    // the lines asked, and those kept here, are started before the deploy,
    // at a terminal, once what refuses the deploy is checked.
    if let Some(record) = &record
        && !record.servers.is_empty()
        && record.deployed.is_none()
        && !at.new_vps
        && at.region.is_none()
        && at.plan.is_none()
    {
        let owing = reach.owing((app, &m.name), &at.lines, false).await?;
        if !owing.kinds().is_empty() {
            if json || !terminal {
                return Err(needs_terminal());
            }
            let checked = Where {
                kept: Some(m.clone()),
                lines: owing.kinds().into_iter().map(|k| (k, None)).collect(),
                ..start
            };
            let (_, m) = reach.ready(app, &checked)?;
            crate::worker::deploy_account::deployed_app(&m)?;
            crate::worker::deploy_account::refuse_record(app, record)?;
            owing.keep(false)?;
            return Ok(First::Owed);
        }
    }
    match record {
        Some(record) if names_something(&record) => return Ok(First::AsBefore),
        // A first deploy that stopped made the records before it wrote
        // `account = true`: none at all is another account's, or deleted,
        // and is refused as before, unless a new server is asked for.
        None if !at.new_vps => {
            return Err(failed(t!(
                "worker_first_deploy.no_record",
                app = m.name.as_str(),
                env
            ))
            .hint(t!(
                "worker_first_deploy.no_record_hint",
                scope = app.scope()
            )));
        }
        // A record naming nothing, or none and a new server asked for.
        Some(_) | None => {}
    }
    if json || !terminal {
        return Err(needs_terminal());
    }
    let owing = reach.owing((app, &m.name), &at.lines, false).await?;
    let checked = Where {
        kept: Some(m.clone()),
        lines: owing.kinds().into_iter().map(|k| (k, None)).collect(),
        ..start
    };
    let (_, m) = reach.ready(app, &checked)?;
    crate::worker::deploy_account::deployed_app(&m)?;
    // Nothing on this command line picked a new server: the prices are
    // asked, and --yes takes only the size named.
    let yes_price = yes && at.new_vps;
    let agreed_once = core::cell::Cell::new(false);
    let agreed = || {
        if !agreed_once.get() {
            owing.agree(&|q| reach.confirm(q), yes_price)?;
            agreed_once.set(true);
        }
        Ok(())
    };
    let text = sized_start(
        reach,
        app,
        (&m, at.plan.as_deref()),
        (region, yes_price, yes),
        &agreed,
    )
    .await?;
    // A start that went through before this run asked nothing: the lines
    // asked are kept, to be asked when they are started.
    if !agreed_once.get() {
        owing.keep(false)?;
    }
    Say { quiet: false }.line(&text);
    Ok(First::Started)
}

/// The start of the first deploy's server: of the cheapest size, or of
/// `--plan`'s (`plan`), offered another when it is not free now. `yes`
/// answers the price; `only_named` (`--yes`) offers no other size or
/// region. A stop of `agreed` (a line's price declined, say) stops it,
/// whatever size it was for.
async fn sized_start(
    reach: &impl Reach,
    app: &App,
    (m, plan): (&Manifest, Option<&str>),
    (region, yes, only_named): (Region<'_>, bool, bool),
    agreed: &dyn Fn() -> Result<(), CliError>,
) -> Result<String, CliError> {
    let stopped = core::cell::Cell::new(false);
    let agreed = || agreed().inspect_err(|_| stopped.set(true));
    let Some(plan) = plan else {
        return reach
            .start(app, m, (region, yes, Size::Cheapest), agreed)
            .await;
    };
    let (_, cores) = reach.plan_cores(plan).await?;
    // A name erpc does not read: refused with the sizes the account offers,
    // once read, before anything is bought.
    let Some(cores) = cores else {
        return reach
            .start(app, m, (region, yes, Size::Unread(plan)), agreed)
            .await;
    };
    let here = match region {
        Region::Asked(r) | Region::Else(r) => r,
    };
    // What is free now; read or not, the start may still find it gone.
    let free = reach.stock().await.ok();
    let none_free = || not_free((cores, here), free.as_deref(), app);
    let near = crate::worker::vps::nearest_region();
    let (named_free, others) = offered(cores, (here, near), free.as_deref());
    let say = Say { quiet: false };
    if named_free {
        match reach
            .start(app, m, (region, yes, Size::Cores(cores)), agreed)
            .await
        {
            // Out of stock though listed free: said, then the next.
            Err(e) if crate::worker::server::out_of_stock(&e) => {
                say.line(&format!("note: {}", e.message));
            }
            done => return done,
        }
    }
    // Never another than named under --yes.
    if only_named {
        return Err(none_free());
    }
    for (c, r) in others {
        say.line(&t!(
            "worker_first_deploy.plan_instead",
            worker = worker_cored(cores),
            region = here,
            other = worker_cored(c),
            other_region = r
        ));
        match reach
            .start(app, m, (Region::Asked(r), false, Size::Cores(c)), agreed)
            .await
        {
            // Declined, or a size the account does not start: the next.
            Err(e) if !stopped.get() && matches!(e.code, Code::Declined | Code::Usage) => {}
            Err(e) if crate::worker::server::out_of_stock(&e) => {
                say.line(&format!("note: {}", e.message));
            }
            done => return done,
        }
    }
    Err(none_free())
}

/// What is free now, as `free` lists it, each once, fewest cores first.
fn free_said(free: &[(u16, &'static str)]) -> String {
    let mut seen: Vec<(u16, &str)> = Vec::new();
    for f in free {
        if !seen.contains(f) {
            seen.push(*f);
        }
    }
    seen.sort_unstable();
    seen.iter()
        .map(|(c, r)| {
            t!(
                "worker_first_deploy.free_one",
                worker = worker_cored(*c),
                region = *r
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// The stop of a `--plan` start whose size (`cores` in `here`) is not
/// free: with what is free now, when it was read.
fn not_free(
    (cores, here): (u16, &str),
    free: Option<&[(u16, &'static str)]>,
    app: &App,
) -> CliError {
    let message = match free {
        Some(free) => {
            let listed = free_said(free);
            t!(
                "worker_first_deploy.plan_not_free",
                worker = worker_cored(cores),
                region = here,
                free = if listed.is_empty() {
                    t!("worker_first_deploy.free_none")
                } else {
                    listed
                }
            )
        }
        // What is free was not read: none is said.
        None => t!(
            "worker_first_deploy.plan_not_free_unread",
            worker = worker_cored(cores),
            region = here
        ),
    };
    failed(message).hint(t!(
        "worker_first_deploy.plan_not_free_hint",
        scope = app.scope()
    ))
}

/// The ERPC Worker of `cores`, as a person reads it.
fn worker_cored(cores: u16) -> String {
    use crate::worker::vps::{Spec, worker};
    worker(&Spec::sized(Some(cores), None))
}

/// Whether `cores` in `here` is free now, by `free` (not read: taken to be),
/// and what to offer in its place, in turn: a bigger size free in `here`,
/// fewest cores first, then the same size in another region, `near` (this
/// machine's) and those nearest it first.
fn offered<'a>(
    cores: u16,
    (here, near): (&'a str, &'static str),
    free: Option<&[(u16, &'static str)]>,
) -> (bool, Vec<(u16, &'a str)>) {
    let Some(free) = free else {
        return (true, Vec::new());
    };
    let has = |c: u16, r: &str| free.contains(&(c, r));
    let mut bigger: Vec<u16> = free
        .iter()
        .filter(|(c, r)| *c > cores && *r == here)
        .map(|(c, _)| *c)
        .collect();
    bigger.sort_unstable();
    bigger.dedup();
    let mut others: Vec<(u16, &'a str)> = bigger.into_iter().map(|c| (c, here)).collect();
    let mut regions = vec![near];
    regions.extend(crate::worker::vps::regions_by_nearness(near));
    others.extend(
        regions
            .into_iter()
            .filter(|r| *r != here && has(cores, r))
            .map(|r| (cores, r)),
    );
    (has(cores, here), others)
}

/// The deploy's options once its server was started here ([`First::Started`],
/// [`First::Owed`]): `--new-server` and `--region` were for the start, and
/// the data lines asked are started before the deploy
/// ([`crate::worker::line_start`]); the deploy to an environment kept in
/// the account that follows refuses all of them
/// ([`crate::worker::deploy_account::refuse_options`]). The lines it took
/// off come back.
pub(crate) fn after_started(at: &mut Where) -> Vec<(LineKind, Option<String>)> {
    at.new_vps = false;
    at.region = None;
    at.plan = None;
    std::mem::take(&mut at.lines)
}

/// What the deploy reads of an environment kept in the account (`held`),
/// once a run decided whether it started its server (`started`): one that
/// started it is never read as an environment with no server, which the
/// deploy would buy one for as before.
pub(crate) fn held_after<T>(
    started: bool,
    held: Option<T>,
    app: &App,
) -> Result<Option<T>, CliError> {
    match held {
        None if started => Err(kept::not_yet(app)),
        held => Ok(held),
    }
}

/// What follows a deploy that started its server, when it stops: the
/// environment is kept in the account now, with its server.
pub(crate) fn after_start(e: CliError, app: &App) -> CliError {
    and_hint(
        e,
        t!(
            "worker_first_deploy.started_hint",
            env = app.env.as_str(),
            scope = app.scope()
        ),
    )
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use erpc_worker::manifest::LineKind;

    use super::*;

    const TOML: &str = "name = \"bot\"\nchain = \"solana\"\n\n[run]\nport = 3000\n";

    /// What the stand-in did at the start: whether erpc.toml kept the
    /// environment in the account as the start would have been sent, the
    /// region and whether `--yes` answered the price.
    type Sent = (bool, String, bool);

    /// This machine, the account and the terminal, in memory.
    #[allow(
        clippy::struct_excessive_bools,
        reason = "each says how one call of the stand-in answers"
    )]
    struct Fake {
        path: PathBuf,
        /// The account's record of the environment.
        record: Option<EnvDetail>,
        /// What the person picks.
        picked: Picked,
        /// Whether the person says yes to the price.
        says_yes: bool,
        /// How the start fails after the yes, if it does.
        fails_after_yes: bool,
        /// A start this machine kept went through before this run: the
        /// account answers with the server, asking nothing.
        went_through_before: bool,
        calls: RefCell<Vec<&'static str>>,
        sent: RefCell<Vec<Sent>>,
        /// The cores `--plan`'s name says.
        plan_cores: Option<u16>,
        /// What the stock read lists free; none: it is not answered.
        free: Option<Vec<(u16, &'static str)>>,
        /// Each start in turn is refused as out of stock, before its
        /// question, when `true`.
        out_of_stock: RefCell<Vec<bool>>,
        /// Each start's question is answered so, in turn (then yes).
        answers_yes: RefCell<Vec<bool>>,
        /// The size and region of each start, in turn.
        sizes: RefCell<Vec<(Option<u16>, String)>>,
        /// Where the lines asked are kept.
        store: PathBuf,
        /// Whether the hourly catalogue offers the lines' plans.
        plans_offered: bool,
        /// Each line's question, in turn.
        line_asked: RefCell<Vec<String>>,
        /// Each line's question is answered so, in turn (then yes).
        line_yes: RefCell<Vec<bool>>,
        /// The lines each check of what the deploy needs was given.
        ready_lines: RefCell<Vec<Vec<LineKind>>>,
    }

    impl Fake {
        fn new(dir: &tempfile::TempDir, toml: &str) -> Self {
            let path = dir.path().join("erpc.toml");
            std::fs::write(&path, toml).expect("written");
            Self {
                path,
                record: None,
                picked: Picked::New,
                says_yes: true,
                fails_after_yes: false,
                went_through_before: false,
                calls: RefCell::new(Vec::new()),
                sent: RefCell::new(Vec::new()),
                plan_cores: None,
                free: None,
                out_of_stock: RefCell::new(Vec::new()),
                answers_yes: RefCell::new(Vec::new()),
                sizes: RefCell::new(Vec::new()),
                store: dir.path().join("worker_line_starts.json"),
                plans_offered: true,
                line_asked: RefCell::new(Vec::new()),
                line_yes: RefCell::new(Vec::new()),
                ready_lines: RefCell::new(Vec::new()),
            }
        }

        /// The kinds of the lines kept here for the environment, and
        /// whether each was agreed to.
        fn lines_kept(&self) -> Vec<(String, bool)> {
            let text = std::fs::read(&self.store).unwrap_or_default();
            if text.is_empty() {
                return Vec::new();
            }
            let v: serde_json::Value = serde_json::from_slice(&text).expect("json");
            v["starts"]
                .as_object()
                .expect("starts")
                .iter()
                .map(|(k, line)| {
                    (
                        k.rsplit(' ').next().unwrap_or_default().to_owned(),
                        line["agreed"].as_bool().unwrap_or(false),
                    )
                })
                .collect()
        }

        /// Keeps a line of `kind` here, owed, agreed to, as an earlier run
        /// did.
        fn owe(&self, kind: LineKind) {
            let pin = kept::pin_key("user-100001", "bot", "prod");
            let owing = Owing::read(
                &self.store,
                (pin, "prod"),
                vec![(
                    kind,
                    crate::worker::line_start::Plan {
                        id: "prod_grpc_1".to_owned(),
                        cents: 12.5,
                        name: "Geyser gRPC Shared".to_owned(),
                    },
                )],
                false,
            )
            .expect("read");
            owing.agree(&|_| Ok(true), true).expect("kept");
        }

        fn kept_there(&self) -> bool {
            kept::kept_there(&Manifest::load(&self.path).expect("reads"), "prod")
        }

        fn manifest(&self) -> Manifest {
            Manifest::load(&self.path).expect("reads")
        }
    }

    #[allow(
        clippy::unused_async_trait_impl,
        reason = "the stand-in answers at once; what it stands in for is awaited"
    )]
    impl Reach for Fake {
        fn ready(&self, _: &App, at: &Where) -> Result<(PathBuf, Manifest), CliError> {
            self.calls.borrow_mut().push("ready");
            self.ready_lines
                .borrow_mut()
                .push(at.lines.iter().map(|(k, _)| *k).collect());
            let m = at.kept.clone().unwrap_or_else(|| self.manifest());
            Ok((self.path.clone(), m))
        }

        async fn sign_in(&self) -> Result<(), CliError> {
            self.calls.borrow_mut().push("sign_in");
            Ok(())
        }

        async fn record(&self, _: &App, _: &str) -> Result<Option<EnvDetail>, CliError> {
            self.calls.borrow_mut().push("record");
            Ok(self.record.clone())
        }

        async fn pick(&self, offer: String) -> Result<Picked, CliError> {
            self.calls.borrow_mut().push("pick");
            assert!(offer.contains("ERPC Worker"), "{offer}");
            Ok(self.picked)
        }

        async fn start(
            &self,
            _: &App,
            _: &Manifest,
            (region, yes, size): (Region<'_>, bool, Size<'_>),
            agreed: impl FnOnce() -> Result<(), CliError>,
        ) -> Result<String, CliError> {
            self.calls.borrow_mut().push("start");
            let region = match region {
                Region::Asked(r) | Region::Else(r) => r.to_owned(),
            };
            self.sizes
                .borrow_mut()
                .push((size_of(size), region.clone()));
            if size == Size::Cores(16) {
                return Err(CliError::new(Code::Usage, "not offered".to_owned()));
            }
            if let Size::Unread(plan) = size {
                return Err(CliError::new(
                    Code::Usage,
                    format!("{plan} gives no size; offered: 1 vCPU, 2 vCPU"),
                ));
            }
            if !self.answers_yes.borrow().is_empty() && !self.answers_yes.borrow_mut().remove(0) {
                return Err(CliError::new(Code::Declined, "declined".to_owned()));
            }
            if self.went_through_before {
                return Ok("The environment's record names a server now.".to_owned());
            }
            if !self.says_yes {
                return Err(CliError::new(
                    Code::Declined,
                    "nothing was started".to_owned(),
                ));
            }
            agreed()?;
            // The account answers out of stock after the yes, as it does.
            if !self.out_of_stock.borrow().is_empty() && self.out_of_stock.borrow_mut().remove(0) {
                return Err(CliError::new(Code::Failed, "nothing free".to_owned())
                    .details(serde_json::json!({ "accountCode": "OUT_OF_STOCK" })));
            }
            self.sent
                .borrow_mut()
                .push((self.kept_there(), region, yes));
            if self.fails_after_yes {
                return Err(CliError::new(Code::Failed, "no answer".to_owned()));
            }
            Ok("Started a new server for environment prod.".to_owned())
        }

        async fn plan_cores(&self, plan: &str) -> Result<(String, Option<u16>), CliError> {
            self.calls.borrow_mut().push("plan");
            Ok((plan.to_owned(), self.plan_cores))
        }

        async fn stock(&self) -> Result<Vec<(u16, &'static str)>, CliError> {
            self.calls.borrow_mut().push("stock");
            self.free
                .clone()
                .ok_or_else(|| CliError::new(Code::Network, "no answer".to_owned()))
        }

        async fn owing(
            &self,
            (_, name): (&App, &str),
            lines: &[(LineKind, Option<String>)],
            fresh: bool,
        ) -> Result<Owing, CliError> {
            self.calls.borrow_mut().push("owing");
            if !lines.is_empty() && !self.plans_offered {
                return Err(CliError::new(Code::Usage, "plan not offered".to_owned()));
            }
            let asked = lines
                .iter()
                .map(|(kind, plan)| {
                    (
                        *kind,
                        crate::worker::line_start::Plan {
                            id: plan.clone().unwrap_or_else(|| "prod_grpc_1".to_owned()),
                            cents: 12.5,
                            name: "Geyser gRPC Shared".to_owned(),
                        },
                    )
                })
                .collect();
            Owing::read(
                &self.store,
                (kept::pin_key("user-100001", name, "prod"), "prod"),
                asked,
                fresh,
            )
        }

        fn confirm(&self, question: &str) -> Result<bool, String> {
            self.line_asked.borrow_mut().push(question.to_owned());
            Ok(if self.line_yes.borrow().is_empty() {
                true
            } else {
                self.line_yes.borrow_mut().remove(0)
            })
        }
    }

    /// A size as the stand-in records it: its cores, none for the
    /// cheapest, 0 for a plan read as none.
    fn size_of(size: Size<'_>) -> Option<u16> {
        match size {
            Size::Cheapest => None,
            Size::Cores(c) => Some(c),
            Size::Unread(_) => Some(0),
        }
    }

    fn app(fake: &Fake) -> App {
        App::at(fake.path.parent().expect("a directory"), "prod")
    }

    async fn go(
        fake: &Fake,
        at: &Where,
        yes: bool,
        (json, terminal): (bool, bool),
    ) -> Result<First, CliError> {
        let m = fake.manifest();
        first_with(fake, &app(fake), (at, yes), &m, (json, terminal)).await
    }

    fn new_server_at(region: Option<&str>) -> Where {
        Where {
            new_vps: true,
            region: region.map(str::to_owned),
            ..Where::default()
        }
    }

    #[tokio::test]
    async fn a_new_server_is_started_in_the_account_with_account_true_written_before_it_is_sent() {
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir, TOML);
        let first = go(&fake, &new_server_at(Some("tokyo")), true, (false, true))
            .await
            .expect("started");
        assert_eq!(first, First::Started);
        // Checked here first, signed in, then started: no picker.
        assert_eq!(*fake.calls.borrow(), ["ready", "sign_in", "owing", "start"]);
        assert_eq!(
            *fake.sent.borrow(),
            [(true, "tokyo".to_owned(), true)],
            "erpc.toml said account = true as the start was sent"
        );
        assert!(fake.kept_there());
    }

    fn planned(region: &str) -> Where {
        Where {
            plan: Some("prod_vps_2".to_owned()),
            ..new_server_at(Some(region))
        }
    }

    #[tokio::test]
    async fn a_plan_is_started_at_its_size_when_it_is_free() {
        let dir = tempfile::tempdir().expect("a directory");
        let mut fake = Fake::new(&dir, TOML);
        fake.plan_cores = Some(2);
        fake.free = Some(vec![(2, "amsterdam"), (4, "amsterdam")]);
        let first = go(&fake, &planned("amsterdam"), false, (false, true))
            .await
            .expect("started");
        assert_eq!(first, First::Started);
        assert_eq!(*fake.sizes.borrow(), [(Some(2), "amsterdam".to_owned())]);
        assert!(fake.kept_there());
        // The stock not read: the size named is started all the same.
        let mut fake = Fake::new(&dir, TOML);
        fake.plan_cores = Some(2);
        go(&fake, &planned("amsterdam"), false, (false, true))
            .await
            .expect("started");
        assert_eq!(*fake.sizes.borrow(), [(Some(2), "amsterdam".to_owned())]);
        // A name that gives no size: refused with the sizes offered, the
        // start asked for none.
        let mut fake = Fake::new(&dir, TOML);
        fake.plan_cores = None;
        let e = go(&fake, &planned("amsterdam"), false, (false, true))
            .await
            .expect_err("refused");
        assert_eq!(e.code, Code::Usage);
        assert_eq!(*fake.sizes.borrow(), [(Some(0), "amsterdam".to_owned())]);
        assert!(!fake.kept_there());
    }

    #[tokio::test]
    async fn a_plan_not_free_is_offered_another_in_turn_each_asked() {
        // The size named has no room: a bigger one there, then the same
        // elsewhere, each asked; a no goes on to the next.
        let dir = tempfile::tempdir().expect("a directory");
        let mut fake = Fake::new(&dir, TOML);
        fake.plan_cores = Some(2);
        fake.free = Some(vec![(4, "amsterdam"), (2, "london")]);
        *fake.answers_yes.borrow_mut() = vec![false, true];
        let _ = crate::node::common::heard::take_printed();
        let first = go(&fake, &planned("amsterdam"), false, (false, true))
            .await
            .expect("started");
        assert_eq!(first, First::Started);
        assert_eq!(
            *fake.sizes.borrow(),
            [
                (Some(4), "amsterdam".to_owned()),
                (Some(2), "london".to_owned())
            ]
        );
        let printed = crate::node::common::heard::take_printed().join("\n");
        assert!(
            printed.contains("ERPC Worker (2 vCPU) in amsterdam, the size --plan names, is not free now; offered in its place: ERPC Worker (4 vCPU) in amsterdam."),
            "{printed}"
        );
        // A yes to the size named, out of stock at the start, then a no to
        // what is offered: erpc.toml keeps the environment in the account
        // since the yes, and the stop says the deploy goes on from there.
        let mut fake = Fake::new(&dir, TOML);
        fake.plan_cores = Some(2);
        fake.free = Some(vec![(2, "amsterdam"), (4, "amsterdam")]);
        *fake.out_of_stock.borrow_mut() = vec![true];
        *fake.answers_yes.borrow_mut() = vec![true, false];
        let e = go(&fake, &planned("amsterdam"), false, (false, true))
            .await
            .expect_err("stopped");
        assert!(fake.kept_there());
        assert!(
            e.hint.as_deref().is_some_and(|h| {
                h.contains("`erpc worker deploy --plan prod_vps_2 --env prod")
                    && h.contains("goes on from where this stopped")
            }),
            "{e:?}"
        );
        // Each declined: stopped, nothing started, what is free said.
        let mut fake = Fake::new(&dir, TOML);
        fake.plan_cores = Some(2);
        fake.free = Some(vec![(4, "amsterdam")]);
        *fake.answers_yes.borrow_mut() = vec![false];
        let e = go(&fake, &planned("amsterdam"), false, (false, true))
            .await
            .expect_err("stopped");
        assert!(
            e.message
                .contains("free now: ERPC Worker (4 vCPU) in amsterdam"),
            "{}",
            e.message
        );
        assert!(!fake.kept_there());
        // An alternative the account does not start: the next asked.
        let mut fake = Fake::new(&dir, TOML);
        fake.plan_cores = Some(2);
        fake.free = Some(vec![(16, "amsterdam"), (2, "london")]);
        go(&fake, &planned("amsterdam"), false, (false, true))
            .await
            .expect("started");
        assert_eq!(
            *fake.sizes.borrow(),
            [
                (Some(16), "amsterdam".to_owned()),
                (Some(2), "london".to_owned())
            ]
        );
        // An alternative out of stock at the start: the next asked.
        let mut fake = Fake::new(&dir, TOML);
        fake.plan_cores = Some(2);
        fake.free = Some(vec![(4, "amsterdam"), (2, "london")]);
        *fake.out_of_stock.borrow_mut() = vec![true];
        go(&fake, &planned("amsterdam"), false, (false, true))
            .await
            .expect("started");
        assert_eq!(
            *fake.sizes.borrow(),
            [
                (Some(4), "amsterdam".to_owned()),
                (Some(2), "london".to_owned())
            ]
        );
        // Out of stock at the start, though listed free: the next asked.
        let mut fake = Fake::new(&dir, TOML);
        fake.plan_cores = Some(2);
        fake.free = Some(vec![(2, "amsterdam"), (2, "london")]);
        *fake.out_of_stock.borrow_mut() = vec![true];
        go(&fake, &planned("amsterdam"), false, (false, true))
            .await
            .expect("started");
        assert_eq!(
            *fake.sizes.borrow(),
            [
                (Some(2), "amsterdam".to_owned()),
                (Some(2), "london".to_owned())
            ]
        );
    }

    #[tokio::test]
    async fn under_yes_a_plan_takes_only_the_size_named() {
        // Not free: stopped, what is free said, nothing started.
        let dir = tempfile::tempdir().expect("a directory");
        let mut fake = Fake::new(&dir, TOML);
        fake.plan_cores = Some(2);
        fake.free = Some(vec![(4, "amsterdam"), (2, "london")]);
        let e = go(&fake, &planned("amsterdam"), true, (false, true))
            .await
            .expect_err("stopped");
        assert!(
            e.message.contains(
                "ERPC Worker (2 vCPU) in amsterdam, the size --plan names, is not free now"
            ) && e.message.contains("ERPC Worker (2 vCPU) in london")
                && e.message.contains("ERPC Worker (4 vCPU) in amsterdam"),
            "{}",
            e.message
        );
        assert!(fake.sizes.borrow().is_empty());
        assert!(!fake.kept_there());
        // Free, then out of stock at the start: stopped, nothing else.
        let mut fake = Fake::new(&dir, TOML);
        fake.plan_cores = Some(2);
        fake.free = Some(vec![(2, "amsterdam"), (2, "london")]);
        *fake.out_of_stock.borrow_mut() = vec![true];
        let e = go(&fake, &planned("amsterdam"), true, (false, true))
            .await
            .expect_err("stopped");
        assert!(e.message.contains("is not free now"), "{}", e.message);
        assert_eq!(*fake.sizes.borrow(), [(Some(2), "amsterdam".to_owned())]);
        // What is free not read, then out of stock: nothing said free.
        let mut fake = Fake::new(&dir, TOML);
        fake.plan_cores = Some(2);
        *fake.out_of_stock.borrow_mut() = vec![true];
        let e = go(&fake, &planned("amsterdam"), true, (false, true))
            .await
            .expect_err("stopped");
        assert!(
            e.message.contains("what is free could not be read")
                && !e.message.contains("free now:"),
            "{}",
            e.message
        );
    }

    #[tokio::test]
    async fn on_a_run_again_yes_takes_only_the_size_named_and_answers_no_price() {
        // --plan --yes, no --new-server: the price asked, and no other size
        // or region offered.
        let dir = tempfile::tempdir().expect("a directory");
        let mut fake = Fake::new(&dir, &kept_toml());
        fake.record = Some(empty_record());
        fake.plan_cores = Some(2);
        fake.free = Some(vec![(4, "amsterdam"), (2, "london")]);
        let at = Where {
            plan: Some("prod_vps_2".to_owned()),
            region: Some("amsterdam".to_owned()),
            ..Where::default()
        };
        let e = go(&fake, &at, true, (false, true))
            .await
            .expect_err("stopped");
        assert!(e.message.contains("is not free now"), "{}", e.message);
        assert!(fake.sizes.borrow().is_empty(), "{:?}", fake.sizes.borrow());
        // Free: started, its price asked.
        fake.free = Some(vec![(2, "amsterdam")]);
        go(&fake, &at, true, (false, true)).await.expect("started");
        assert!(!fake.sent.borrow()[0].2, "asked");
        // Without --yes: what is free offered in turn, as on a first deploy.
        let dir = tempfile::tempdir().expect("a directory");
        let mut fake = Fake::new(&dir, &kept_toml());
        fake.record = Some(empty_record());
        fake.plan_cores = Some(2);
        fake.free = Some(vec![(4, "amsterdam")]);
        go(&fake, &at, false, (false, true)).await.expect("started");
        assert_eq!(*fake.sizes.borrow(), [(Some(4), "amsterdam".to_owned())]);
    }

    #[allow(
        clippy::too_many_lines,
        reason = "each step of a first deploy's lines, one after another"
    )]
    #[tokio::test]
    async fn each_line_is_read_before_anything_and_asked_after_the_servers_price() {
        let grpc = Where {
            lines: vec![(LineKind::Grpc, None)],
            ..new_server_at(None)
        };
        // A plan the hourly catalogue does not offer: refused before
        // anything is made or bought.
        let dir = tempfile::tempdir().expect("a directory");
        let mut fake = Fake::new(&dir, TOML);
        fake.plans_offered = false;
        let e = go(&fake, &grpc, false, (false, true))
            .await
            .expect_err("refused");
        assert_eq!(e.code, Code::Usage);
        assert_eq!(*fake.calls.borrow(), ["ready", "sign_in", "owing"]);
        assert!(!fake.kept_there() && fake.sent.borrow().is_empty());
        // Asked after the server's yes, before its start: kept here, owed,
        // agreed to, then erpc.toml written, then the start sent.
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir, TOML);
        let first = go(&fake, &grpc, false, (false, true))
            .await
            .expect("started");
        assert_eq!(first, First::Started);
        let asked = fake.line_asked.borrow().clone();
        assert_eq!(asked.len(), 1);
        assert!(
            asked[0].contains("gRPC line")
                && asked[0].contains("lets in the ERPC Worker's address"),
            "{}",
            asked[0]
        );
        assert_eq!(fake.lines_kept(), [("grpc".to_owned(), true)]);
        assert!(
            fake.sent.borrow()[0].0,
            "erpc.toml written before the start"
        );
        assert_eq!(*fake.ready_lines.borrow(), [vec![LineKind::Grpc]]);
        // A no to the line: nothing sent, erpc.toml as it was, nothing kept.
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir, TOML);
        fake.line_yes.borrow_mut().push(false);
        let e = go(&fake, &grpc, false, (false, true))
            .await
            .expect_err("declined");
        assert_eq!(e.code, Code::Declined);
        assert!(fake.sent.borrow().is_empty());
        assert!(!fake.kept_there());
        assert!(fake.lines_kept().is_empty());
        // Under --yes: said, not asked.
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir, TOML);
        let _ = crate::node::common::heard::take_printed();
        go(&fake, &grpc, true, (false, true))
            .await
            .expect("started");
        assert!(fake.line_asked.borrow().is_empty());
        let printed = crate::node::common::heard::take_printed().join("\n");
        assert!(printed.contains("Starting a gRPC line"), "{printed}");
        // A no to the line with --plan: no other size is offered for it.
        let dir = tempfile::tempdir().expect("a directory");
        let mut fake = Fake::new(&dir, TOML);
        fake.plan_cores = Some(2);
        fake.free = Some(vec![(2, "amsterdam"), (4, "amsterdam")]);
        fake.line_yes.borrow_mut().push(false);
        let planned_grpc = Where {
            lines: vec![(LineKind::Grpc, None)],
            ..planned("amsterdam")
        };
        let e = go(&fake, &planned_grpc, false, (false, true))
            .await
            .expect_err("declined");
        assert_eq!(e.code, Code::Declined);
        assert_eq!(*fake.sizes.borrow(), [(Some(2), "amsterdam".to_owned())]);
        assert!(!fake.kept_there());
        // A no to the line on a size offered in place of the one named: no
        // further size is offered.
        let dir = tempfile::tempdir().expect("a directory");
        let mut fake = Fake::new(&dir, TOML);
        fake.plan_cores = Some(2);
        fake.free = Some(vec![(4, "amsterdam"), (2, "london")]);
        fake.line_yes.borrow_mut().push(false);
        let e = go(&fake, &planned_grpc, false, (false, true))
            .await
            .expect_err("declined");
        assert_eq!(e.code, Code::Declined);
        assert_eq!(*fake.sizes.borrow(), [(Some(4), "amsterdam".to_owned())]);
        assert!(fake.sent.borrow().is_empty());
        // Asked once, on the first yes, though another size is offered.
        let dir = tempfile::tempdir().expect("a directory");
        let mut fake = Fake::new(&dir, TOML);
        fake.plan_cores = Some(2);
        fake.free = Some(vec![(2, "amsterdam"), (4, "amsterdam")]);
        *fake.out_of_stock.borrow_mut() = vec![true];
        go(&fake, &planned_grpc, false, (false, true))
            .await
            .expect("started");
        assert_eq!(fake.sizes.borrow().len(), 2);
        assert_eq!(fake.line_asked.borrow().len(), 1);
        // A start that went through before this run: nothing asked, the
        // line kept, to be asked when it is started.
        let dir = tempfile::tempdir().expect("a directory");
        let mut fake = Fake::new(&dir, TOML);
        fake.went_through_before = true;
        go(&fake, &grpc, false, (false, true))
            .await
            .expect("started");
        assert!(fake.line_asked.borrow().is_empty());
        assert_eq!(fake.lines_kept(), [("grpc".to_owned(), false)]);
        // On a run again, the lines are asked as the server's price is.
        let dir = tempfile::tempdir().expect("a directory");
        let mut fake = Fake::new(&dir, &kept_toml());
        fake.record = Some(empty_record());
        let at = Where {
            lines: vec![(LineKind::Grpc, None)],
            ..Where::default()
        };
        go(&fake, &at, true, (false, true)).await.expect("started");
        assert_eq!(
            fake.line_asked.borrow().len(),
            1,
            "--yes without --new-server"
        );
        assert_eq!(fake.lines_kept(), [("grpc".to_owned(), true)]);
        // There too, a start that went through before keeps the lines
        // asked, to be asked when they are started.
        let dir = tempfile::tempdir().expect("a directory");
        let mut fake = Fake::new(&dir, &kept_toml());
        fake.record = Some(empty_record());
        fake.went_through_before = true;
        go(&fake, &at, false, (false, true)).await.expect("started");
        assert!(fake.line_asked.borrow().is_empty());
        assert_eq!(fake.lines_kept(), [("grpc".to_owned(), false)]);
        // And one an earlier run agreed to is said there, not asked.
        let dir = tempfile::tempdir().expect("a directory");
        let mut fake = Fake::new(&dir, &kept_toml());
        fake.record = Some(empty_record());
        fake.owe(LineKind::Shreds);
        let _ = crate::node::common::heard::take_printed();
        go(&fake, &Where::default(), false, (false, true))
            .await
            .expect("started");
        assert!(fake.line_asked.borrow().is_empty());
        let printed = crate::node::common::heard::take_printed().join("\n");
        assert!(printed.contains("agreed to on an earlier run"), "{printed}");
        assert_eq!(*fake.ready_lines.borrow(), [vec![LineKind::Shreds]]);
    }

    #[test]
    fn what_is_offered_in_place_of_a_plan_goes_bigger_there_then_nearest_first() {
        let free = [
            (8, "amsterdam"),
            (4, "amsterdam"),
            (2, "tokyo"),
            (2, "frankfurt"),
            (2, "london"),
            (1, "amsterdam"),
        ];
        let (named, others) = offered(2, ("amsterdam", "amsterdam"), Some(&free));
        assert!(!named);
        assert_eq!(
            others,
            [
                (4, "amsterdam"),
                (8, "amsterdam"),
                (2, "london"),
                (2, "frankfurt"),
                (2, "tokyo")
            ]
        );
        // This machine's region first, when it is not the one asked.
        let (_, others) = offered(2, ("amsterdam", "tokyo"), Some(&free));
        assert_eq!(others[2], (2, "tokyo"));
        let (named, others) = offered(2, ("london", "amsterdam"), Some(&free));
        assert!(named);
        assert!(!others.contains(&(2, "london")));
        // Not read: the size named is taken to be free.
        assert_eq!(offered(2, ("london", "london"), None), (true, Vec::new()));
    }

    #[tokio::test]
    async fn a_wallet_apps_first_deploy_goes_the_account_way_too() {
        let dir = tempfile::tempdir().expect("a directory");
        let toml = format!(
            "{TOML}\n[wallet]\nsource = \"keychain:erpc-worker/bot.wallet\"\n\
             pubkey = \"7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU\"\n"
        );
        let fake = Fake::new(&dir, &toml);
        let _ = crate::node::common::heard::take_printed();
        let first = go(&fake, &new_server_at(None), true, (false, true))
            .await
            .expect("started");
        assert_eq!(first, First::Started);
        assert_eq!(*fake.calls.borrow(), ["ready", "sign_in", "owing", "start"]);
        assert!(fake.kept_there());
        let printed = crate::node::common::heard::take_printed().join("\n");
        assert!(!printed.contains("as before"), "{printed}");
        // Under --json, or with nobody at a terminal, it is refused first,
        // as any first deploy the account way is.
        let fake = Fake::new(&dir, &toml);
        let e = go(&fake, &new_server_at(None), true, (true, true))
            .await
            .expect_err("refused");
        assert_eq!(e.code, Code::NeedsTerminal);
        assert!(fake.calls.borrow().is_empty());
    }

    #[tokio::test]
    async fn a_server_picked_at_the_terminal_is_deployed_to_as_before_and_nothing_is_written() {
        let dir = tempfile::tempdir().expect("a directory");
        let mut fake = Fake::new(&dir, TOML);
        fake.picked = Picked::Server(100_001);
        let first = go(&fake, &Where::default(), false, (false, true))
            .await
            .expect("picked");
        assert_eq!(first, First::Picked(100_001));
        assert_eq!(*fake.calls.borrow(), ["ready", "sign_in", "pick"]);
        assert!(!fake.kept_there());
        assert_eq!(std::fs::read_to_string(&fake.path).expect("read"), TOML);
        // A new one picked: started in the account.
        let mut fake = Fake::new(&dir, TOML);
        fake.picked = Picked::New;
        let first = go(&fake, &Where::default(), false, (false, true))
            .await
            .expect("started");
        assert_eq!(first, First::Started);
        assert_eq!(
            *fake.calls.borrow(),
            ["ready", "sign_in", "pick", "owing", "start"]
        );
        assert!(fake.kept_there());
    }

    #[tokio::test]
    async fn a_start_that_went_through_before_this_run_still_writes_account_true() {
        let dir = tempfile::tempdir().expect("a directory");
        let mut fake = Fake::new(&dir, TOML);
        fake.went_through_before = true;
        let first = go(&fake, &new_server_at(None), false, (false, true))
            .await
            .expect("done before");
        assert_eq!(first, First::Started);
        assert!(fake.sent.borrow().is_empty(), "nothing sent, nothing asked");
        assert!(fake.kept_there(), "erpc.toml says so all the same");
    }

    #[tokio::test]
    async fn a_no_to_the_price_leaves_erpc_toml_as_it_was() {
        let dir = tempfile::tempdir().expect("a directory");
        let mut fake = Fake::new(&dir, TOML);
        fake.says_yes = false;
        let e = go(&fake, &new_server_at(None), false, (false, true))
            .await
            .expect_err("declined");
        assert_eq!(e.code, Code::Declined);
        assert!(e.hint.is_none(), "{:?}", e.hint);
        assert_eq!(std::fs::read_to_string(&fake.path).expect("read"), TOML);
    }

    #[tokio::test]
    async fn a_stop_after_account_true_is_written_says_the_deploy_goes_on_from_there() {
        let dir = tempfile::tempdir().expect("a directory");
        let mut fake = Fake::new(&dir, TOML);
        fake.fails_after_yes = true;
        let e = go(&fake, &new_server_at(None), true, (false, true))
            .await
            .expect_err("stopped");
        assert!(fake.kept_there());
        let hint = e.hint.unwrap_or_default();
        assert!(
            hint.contains("`erpc worker deploy --env prod") && hint.contains("goes on"),
            "{hint}"
        );
    }

    #[tokio::test]
    async fn each_refusal_before_anything_reaches_nothing_and_writes_nothing() {
        let dir = tempfile::tempdir().expect("a directory");
        // Nobody at a terminal, or --json: the first login needs one.
        for (json, terminal) in [(true, true), (false, false), (true, false)] {
            let fake = Fake::new(&dir, TOML);
            let e = go(&fake, &new_server_at(None), true, (json, terminal))
                .await
                .expect_err("refused");
            assert_eq!(e.code, Code::NeedsTerminal);
            assert!(e.message.contains("nothing was started"), "{}", e.message);
            assert!(fake.calls.borrow().is_empty(), "{:?}", fake.calls.borrow());
            assert!(!fake.kept_there());
        }
        // A region the account does not name.
        let fake = Fake::new(&dir, TOML);
        let e = go(&fake, &new_server_at(Some("mars")), true, (false, true))
            .await
            .expect_err("refused");
        assert_eq!(e.code, Code::Usage);
        assert!(fake.calls.borrow().is_empty(), "{:?}", fake.calls.borrow());
        // More settings than the account keeps the names of.
        let many =
            (0..=crate::worker::deploy_account::NAMES_MAX).fold(String::new(), |mut vars, i| {
                use std::fmt::Write as _;
                let _ = writeln!(vars, "V{i} = \"x\"");
                vars
            });
        let fake = Fake::new(&dir, &format!("{TOML}\n[vars]\n{many}"));
        let e = go(&fake, &new_server_at(None), true, (false, true))
            .await
            .expect_err("refused");
        assert!(e.message.contains("128"), "{}", e.message);
        assert_eq!(*fake.calls.borrow(), ["ready"]);
        assert!(!fake.kept_there());
        // At the picker: a server of the account picked is deployed to as
        // before, and a new one is refused before it is started.
        let mut fake = Fake::new(&dir, &format!("{TOML}\n[vars]\n{many}"));
        fake.picked = Picked::Server(100_001);
        let first = go(&fake, &Where::default(), true, (false, true))
            .await
            .expect("picked");
        assert_eq!(first, First::Picked(100_001));
        let fake = Fake::new(&dir, &format!("{TOML}\n[vars]\n{many}"));
        let e = go(&fake, &Where::default(), true, (false, true))
            .await
            .expect_err("refused");
        assert!(e.message.contains("128"), "{}", e.message);
        assert_eq!(*fake.calls.borrow(), ["ready", "sign_in", "pick"]);
        assert!(!fake.kept_there());
    }

    #[tokio::test]
    async fn what_the_account_does_not_take_yet_reaches_nothing_and_goes_as_before() {
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir, TOML);
        let lines = Where {
            lines: vec![(LineKind::Udp, None)],
            ..new_server_at(None)
        };
        let first = go(&fake, &lines, true, (true, false))
            .await
            .expect("as before");
        assert_eq!(first, First::AsBefore);
        assert!(fake.calls.borrow().is_empty());
        assert!(!fake.kept_there());
        // At a terminal too, with a line taken off the record alone.
        let forget = Where {
            forget_lines: vec!["200002".to_owned()],
            ..new_server_at(None)
        };
        let first = go(&fake, &forget, true, (false, true))
            .await
            .expect("as before");
        assert_eq!(first, First::AsBefore);
        assert!(fake.calls.borrow().is_empty());
        assert!(!fake.kept_there());
    }

    #[test]
    fn a_deploy_that_started_its_server_is_never_read_as_one_with_none() {
        let app = App::at("apps/bot", "prod");
        let e = held_after(true, None::<()>, &app).expect_err("refused");
        assert!(
            e.message.contains("kept in the ERPC account"),
            "{}",
            e.message
        );
        assert_eq!(
            held_after(false, None::<()>, &app).expect("as before"),
            None
        );
        assert_eq!(held_after(true, Some(7), &app).expect("kept"), Some(7));
    }

    fn kept_toml() -> String {
        format!("{TOML}\n[env.prod]\naccount = true\n")
    }

    #[allow(
        clippy::too_many_lines,
        reason = "each way a run that stopped is run again, one after another"
    )]
    #[tokio::test]
    async fn a_run_that_stopped_is_resumed_only_while_the_account_names_nothing() {
        let dir = tempfile::tempdir().expect("a directory");
        // A record naming nothing, as a first deploy that stopped leaves
        // it: started, the price asked unless --new-server came with --yes.
        for (new_vps, yes, said) in [
            (false, true, false),
            (true, true, true),
            (true, false, false),
        ] {
            let mut fake = Fake::new(&dir, &kept_toml());
            fake.record = Some(empty_record());
            let at = Where {
                new_vps,
                ..Where::default()
            };
            let first = go(&fake, &at, yes, (false, true)).await.expect("started");
            assert_eq!(first, First::Started);
            assert_eq!(
                *fake.calls.borrow(),
                ["sign_in", "record", "owing", "ready", "start"]
            );
            assert_eq!(fake.sent.borrow()[0].2, said, "{new_vps} {yes}");
        }
        // No record at all: another account's, or deleted. Refused as
        // before, nothing asked or started, unless --new-server asks for a
        // new server in the account signed in to.
        let fake = Fake::new(&dir, &kept_toml());
        let e = go(&fake, &Where::default(), true, (false, true))
            .await
            .expect_err("refused");
        assert_eq!(e.code, Code::Failed);
        assert!(
            e.message
                .contains("the ERPC account you are signed in to has no record"),
            "{}",
            e.message
        );
        assert!(
            e.hint.unwrap_or_default().contains("erpc login"),
            "the account it was made in"
        );
        assert_eq!(*fake.calls.borrow(), ["sign_in", "record"]);
        for (yes, said) in [(true, true), (false, false)] {
            let fake = Fake::new(&dir, &kept_toml());
            let first = go(&fake, &new_server_at(None), yes, (false, true))
                .await
                .expect("started");
            assert_eq!(first, First::Started);
            assert_eq!(fake.sent.borrow()[0].2, said);
        }
        // More settings than the account keeps the names of: refused before
        // the start.
        let many =
            (0..=crate::worker::deploy_account::NAMES_MAX).fold(String::new(), |mut vars, i| {
                use std::fmt::Write as _;
                let _ = writeln!(vars, "V{i} = \"x\"");
                vars
            });
        let mut fake = Fake::new(&dir, &format!("{}\n[vars]\n{many}", kept_toml()));
        fake.record = Some(empty_record());
        let e = go(&fake, &new_server_at(None), true, (false, true))
            .await
            .expect_err("refused");
        assert!(e.message.contains("128"), "{}", e.message);
        assert_eq!(
            *fake.calls.borrow(),
            ["sign_in", "record", "owing", "ready"]
        );
        // A record that names a server: deployed to as before, nothing
        // started.
        let mut fake = Fake::new(&dir, &kept_toml());
        fake.record = Some(record_with_server());
        let first = go(&fake, &new_server_at(None), true, (false, true))
            .await
            .expect("as before");
        assert_eq!(first, First::AsBefore);
        assert_eq!(*fake.calls.borrow(), ["sign_in", "record"]);
        // Nobody at a terminal: refused, nothing started.
        let mut fake = Fake::new(&dir, &kept_toml());
        fake.record = Some(empty_record());
        let e = go(&fake, &Where::default(), true, (true, true))
            .await
            .expect_err("refused");
        assert_eq!(e.code, Code::NeedsTerminal);
        assert_eq!(*fake.calls.borrow(), ["sign_in", "record"]);
        // What a deploy there does not take: as before, unread.
        let fake = Fake::new(&dir, &kept_toml());
        let lines = Where {
            lines: vec![(LineKind::Udp, None)],
            ..Where::default()
        };
        let first = go(&fake, &lines, true, (false, true))
            .await
            .expect("as before");
        assert_eq!(first, First::AsBefore);
        assert!(fake.calls.borrow().is_empty());
    }

    #[allow(
        clippy::too_many_lines,
        reason = "each way a line is owed, or not, one after another"
    )]
    #[tokio::test]
    async fn a_line_asked_or_kept_here_before_the_first_deploy_is_owed_once_the_deploy_is_checked()
    {
        let dir = tempfile::tempdir().expect("a directory");
        let grpc = Where {
            lines: vec![(LineKind::Grpc, None)],
            ..Where::default()
        };
        // Asked of one whose server was started and never deployed to:
        // owed, once what refuses the deploy is checked, and kept here, to
        // be asked when it is started.
        let mut fake = Fake::new(&dir, &kept_toml());
        fake.record = Some(record_with_server());
        let first = go(&fake, &grpc, true, (false, true)).await.expect("owed");
        assert_eq!(first, First::Owed);
        assert_eq!(
            *fake.calls.borrow(),
            ["sign_in", "record", "owing", "ready"]
        );
        assert_eq!(fake.lines_kept(), [("grpc".to_owned(), false)]);
        // Refused first with nobody at a terminal, nothing kept.
        let dir = tempfile::tempdir().expect("a directory");
        let mut fake = Fake::new(&dir, &kept_toml());
        fake.record = Some(record_with_server());
        let e = go(&fake, &grpc, true, (true, true))
            .await
            .expect_err("refused");
        assert_eq!(e.code, Code::NeedsTerminal);
        assert!(fake.lines_kept().is_empty());
        // Kept here by an earlier run, nothing on the command line: owed,
        // as the plain deploy a stop names goes on.
        let mut fake = Fake::new(&dir, &kept_toml());
        fake.record = Some(record_with_server());
        fake.owe(LineKind::Grpc);
        let first = go(&fake, &Where::default(), false, (false, true))
            .await
            .expect("owed");
        assert_eq!(first, First::Owed);
        assert_eq!(fake.lines_kept(), [("grpc".to_owned(), true)]);
        // The deploy's checks see the line kept here as one asked: a
        // setting it gives does not refuse the deploy.
        assert_eq!(*fake.ready_lines.borrow(), [vec![LineKind::Grpc]]);
        // Neither asked nor kept here: as before.
        let dir = tempfile::tempdir().expect("a directory");
        let mut fake = Fake::new(&dir, &kept_toml());
        fake.record = Some(record_with_server());
        let first = go(&fake, &Where::default(), false, (false, true))
            .await
            .expect("as before");
        assert_eq!(first, First::AsBefore);
        // With anything else for a server (--new-server, --region,
        // --plan), on a record with no server, or once deployed to: as
        // before, refused by the deploy that follows.
        let mut deployed = record_with_server();
        deployed.deployed = Some(erpc_api::worker::Deployed::new(
            "r1",
            "2026-11-27T00:00:00Z",
        ));
        let mut address_only = empty_record();
        address_only.facts.host = Some("203.0.113.10".to_owned());
        for (at, record) in [
            (
                Where {
                    new_vps: true,
                    ..grpc.clone()
                },
                record_with_server(),
            ),
            (
                Where {
                    region: Some("tokyo".to_owned()),
                    ..grpc.clone()
                },
                record_with_server(),
            ),
            (
                Where {
                    plan: Some("prod_vps_2".to_owned()),
                    ..grpc.clone()
                },
                record_with_server(),
            ),
            (grpc.clone(), address_only),
            (grpc.clone(), deployed),
        ] {
            let mut fake = Fake::new(&dir, &kept_toml());
            fake.record = Some(record);
            let first = go(&fake, &at, true, (false, true))
                .await
                .expect("as before");
            assert_eq!(first, First::AsBefore, "{at:?}");
            assert!(fake.lines_kept().is_empty());
        }
        // One moved in, never deployed to: owed the same.
        let mut moved = record_with_server();
        moved.servers[0].hourly = false;
        let mut fake = Fake::new(&dir, &kept_toml());
        fake.record = Some(moved);
        let first = go(&fake, &grpc, true, (false, true)).await.expect("owed");
        assert_eq!(first, First::Owed);
        // What refuses the deploy refuses before a line is owed: more
        // settings than the account keeps, a server coming in.
        let many =
            (0..=crate::worker::deploy_account::NAMES_MAX).fold(String::new(), |mut vars, i| {
                use std::fmt::Write as _;
                let _ = writeln!(vars, "V{i} = \"x\"");
                vars
            });
        let dir = tempfile::tempdir().expect("a directory");
        let mut fake = Fake::new(&dir, &format!("{}\n[vars]\n{many}", kept_toml()));
        fake.record = Some(record_with_server());
        let e = go(&fake, &grpc, true, (false, true))
            .await
            .expect_err("refused");
        assert!(e.message.contains("128"), "{}", e.message);
        assert!(fake.lines_kept().is_empty());
        let mut coming = record_with_server();
        coming.servers[0].slot = erpc_api::worker::Slot::Outgoing;
        let mut fake = Fake::new(&dir, &kept_toml());
        fake.record = Some(coming);
        let e = go(&fake, &grpc, true, (false, true))
            .await
            .expect_err("refused");
        assert!(e.message.contains("going out"), "{}", e.message);
        assert!(fake.lines_kept().is_empty());
    }

    fn empty_record() -> EnvDetail {
        let mut record = record_with_server();
        record.servers.clear();
        record
    }

    fn record_with_server() -> EnvDetail {
        serde_json::from_value(serde_json::json!({
            "name": "prod", "revision": 1, "factsFormat": 2,
            "facts": { "desiredCores": null, "host": null, "sshUser": null,
                "sshPort": null, "hostKey": null,
                "firewall": { "sshAllow": [], "appAllow": [] }, "starting": {},
                "backup": null },
            "servers": [{ "id": "0b8e7c52-91d4-4f6a-8e23-7d1a5c9b3e60",
                "slot": "active", "cores": 1, "memoryGb": 2, "region": "amsterdam",
                "hourly": true, "appRunning": false, "state": "provisioning" }],
            "desiredCores": null, "activeCores": null, "coreOptions": [], "lines": [],
            "refStates": { "backup": null }, "deployed": null, "deployedApp": null,
            "updatedAt": "2026-11-24T12:00:00.000Z"
        }))
        .expect("an environment")
    }

    fn fresh() -> Where {
        Where::default()
    }

    #[test]
    fn a_new_server_for_an_environment_with_nothing_yet_goes_to_the_account() {
        let new = Where {
            new_vps: true,
            ..fresh()
        };
        let at_terminal = (false, true);
        // No table, or an empty one: --new-server, or the picker.
        for env in [None, Some(Env::default())] {
            assert_eq!(
                way(env.as_ref(), &new, at_terminal),
                Way::New { asked: true }
            );
            assert_eq!(
                way(env.as_ref(), &fresh(), at_terminal),
                Way::New { asked: false }
            );
        }
        // --region goes with it.
        let tokyo = Where {
            region: Some("tokyo".to_owned()),
            ..new.clone()
        };
        assert_eq!(way(None, &tokyo, at_terminal), Way::New { asked: true });
    }

    #[test]
    fn what_names_where_it_goes_or_is_kept_goes_as_before() {
        let at_terminal = (false, true);
        let named = [
            Where {
                host: Some("203.0.113.7".to_owned()),
                ..fresh()
            },
            Where {
                vps: Some(100_001),
                ..fresh()
            },
            Where {
                inline: true,
                new_vps: true,
                ..fresh()
            },
            Where {
                vault: Some("v".to_owned()),
                new_vps: true,
                ..fresh()
            },
        ];
        for at in &named {
            assert_eq!(way(None, at, at_terminal), Way::AsBefore, "{at:?}");
        }
        // Anything in the table: a server, an address, a start on record,
        // a 1Password item, a firewall list.
        let mut with_lists = Env::default();
        with_lists.firewall.app_allow =
            vec![erpc_worker::net::Cidr::parse_any("203.0.113.0/24").expect("a network")];
        let tables = [
            Env {
                host: Some("203.0.113.7".to_owned()),
                ..Env::default()
            },
            Env {
                inventory: Some(erpc_worker::manifest::Inventory {
                    vault: "v".to_owned(),
                }),
                ..Env::default()
            },
            with_lists,
        ];
        let new = Where {
            new_vps: true,
            ..fresh()
        };
        for env in &tables {
            assert_eq!(way(Some(env), &new, at_terminal), Way::AsBefore);
        }
        // Nobody to pick and nothing asked for: refused as before.
        assert_eq!(way(None, &fresh(), (false, false)), Way::AsBefore);
    }

    #[test]
    fn what_the_account_does_not_take_yet_goes_as_before_and_is_said() {
        let new = || Where {
            new_vps: true,
            ..fresh()
        };
        let at_terminal = (false, true);
        // A gRPC, Shreds or Unlimited RPC line goes the account way, at a
        // terminal only.
        for kind in [LineKind::Grpc, LineKind::Shreds, LineKind::Unlimited] {
            let line = Where {
                lines: vec![(kind, None)],
                ..new()
            };
            assert_eq!(way(None, &line, at_terminal), Way::New { asked: true });
            assert_eq!(way(None, &line, (true, false)), Way::NeedsTerminal);
        }
        // A UDP Forwarding line, or one of its options, goes as before.
        let lines = Where {
            lines: vec![(LineKind::Grpc, None), (LineKind::Udp, None)],
            ..new()
        };
        assert_eq!(way(None, &lines, at_terminal), Way::Said(Why::Lines));
        // Without a terminal too: as before, where --yes answers all.
        assert_eq!(way(None, &lines, (true, false)), Way::Said(Why::Lines));
        for udp in [
            Where {
                udp_port: Some(10_001),
                ..new()
            },
            Where {
                udp_region: Some("tokyo".to_owned()),
                ..new()
            },
            Where {
                udp_any_source: true,
                ..new()
            },
        ] {
            assert_eq!(way(None, &udp, at_terminal), Way::Said(Why::Lines));
        }
        // A line taken off the record is a line asked about too.
        let forget = Where {
            forget_lines: vec!["200002".to_owned()],
            ..new()
        };
        assert_eq!(way(None, &forget, at_terminal), Way::Said(Why::Lines));
        let plan = Where {
            plan: Some("vps-1".to_owned()),
            ..new()
        };
        // --plan goes the account way, at a terminal only.
        assert_eq!(way(None, &plan, at_terminal), Way::New { asked: true });
        assert_eq!(way(None, &plan, (true, false)), Way::NeedsTerminal);
        assert!(why_said(Why::Lines).contains("UDP Forwarding line"));
    }

    #[test]
    fn a_new_server_with_nobody_at_a_terminal_or_under_json_is_refused_first() {
        let new = Where {
            new_vps: true,
            ..fresh()
        };
        for (json, terminal) in [(true, true), (false, false), (true, false)] {
            assert_eq!(
                way(None, &new, (json, terminal)),
                Way::NeedsTerminal,
                "{json} {terminal}"
            );
        }
        // The picker under --json too.
        assert_eq!(way(None, &fresh(), (true, true)), Way::NeedsTerminal);
    }

    #[test]
    fn an_environment_kept_in_the_account_is_resumed_whatever_is_asked() {
        let kept = crate::worker::EnvRecord::kept_in_account();
        for at in [
            fresh(),
            Where {
                new_vps: true,
                ..fresh()
            },
        ] {
            for (json, terminal) in [(false, true), (true, false)] {
                assert_eq!(way(Some(&kept), &at, (json, terminal)), Way::Resume);
            }
        }
    }

    #[test]
    fn what_a_started_deploy_goes_on_with_is_taken_by_the_deploy_to_the_account() {
        let app = App::at("apps/bot", "prod");
        let kept = crate::worker::EnvRecord::kept_in_account();
        // Every command line a first deploy starts a server for, or a run
        // that stopped goes on from, with what else it may carry.
        let asked = [
            Where::default(),
            Where {
                new_vps: true,
                ..Where::default()
            },
            Where {
                new_vps: true,
                region: Some("tokyo".to_owned()),
                ..Where::default()
            },
            Where {
                region: Some("tokyo".to_owned()),
                upto: crate::worker::deploy::Upto::Prepared,
                ..Where::default()
            },
            Where {
                plan: Some("prod_vps_2".to_owned()),
                lines: vec![(LineKind::Grpc, None)],
                ..Where::default()
            },
        ];
        for at in asked {
            let routed = [
                way(None, &at, (false, true)),
                way(Some(&kept), &at, (false, true)),
            ];
            assert!(
                matches!(routed, [Way::New { .. }, Way::Resume]),
                "{at:?}: {routed:?}"
            );
            let mut after = at.clone();
            after_started(&mut after);
            assert!(
                crate::worker::deploy_account::refuse_options(&after, &app).is_ok(),
                "{at:?}"
            );
            // Not taken as it was, when it asked for a new server, a
            // region, a plan or a line.
            if at.new_vps || at.region.is_some() || at.plan.is_some() || !at.lines.is_empty() {
                assert!(crate::worker::deploy_account::refuse_options(&at, &app).is_err());
            }
        }
    }

    #[test]
    fn only_a_record_that_names_nothing_is_started_for() {
        let record = |servers: serde_json::Value, host: Option<&str>, deployed: bool| {
            let mut value = serde_json::json!({
                "name": "prod", "revision": 1, "factsFormat": 2,
                "facts": { "desiredCores": null, "host": host, "sshUser": null,
                    "sshPort": null, "hostKey": null,
                    "firewall": { "sshAllow": [], "appAllow": [] }, "starting": {},
                    "backup": null },
                "servers": servers, "desiredCores": null, "activeCores": null,
                "coreOptions": [], "lines": [], "refStates": { "backup": null },
                "deployed": null, "deployedApp": null,
                "updatedAt": "2026-11-24T12:00:00.000Z"
            });
            if deployed {
                value["deployed"] =
                    serde_json::json!({ "release": "r1", "at": "2026-11-25T08:00:00.000Z" });
            }
            serde_json::from_value::<EnvDetail>(value).expect("an environment")
        };
        let server = serde_json::json!([{ "id": "0b8e7c52-91d4-4f6a-8e23-7d1a5c9b3e60",
            "slot": "active", "cores": 1, "memoryGb": 2, "region": "amsterdam",
            "hourly": true, "appRunning": false, "state": "provisioning" }]);
        assert!(!names_something(&record(
            serde_json::json!([]),
            None,
            false
        )));
        assert!(names_something(&record(server, None, false)));
        // An address and no server, or a deploy on record: as `server end`
        // leaves one, which a deploy still refuses as before.
        assert!(names_something(&record(
            serde_json::json!([]),
            Some("203.0.113.7"),
            false
        )));
        assert!(names_something(&record(serde_json::json!([]), None, true)));
    }

    #[test]
    fn the_region_is_one_the_account_names_or_the_nearest() {
        let asked = Where {
            region: Some("tokyo".to_owned()),
            ..fresh()
        };
        assert_eq!(region(&asked).expect("a region"), Region::Asked("tokyo"));
        let odd = Where {
            region: Some("mars".to_owned()),
            ..fresh()
        };
        let e = region(&odd).expect_err("not a region");
        assert_eq!(e.code, Code::Usage);
        assert!(e.message.contains("amsterdam"), "{}", e.message);
        match region(&fresh()).expect("a region") {
            Region::Else(r) => assert!(crate::worker::vps::REGIONS.contains(&r), "{r}"),
            other @ Region::Asked(_) => panic!("{other:?}"),
        }
    }

    #[test]
    fn account_true_is_written_once_and_never_over_a_table_that_holds_something() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = dir.path().join("erpc.toml");
        let base = "name = \"bot\"\nchain = \"solana\"\n\n[run]\nport = 3000\n";
        std::fs::write(&path, base).expect("written");
        let app = App::at(dir.path(), "prod");
        keep_in_account(&path, &app, "bot").expect("written");
        let m = Manifest::load(&path).expect("reads");
        assert!(kept::kept_there(&m, "prod"));
        // Again: nothing to do.
        let before = std::fs::read_to_string(&path).expect("read");
        keep_in_account(&path, &app, "bot").expect("as it is");
        assert_eq!(std::fs::read_to_string(&path).expect("read"), before);
        // A table that holds a server since is not written over.
        std::fs::write(
            &path,
            format!("{base}\n[env.prod]\nhost = \"203.0.113.7\"\n"),
        )
        .expect("written");
        let e = keep_in_account(&path, &app, "bot").expect_err("refused");
        assert!(e.message.contains("prod"), "{}", e.message);
        assert!(
            !kept::kept_there(&Manifest::load(&path).expect("reads"), "prod"),
            "left as it was"
        );
    }

    #[test]
    fn every_region_this_machine_may_be_near_is_one_the_account_starts_in() {
        let help = crate::cli::i18n::CATALOG
            .get(
                erpc_core::i18n::Lang::En,
                "cli_worker.worker server start --region",
                &[],
            )
            .expect("the help of --region");
        for region in crate::worker::vps::REGIONS {
            assert!(help.contains(region), "{region}: {help}");
        }
        for zone in [
            "Asia/Tokyo",
            "Asia/Hong_Kong",
            "Asia/Dubai",
            "Australia/Sydney",
            "America/New_York",
            "Europe/London",
            "Europe/Amsterdam",
            "Europe/Berlin",
            "Africa/Lagos",
            "Japan",
            "",
            "UTC",
        ] {
            let region = crate::worker::vps::region_for_zone(zone);
            assert!(
                crate::worker::vps::REGIONS.contains(&region),
                "{zone}: {region}"
            );
        }
    }
}
