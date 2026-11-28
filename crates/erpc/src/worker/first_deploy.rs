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
//! does not take yet (a data line, `--plan`) or whose app names a wallet
//! (whose record in the account this erpc does not make yet), and it says
//! why.
//!
//! Everything that would refuse the deploy is asked before anything is
//! written or bought: a terminal and no `--json` (the first login is asked
//! there only), what the deploy needs on this machine, the sign-in. The
//! account's records of the app and the environment are made when missing
//! (free, said on stderr); the price is said and asked (`--yes` says it on
//! stderr instead); then `erpc.toml` gets `account = true`, and only then
//! is the start sent, under a key kept on this machine.
//!
//! A run that stopped is run again: an environment `erpc.toml` keeps in the
//! account whose record names no server, no address, no line and no
//! deploy goes the same way, a start kept on this machine or open in the
//! account first, and buys no second server. There `--yes` answers the
//! price only with `--new-server`. One the account signed in to has no
//! record of at all (another account's, or deleted: a first deploy makes
//! the records before it writes `account = true`) is refused as before,
//! unless `--new-server` asks for a new server in the account signed in to.

use std::path::{Path, PathBuf};

use erpc_api::worker::{Code as AccountCode, EnvDetail, WorkerError};
use erpc_worker::manifest::{Env, Manifest};

use crate::cli::error::{CliError, Code};
use crate::node::common::Say;
use crate::worker::App;
use crate::worker::account::{self as kept, Account};
use crate::worker::deploy::{Picked, Where};
use crate::worker::server::Region;

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
    /// on the account's record: the deploy to it follows.
    Started,
}

/// Why a first deploy keeps the environment in `erpc.toml`, as before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Why {
    /// A data line asked for.
    Lines,
    /// `--plan`.
    Plan,
    /// A wallet in `erpc.toml`.
    Wallet,
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
/// table for it) goes, asked as `at` asks, for an app with a wallet or
/// not, under `--json` or not, at a terminal or not.
fn way(env: Option<&Env>, wallet: bool, at: &Where, (json, terminal): (bool, bool)) -> Way {
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
    let lines = !at.lines.is_empty()
        || at.udp_port.is_some()
        || at.udp_region.is_some()
        || at.udp_any_source
        || !at.forget_lines.is_empty();
    if lines {
        return Way::Said(Why::Lines);
    }
    if at.plan.is_some() {
        return Way::Said(Why::Plan);
    }
    if wallet {
        return Way::Said(Why::Wallet);
    }
    if json || !terminal {
        return Way::NeedsTerminal;
    }
    Way::New { asked: at.new_vps }
}

/// Why, as the note says it.
fn why_said(why: Why) -> String {
    match why {
        Why::Lines => t!("worker_first_deploy.why_lines"),
        Why::Plan => t!("worker_first_deploy.why_plan"),
        Why::Wallet => t!("worker_first_deploy.why_wallet"),
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
    /// Starts its server in `region` ([`crate::worker::server::for_deploy`]),
    /// `yes` answering the price, `agreed` run after the yes and before the
    /// start is sent; what the account then keeps, said.
    async fn start(
        &self,
        app: &App,
        m: &Manifest,
        asked: (Region<'_>, bool),
        agreed: impl FnOnce() -> Result<(), CliError>,
    ) -> Result<String, CliError>;
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
        (region, yes): (Region<'_>, bool),
        agreed: impl FnOnce() -> Result<(), CliError>,
    ) -> Result<String, CliError> {
        crate::worker::server::for_deploy(self.signed()?, app, m, (region, yes), agreed).await
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
    match way(m.env.get(env), m.wallet.is_some(), at, (json, terminal)) {
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
    let written = core::cell::Cell::new(false);
    let started = reach
        .start(app, &m, (region, yes), || {
            keep_in_account(&path, app, &m.name)?;
            written.set(true);
            Ok(())
        })
        .await;
    let text = match started {
        Ok(text) => text,
        // Once erpc.toml keeps it in the account, a stop says the deploy
        // goes on from there.
        Err(e) if written.get() => {
            return Err(and_hint(
                e,
                t!(
                    "worker_first_deploy.kept_now_hint",
                    env = app.env.as_str(),
                    scope = app.scope()
                ),
            ));
        }
        Err(e) => return Err(e),
    };
    // A start this machine kept that went through before this run sends
    // nothing and asks nothing: erpc.toml is made to say so now.
    keep_in_account(&path, app, &m.name)?;
    Say { quiet: false }.line(&text);
    Ok(First::Started)
}

/// An environment `erpc.toml` keeps in the account: started for as a new
/// one is when the account's record names no server, no address, no line
/// and no deploy, or, with `--new-server`, when the account has no record
/// of it; refused as before when it has none and nothing asked for a new
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
    // What a deploy there does not take is refused as before, unread.
    if crate::worker::deploy_account::refuse_options(&start, app).is_err() {
        return Ok(First::AsBefore);
    }
    let region = region(at)?;
    reach.sign_in().await?;
    let env = app.env.as_str();
    match reach.record(app, &m.name).await? {
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
        return Err(CliError::new(
            Code::NeedsTerminal,
            t!("worker_first_deploy.resume_needs_terminal", env),
        )
        .hint(t!(
            "worker_first_deploy.resume_needs_terminal_hint",
            scope = app.scope()
        )));
    }
    let checked = Where {
        kept: Some(m.clone()),
        ..start
    };
    let (_, m) = reach.ready(app, &checked)?;
    crate::worker::deploy_account::deployed_app(&m)?;
    // Nothing on this command line picked a new server: the price is asked.
    let yes = yes && at.new_vps;
    let text = reach.start(app, &m, (region, yes), || Ok(())).await?;
    Say { quiet: false }.line(&text);
    Ok(First::Started)
}

/// The deploy's options once its server was started here ([`First::Started`]):
/// `--new-server` and `--region` were for the start, and the deploy to an
/// environment kept in the account that follows refuses both
/// ([`crate::worker::deploy_account::refuse_options`]).
pub(crate) fn after_started(at: &mut Where) {
    at.new_vps = false;
    at.region = None;
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
            }
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
            (region, yes): (Region<'_>, bool),
            agreed: impl FnOnce() -> Result<(), CliError>,
        ) -> Result<String, CliError> {
            self.calls.borrow_mut().push("start");
            let region = match region {
                Region::Asked(r) | Region::Else(r) => r.to_owned(),
            };
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
            self.sent
                .borrow_mut()
                .push((self.kept_there(), region, yes));
            if self.fails_after_yes {
                return Err(CliError::new(Code::Failed, "no answer".to_owned()));
            }
            Ok("Started a new server for environment prod.".to_owned())
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
        assert_eq!(*fake.calls.borrow(), ["ready", "sign_in", "start"]);
        assert_eq!(
            *fake.sent.borrow(),
            [(true, "tokyo".to_owned(), true)],
            "erpc.toml said account = true as the start was sent"
        );
        assert!(fake.kept_there());
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
        assert_eq!(*fake.calls.borrow(), ["ready", "sign_in", "pick", "start"]);
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
            lines: vec![(LineKind::Grpc, None)],
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
                ["sign_in", "record", "ready", "start"]
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
        assert_eq!(*fake.calls.borrow(), ["sign_in", "record", "ready"]);
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
            lines: vec![(LineKind::Grpc, None)],
            ..Where::default()
        };
        let first = go(&fake, &lines, true, (false, true))
            .await
            .expect("as before");
        assert_eq!(first, First::AsBefore);
        assert!(fake.calls.borrow().is_empty());
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
                way(env.as_ref(), false, &new, at_terminal),
                Way::New { asked: true }
            );
            assert_eq!(
                way(env.as_ref(), false, &fresh(), at_terminal),
                Way::New { asked: false }
            );
        }
        // --region goes with it.
        let tokyo = Where {
            region: Some("tokyo".to_owned()),
            ..new.clone()
        };
        assert_eq!(
            way(None, false, &tokyo, at_terminal),
            Way::New { asked: true }
        );
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
            assert_eq!(way(None, false, at, at_terminal), Way::AsBefore, "{at:?}");
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
            assert_eq!(way(Some(env), false, &new, at_terminal), Way::AsBefore);
        }
        // Nobody to pick and nothing asked for: refused as before.
        assert_eq!(way(None, false, &fresh(), (false, false)), Way::AsBefore);
    }

    #[test]
    fn what_the_account_does_not_take_yet_goes_as_before_and_is_said() {
        let new = || Where {
            new_vps: true,
            ..fresh()
        };
        let at_terminal = (false, true);
        let lines = Where {
            lines: vec![(LineKind::Grpc, None)],
            ..new()
        };
        assert_eq!(way(None, false, &lines, at_terminal), Way::Said(Why::Lines));
        // Without a terminal too: as before, where --yes answers all.
        assert_eq!(
            way(None, false, &lines, (true, false)),
            Way::Said(Why::Lines)
        );
        // A line taken off the record is a line asked about too.
        let forget = Where {
            forget_lines: vec!["200002".to_owned()],
            ..new()
        };
        assert_eq!(
            way(None, false, &forget, at_terminal),
            Way::Said(Why::Lines)
        );
        let plan = Where {
            plan: Some("vps-1".to_owned()),
            ..new()
        };
        assert_eq!(way(None, false, &plan, at_terminal), Way::Said(Why::Plan));
        assert_eq!(way(None, true, &new(), at_terminal), Way::Said(Why::Wallet));
        // Each is said in words of its own.
        let said: Vec<String> = [Why::Lines, Why::Plan, Why::Wallet]
            .into_iter()
            .map(why_said)
            .collect();
        assert!(said[0].contains("data line"), "{}", said[0]);
        assert!(said[1].contains("--plan"), "{}", said[1]);
        assert!(said[2].contains("wallet"), "{}", said[2]);
    }

    #[test]
    fn a_new_server_with_nobody_at_a_terminal_or_under_json_is_refused_first() {
        let new = Where {
            new_vps: true,
            ..fresh()
        };
        for (json, terminal) in [(true, true), (false, false), (true, false)] {
            assert_eq!(
                way(None, false, &new, (json, terminal)),
                Way::NeedsTerminal,
                "{json} {terminal}"
            );
        }
        // The picker under --json too.
        assert_eq!(way(None, false, &fresh(), (true, true)), Way::NeedsTerminal);
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
                assert_eq!(way(Some(&kept), false, &at, (json, terminal)), Way::Resume);
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
        ];
        for at in asked {
            let routed = [
                way(None, false, &at, (false, true)),
                way(Some(&kept), false, &at, (false, true)),
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
            // Not taken as it was, when it asked for a new server or a
            // region.
            if at.new_vps || at.region.is_some() {
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
