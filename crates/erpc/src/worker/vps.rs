// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The ERPC servers `erpc worker deploy` puts a worker on: a VPS the
//! account has, or a new one started by the hour.
//!
//! A new one is the cheapest VPS plan the hourly catalogue offers, in the
//! region nearest this machine. Nearest is read from the machine's time
//! zone: user-api names no per-region host erpc could time, and erpc asks
//! no outside service where the operator is. `--region` and `--plan`
//! choose otherwise. Starting it, waiting for it, and making it key-only
//! go through the same steps `erpc ai` uses. A start shows the price and
//! the balance, which user-api gives, and is answered by the person at the
//! terminal, or by `--yes` on a deploy, which says them and goes ahead.
//! Ending one is the person's to answer, but for what `erpc worker delete
//! --release-server --yes` names: that command line is the yes, and each
//! end is said.
//!
//! A data line (an hourly gRPC, Shreds, UDP Forwarding or Unlimited RPC
//! line) is started for the server the same way, at the cheapest plan
//! unless one is asked for. It lets in the server's address only, and
//! takes no token. A gRPC or Shreds line is told the address when it
//! starts; an Unlimited RPC is started in the server's region, and its
//! whitelist is set after. A UDP Forwarding line is the other way about:
//! ERPC sends the leader's raw shreds from a node in a region to a UDP port
//! of the server's own, so the line is pointed at the server's address and
//! port once it is started, and the addresses it sends from (`sources`) go
//! on record for the server's firewall to let in. It comes as two
//! products, Standard and Premium, each its own hourly family with its own
//! list; which one a line is comes from the list it is in, never from the
//! record.
//!
//! A start's request is kept on record from before it leaves until its
//! outcome is known ([`StartRecord`]), so that one that got no answer is
//! sent again with the same key and never with a new one. What each answer
//! does to it is [`Answer`].

use erpc_ai::actions::StartError;
use erpc_ai::confirm::Confirm;
use erpc_ai::servers::Servers as _;
use erpc_ai::session::Access as _;
use erpc_api::udp::{
    FAMILIES as UDP_FAMILIES, FAMILY_NAMES as UDP_FAMILY_NAMES, Family as UdpFamily,
    family_of as udp_family_of, is_row_of,
};
use erpc_api::{account, hourly};
use erpc_auth::AuthClient;
use erpc_ssh::Target;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

use erpc_worker::manifest::{Env, Line, LineKind, Resource, ResourceKind, Start};
use secrecy::SecretString;
use serde_json::{Value, json};

use crate::cli::error::{CliError, Code};
use crate::node::common::Say;

/// The regions a VPS can be started in.
pub(crate) const REGIONS: [&str; 7] = [
    "amsterdam",
    "frankfurt",
    "london",
    "ny",
    "tokyo",
    "singapore",
    "sydney",
];

/// What an ERPC server is made of, as the account or its product's name
/// gives it; what neither gives is left out.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Spec {
    /// Its vCPUs.
    pub(crate) cores: Option<u16>,
    /// Its memory, in GB.
    pub(crate) memory_gb: Option<u32>,
    /// Its disk, in GB.
    pub(crate) disk_gb: Option<u32>,
    /// What its disk is.
    pub(crate) disk: Disk,
}

/// What a server's disk is, as its product's name says.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Disk {
    /// `NVMe`.
    Nvme,
    /// SSD.
    Ssd,
    /// Not said.
    #[default]
    Unsaid,
}

/// The words a product's own name, before its first ` - `, may hold: those
/// of the names the account's servers are sold under. Any other word there
/// gives no spec.
const NAME_WORDS: [&str; 8] = ["🛰️", "🛰", "slv", "vps", "super", "premium", "max", "plus"];
/// What may follow a CPU part's `<n> vCPU`: the makers and lines the
/// account's names use, as they go together. Anything else there gives no
/// spec.
const CPU_NAMES: [&[&str]; 10] = [
    &["amd"],
    &["intel"],
    &["epyc"],
    &["epyc4g"],
    &["xeon"],
    &["ryzen"],
    &["amd", "epyc"],
    &["amd", "epyc4g"],
    &["amd", "ryzen"],
    &["intel", "xeon"],
];
/// The words that may follow a memory size: `4 GB DDR5`.
const MEMORY_WORDS: [&str; 4] = ["ddr4", "ddr5", "ram", "ecc"];
/// The words that may follow a disk size: `10 GB SSD NVMe4`.
const DISK_WORDS: [&str; 5] = ["ssd", "nvme", "nvme3", "nvme4", "hdd"];

/// One part of a product's name, read in the known form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Part {
    /// `<n> vCPU`, its CPU's words, and `x <size> <memory words>` if given.
    Cpu(u16, Option<u32>),
    /// `<size> <memory words>`.
    Memory(u32),
    /// `<size> <disk words>`.
    Disk(u32, Disk),
}

/// Whether `word` is one of `list`, whatever its case.
fn known(word: &str, list: &[&str]) -> bool {
    list.iter().any(|k| word.eq_ignore_ascii_case(k))
}

/// Whether `words` are one or more of `list`, none of them twice.
fn all_known(words: &[&str], list: &[&str]) -> bool {
    !words.is_empty()
        && words
            .iter()
            .enumerate()
            .all(|(i, w)| known(w, list) && !words[..i].iter().any(|v| v.eq_ignore_ascii_case(w)))
}

/// A number written in digits alone, of at most `most` digits, with no
/// nought first (so above nought).
fn digits(word: &str, most: usize) -> Option<u32> {
    let plain = (1..=most).contains(&word.len())
        && !word.starts_with('0')
        && word.chars().all(|c| c.is_ascii_digit());
    plain.then(|| word.parse().ok()).flatten()
}

/// The size `words` begins with, in GB: digits, then `GB`, or `TB` (1000
/// GB each) where `tb` allows it. Too large to count: none.
fn size_of(words: &[&str], tb: bool) -> Option<u32> {
    let [n, unit, ..] = words else {
        return None;
    };
    let n = digits(n, 9)?;
    match *unit {
        "GB" => Some(n),
        "TB" if tb => n.checked_mul(1000),
        _ => None,
    }
}

/// `words`, every one of them, as one part in the known form; none when a
/// word is not where that form has it.
fn part_of(words: &[&str]) -> Option<Part> {
    if words.get(1).is_some_and(|w| w.eq_ignore_ascii_case("vcpu")) {
        let cores = u16::try_from(digits(words[0], 3)?).ok()?;
        let rest = &words[2..];
        let cpu = rest
            .iter()
            .take_while(|w| !w.eq_ignore_ascii_case("x"))
            .count();
        let named = &rest[..cpu];
        let cpu_known = |name: &&[&str]| {
            name.len() == named.len()
                && name
                    .iter()
                    .zip(named)
                    .all(|(k, w)| w.eq_ignore_ascii_case(k))
        };
        if !named.is_empty() && !CPU_NAMES.iter().any(cpu_known) {
            return None;
        }
        let memory = match &rest[cpu..] {
            [] => None,
            [_x, size @ ..] => {
                let gb = size_of(size, false)?;
                if !all_known(&size[2..], &MEMORY_WORDS) {
                    return None;
                }
                Some(gb)
            }
        };
        return Some(Part::Cpu(cores, memory));
    }
    let kind = words.get(2..)?;
    if all_known(kind, &MEMORY_WORDS) {
        return size_of(words, false).map(Part::Memory);
    }
    if !all_known(kind, &DISK_WORDS) {
        return None;
    }
    let gb = size_of(words, true)?;
    let is = |k: &str| kind.iter().any(|w| w.eq_ignore_ascii_case(k));
    let nvme = is("nvme") || is("nvme3") || is("nvme4");
    // A disk said to be two kinds: not in the form.
    if is("hdd") && (nvme || is("ssd")) {
        return None;
    }
    let disk = if nvme {
        Disk::Nvme
    } else if is("ssd") {
        Disk::Ssd
    } else {
        Disk::Unsaid
    };
    Some(Part::Disk(gb, disk))
}

impl Spec {
    /// The cores and memory the account gives.
    pub(crate) const fn sized(cores: Option<u16>, memory_gb: Option<u32>) -> Self {
        Self {
            cores,
            memory_gb,
            disk_gb: None,
            disk: Disk::Unsaid,
        }
    }

    /// The spec in the name of a product, read only when all of the name
    /// is in the known form, word by word, case aside but for `GB` and
    /// `TB`: the product's own name from [`NAME_WORDS`] (`🛰️ SLV VPS`), then
    /// parts split by ` - `, each one of `<n> vCPU` (1 to 3 digits, then
    /// CPU words as in [`CPU_NAMES`] and, if given, `x <n> GB <memory
    /// words>`), `<n> GB <memory words>` ([`MEMORY_WORDS`]) and `<n> GB|TB
    /// <disk words>` ([`DISK_WORDS`], one kind of disk), with a CPU, a
    /// memory and a disk part each at most once and no word twice in a
    /// part. Disk parts joined by ` + ` count as the one disk part and
    /// give no disk. `SLV VPS - 1 vCPU AMD EPYC4G x 4 GB DDR5 - 10 GB SSD
    /// NVMe4` has 1 vCPU, 4 GB of memory and a 10 GB `NVMe` disk. Any other
    /// name gives none at all.
    pub(crate) fn of_title(title: &str) -> Self {
        let words: Vec<&str> = title.split_whitespace().collect();
        let Some(at) = words.iter().position(|w| *w == "-") else {
            return Self::default();
        };
        let name = &words[..at];
        if name.is_empty() || !name.iter().all(|w| known(w, &NAME_WORDS)) {
            return Self::default();
        }
        Self::of_parts(&words[at + 1..])
    }

    /// The parts `words` holds, split by `-`, read in the known form: the
    /// spec they give together, or none when one is not in it.
    fn of_parts(words: &[&str]) -> Self {
        let mut spec = Self::default();
        let mut disks = 0_usize;
        for part in words.split(|w| *w == "-") {
            let pieces: Vec<&[&str]> = part.split(|w| *w == "+").collect();
            let twice = if pieces.len() > 1 {
                // ` + ` joins disks only: the one disk part, but not one
                // disk, so none is said.
                if !pieces
                    .iter()
                    .all(|piece| matches!(part_of(piece), Some(Part::Disk(..))))
                {
                    return Self::default();
                }
                disks += 1;
                false
            } else {
                match part_of(part) {
                    Some(Part::Cpu(cores, memory)) if spec.cores.is_none() => {
                        spec.cores = Some(cores);
                        memory.is_some_and(|gb| spec.memory_gb.replace(gb).is_some())
                    }
                    Some(Part::Memory(gb)) => spec.memory_gb.replace(gb).is_some(),
                    Some(Part::Disk(gb, disk)) => {
                        disks += 1;
                        (spec.disk_gb, spec.disk) = (Some(gb), disk);
                        false
                    }
                    Some(Part::Cpu(..)) | None => true,
                }
            };
            if twice || disks > 1 {
                return Self::default();
            }
        }
        spec
    }

    /// What is known of it, said: `1 vCPU, 4 GB memory, 10 GB NVMe`.
    pub(crate) fn said(&self) -> Option<String> {
        let mut parts = Vec::new();
        if let Some(cores) = self.cores {
            parts.push(t!("worker_vps.worker.cores", cores));
        }
        if let Some(memory) = self.memory_gb {
            parts.push(t!("worker_vps.worker.memory", memory));
        }
        if let Some(disk) = self.disk_gb {
            parts.push(match self.disk {
                Disk::Nvme => t!("worker_vps.worker.disk_nvme", disk),
                Disk::Ssd => t!("worker_vps.worker.disk_ssd", disk),
                Disk::Unsaid => t!("worker_vps.worker.disk", disk),
            });
        }
        (!parts.is_empty()).then(|| parts.join(&t!("worker_vps.worker.sep")))
    }
}

/// An ERPC server as a person reads it: "ERPC Worker" and its spec, such
/// as `ERPC Worker (1 vCPU, 4 GB memory, 10 GB NVMe)`; "ERPC Worker" alone
/// when none of it is known. Never "VPS", nor the product's own name.
pub(crate) fn worker(spec: &Spec) -> String {
    match spec.said() {
        Some(spec) => t!("worker_vps.worker.named", spec),
        None => t!("worker_vps.worker.bare"),
    }
}

/// [`worker`], with the id a person names it by: `ERPC Worker 100001 (1
/// vCPU, 4 GB memory, 10 GB NVMe)`.
pub(crate) fn worker_id(id: impl std::fmt::Display, spec: &Spec) -> String {
    let id = id.to_string();
    match spec.said() {
        Some(spec) => t!("worker_vps.worker.named_id", id, spec),
        None => t!("worker_vps.worker.bare_id", id),
    }
}

/// What `erpc ai`'s start or end of a server asks, through `inner`, with
/// the product's own name said as the ERPC Worker it is ([`worker`])
/// wherever it appears: the yes or no is `inner`'s.
struct AsWorker<'a> {
    inner: &'a dyn Confirm,
    named: Named<'a>,
}

/// Which server [`AsWorker`] names.
enum Named<'a> {
    /// The one a start buys: its product's name, and the ERPC Worker it is.
    Start { product: &'a str, worker: String },
    /// ERPC Worker `id`, which an end ends: `erpc ai` names it by its
    /// product's name, followed on the product's line by `(vps <id>)`.
    End { id: i64 },
    /// Something else, said as `erpc ai` says it.
    AsIs,
}

/// Who answers the end of `product_type` `id` that `erpc worker delete
/// --release-server` asks for: `asked` (none: nobody), with an ERPC
/// Worker said as the ERPC Worker it is.
fn end_answerer<'a>(
    asked: Option<&'a dyn Confirm>,
    product_type: &str,
    id: i64,
) -> Option<AsWorker<'a>> {
    asked.map(|inner| AsWorker {
        inner,
        named: if product_type == "vps" {
            Named::End { id }
        } else {
            Named::AsIs
        },
    })
}

impl AsWorker<'_> {
    /// `ask`, its product's name said as the ERPC Worker.
    fn renamed(&self, ask: &erpc_ai::confirm::Confirmation) -> erpc_ai::confirm::Confirmation {
        let (product, worker, tag) = match &self.named {
            Named::AsIs => return ask.clone(),
            Named::Start { product, worker } => ((*product).to_owned(), worker.clone(), None),
            Named::End { id } => {
                // The product's line says its name and `(vps <id>)`.
                let tag = format!(" (vps {id})");
                let Some(product) = ask.lines.iter().find_map(|(_, v)| v.strip_suffix(&tag)) else {
                    return ask.clone();
                };
                let worker = worker_id(id, &Spec::of_title(product));
                (product.to_owned(), worker, Some(tag))
            }
        };
        let name = product.trim();
        let swap = |text: &str| {
            let text = tag
                .as_deref()
                .and_then(|tag| text.strip_suffix(tag))
                .unwrap_or(text);
            if name.is_empty() {
                text.to_owned()
            } else {
                text.replace(name, &worker)
            }
        };
        erpc_ai::confirm::Confirmation {
            title: swap(&ask.title),
            lines: ask
                .lines
                .iter()
                .map(|(label, value)| (label.clone(), swap(value)))
                .collect(),
        }
    }
}

impl Confirm for AsWorker<'_> {
    fn confirm<'a>(
        &'a self,
        ask: &'a erpc_ai::confirm::Confirmation,
    ) -> core::pin::Pin<Box<dyn Future<Output = bool> + 'a>> {
        Box::pin(async move { self.inner.confirm(&self.renamed(ask)).await })
    }
}

/// How a family of hourly products is named: the servers as
/// [`worker`] names them, the others by the catalogue's word.
fn family_said(family: &str) -> String {
    if family == "vps" {
        t!("worker_vps.worker.bare")
    } else {
        family.to_owned()
    }
}

/// The UDP port a UDP Forwarding line sends to when neither `--udp-port`
/// nor a line on record names one.
pub(crate) const DEFAULT_UDP_PORT: u16 = 10001;

/// The server a line is for: the address it lets in, the UDP port a UDP
/// Forwarding line sends to, and the region (the server's, or
/// `--udp-region`) an Unlimited RPC or a UDP Forwarding line is started in.
pub(crate) struct LineTarget {
    pub(crate) ip: Ipv4Addr,
    pub(crate) udp_port: Option<u16>,
    pub(crate) region: Option<String>,
}

fn failed(message: impl Into<String>) -> CliError {
    CliError::new(Code::Failed, message)
}

/// Says what would have been asked, and goes ahead: the answer `--yes`
/// gives to a start, and to the ends `erpc worker delete --release-server`
/// names. An hourly product is paid from ERPC Credit, which is bought
/// beforehand, and user-api refuses a start the credit does not cover; so
/// a command line that names what to start, with `--yes`, is the yes. A
/// delete that ends the server, with `--yes`, is the yes to ending the
/// lines and the server on its record. The product and its price (on a
/// start, the credit and how long it lasts too) are still said, on
/// standard error, whether or not the output is JSON.
#[derive(Default)]
struct Accepted;

impl Confirm for Accepted {
    fn confirm<'a>(
        &'a self,
        ask: &'a erpc_ai::confirm::Confirmation,
    ) -> core::pin::Pin<Box<dyn Future<Output = bool> + 'a>> {
        eprintln!("{}", accepted_text(&ask.text()));
        Box::pin(async { true })
    }
}

/// What [`Accepted`] says in place of the question: what would have been
/// asked, and that `--yes` answered it.
fn accepted_text(asked: &str) -> String {
    format!("{asked}\n  {}", t!("worker_vps.accepted"))
}

/// A session with user-api, and a way to ask the person.
pub(crate) struct Api {
    client: AuthClient,
    token: SecretString,
    confirm: crate::ai::TerminalConfirm,
    /// Whether `--yes` answers what a start asks; `None` for a command that
    /// has no such flag, which a refusal then does not name.
    yes: Option<bool>,
    /// In the session that ends what `erpc worker delete --release-server`
    /// names ([`Api::releasing`]): whether its `--yes` answers those ends.
    /// `None` elsewhere, where `--yes` answers no end.
    release: Option<bool>,
    accepted: Accepted,
    /// In a test, the loopback server that stands in for user-api
    /// ([`stub`]): the reads, and the pointing of a UDP Forwarding line, go
    /// to it by their path. The session's client reaches user-api alone and
    /// is never pointed elsewhere.
    #[cfg(test)]
    stub: Option<std::net::SocketAddr>,
}

impl Api {
    /// Signs in with the stored session.
    pub(crate) async fn open() -> Result<Self, CliError> {
        let client = AuthClient::new().map_err(|e| CliError::new(Code::Network, e.to_string()))?;
        let access = crate::ai::StoreAccess::open(client.clone()).map_err(|o| {
            o.error()
                .unwrap_or_else(|| CliError::new(Code::NotSignedIn, t!("worker_vps.no_session")))
        })?;
        let token = access
            .access_token()
            .await
            .map_err(|e| CliError::new(Code::NotSignedIn, e).hint(t!("worker_vps.login_hint")))?;
        Ok(Self {
            client,
            token,
            confirm: crate::ai::TerminalConfirm::default(),
            yes: None,
            release: None,
            accepted: Accepted,
            #[cfg(test)]
            stub: None,
        })
    }

    /// The same session, with `--yes` answering what a start asks (the
    /// price of an hourly product) and the first login to a server erpc
    /// has not made key-only yet. An end it makes is still the person's to
    /// say.
    #[must_use]
    pub(crate) fn accepting(mut self, yes: bool) -> Self {
        self.yes = Some(yes);
        self
    }

    /// The same session, for what `erpc worker delete --release-server`
    /// ends (the environment's lines and its hourly server): `--yes`
    /// (`yes`) answers each end, which is said on standard error; without
    /// it each is the person's to say, at a terminal. It answers no start
    /// and no first login.
    #[must_use]
    pub(crate) fn releasing(mut self, yes: bool) -> Self {
        self.release = Some(yes);
        self
    }

    /// One that reaches nothing, for tests that never call user-api.
    #[cfg(test)]
    pub(crate) fn offline() -> Self {
        Self {
            client: AuthClient::new().expect("client"),
            token: SecretString::from(String::new()),
            confirm: crate::ai::TerminalConfirm::default(),
            yes: None,
            release: None,
            accepted: Accepted,
            stub: None,
        }
    }

    /// One whose reads, and whose pointing of a UDP Forwarding line, are
    /// answered by the loopback server at `stub`.
    #[cfg(test)]
    pub(crate) fn stubbed(stub: std::net::SocketAddr) -> Self {
        Self {
            stub: Some(stub),
            ..Self::offline()
        }
    }

    /// The confirmation `who` gives.
    fn by(&self, who: Answerer) -> &dyn Confirm {
        match who {
            Answerer::Yes => &self.accepted,
            Answerer::Person => &self.confirm,
        }
    }

    /// Who answers an end: `--yes`, in a session [`Api::releasing`] made
    /// with it; else the person at the terminal, or nobody.
    fn confirm(&self) -> Option<&dyn Confirm> {
        // A stubbed session has no one to ask, so no end gets as far as a
        // request.
        #[cfg(test)]
        if self.stub.is_some() {
            return None;
        }
        self.end_answerer(crate::account::session::has_terminal())
            .map(|who| self.by(who))
    }

    /// Who answers an end, with a person at a terminal (`terminal`) or
    /// not: `--yes`, in a session [`Api::releasing`] made with it; else the
    /// person, or nobody.
    fn end_answerer(&self, terminal: bool) -> Option<Answerer> {
        match self.release {
            Some(yes) => answerer(Asked::Release, Some(yes), terminal),
            None => answerer(Asked::End, self.yes, terminal),
        }
    }

    /// Who answers a start: `--yes`, else the person at the terminal.
    ///
    /// # Errors
    ///
    /// With neither, what to do about it: a start is never refused with
    /// words meant for a model.
    fn confirm_start(&self) -> Result<&dyn Confirm, CliError> {
        // Nor any start.
        #[cfg(test)]
        if self.stub.is_some() {
            return Err(nobody(Asked::Start, self.yes));
        }
        answerer(
            Asked::Start,
            self.yes,
            crate::account::session::has_terminal(),
        )
        .map(|who| self.by(who))
        .ok_or_else(|| nobody(Asked::Start, self.yes))
    }

    /// Who answers a start now: `--yes`, the person at the terminal, or
    /// nobody. A stubbed session has no terminal.
    fn start_answerer(&self) -> Option<Answerer> {
        #[cfg(test)]
        if self.stub.is_some() {
            return answerer(Asked::Start, self.yes, false);
        }
        answerer(
            Asked::Start,
            self.yes,
            crate::account::session::has_terminal(),
        )
    }

    /// Who answers the first login to a server: `--yes`, else the person
    /// at the terminal.
    ///
    /// # Errors
    ///
    /// With neither, what the login is and what to do about it: it starts
    /// nothing and has no price, and is not refused as a start is.
    fn confirm_login(&self) -> Result<&dyn Confirm, CliError> {
        answerer(
            Asked::Login,
            self.yes,
            crate::account::session::has_terminal(),
        )
        .map(|who| self.by(who))
        .ok_or_else(|| nobody(Asked::Login, self.yes))
    }

    /// What user-api answers at `url`, one of the account's own reads.
    pub(crate) async fn read(&self, url: &str) -> Result<Value, CliError> {
        let silent = |e| CliError::new(Code::Network, t!("worker_vps.api_silent", error = e));
        #[cfg(test)]
        if let Some(stub) = self.stub {
            let (status, body) = stub::send(stub, "GET", url, None).await;
            return account::read_reply(status, &body).map_err(silent);
        }
        account::read(&self.client, &self.token, url)
            .await
            .map_err(silent)
    }

    /// Reads a UDP Forwarding `my` list, whose refusal is user-api's own
    /// word rather than a refused session.
    async fn read_udp(&self, url: &str) -> Result<Value, erpc_api::ApiError> {
        #[cfg(test)]
        if let Some(stub) = self.stub {
            let (status, body) = stub::send(stub, "GET", url, None).await;
            return account::udp_forwarding_reply(status, &body);
        }
        account::read_udp_forwarding(&self.client, &self.token, url).await
    }

    /// Points UDP Forwarding line `number` at `destination` from `region`.
    async fn set_udp_destination(
        &self,
        url: &str,
        number: i64,
        region: &str,
        destination: &str,
    ) -> Result<Value, erpc_api::ApiError> {
        #[cfg(test)]
        if let Some(stub) = self.stub {
            let body = account::udp_destination(number, region, destination);
            let (status, text) = stub::send(stub, "PUT", url, Some(&body)).await;
            return account::udp_forwarding_reply(status, &text);
        }
        account::set_udp_destination(&self.client, &self.token, url, number, region, destination)
            .await
    }
}

/// What is asked before something is done.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Asked {
    /// The start of an hourly product, at its price.
    Start,
    /// The first login to a server erpc has not made key-only yet: once,
    /// with its password, to put the key in and turn password logins off.
    /// It starts nothing and has no price.
    Login,
    /// The end of an hourly product.
    End,
    /// The end of what `erpc worker delete --release-server` names: one of
    /// the environment's lines, or its hourly server.
    Release,
}

/// Who answers what is asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answerer {
    /// `--yes` on the command line.
    Yes,
    /// The person at the terminal.
    Person,
}

/// Who answers `asked`, from whether `--yes` was given (`None`: the
/// command has no such flag) and whether a person is at a terminal; `None`
/// when nobody can. `--yes` answers a start, a first login and the ends a
/// `delete --release-server` names, and comes first there, so that a
/// script, an agent or a person who passed it is not asked again. It
/// answers no other end (one a deploy offers after a step failed, `run`'s
/// lines): those are the person's to say, at a terminal.
fn answerer(asked: Asked, yes: Option<bool>, terminal: bool) -> Option<Answerer> {
    match (asked, yes) {
        (Asked::Start | Asked::Login | Asked::Release, Some(true)) => Some(Answerer::Yes),
        _ => terminal.then_some(Answerer::Person),
    }
}

/// The refusal of a start or a first login that nobody can answer, in
/// words for whoever ran the command. The way out it names is one the
/// command has: `--yes` only where there is such a flag.
fn nobody(asked: Asked, yes: Option<bool>) -> CliError {
    let (message, hint) = match (asked, yes) {
        (Asked::Login, Some(_)) => (
            t!("worker_vps.login.needs_yes"),
            t!("worker_vps.login.needs_yes_hint"),
        ),
        (Asked::Login, None) => (
            t!("worker_vps.login.needs_yes"),
            t!("worker_vps.login.needs_terminal_hint"),
        ),
        (Asked::Start | Asked::End | Asked::Release, Some(_)) => {
            (t!("worker_vps.needs_yes"), t!("worker_vps.needs_yes_hint"))
        }
        (Asked::Start | Asked::End | Asked::Release, None) => (
            t!("worker_vps.needs_yes"),
            t!("worker_vps.needs_terminal_hint"),
        ),
    };
    CliError::new(Code::NeedsTerminal, message).hint(hint)
}

/// Where a start's request is kept from before it leaves until its outcome
/// is on record. A start that got no answer (a timeout, a connection that
/// broke, erpc stopped) is then sent again with the same key, never with a
/// new one. `erpc worker run` has no such record: what it implements keeps
/// nothing, and its hints say so.
pub(crate) trait StartRecord {
    /// The request on record for what is being started: one a run left
    /// without learning its outcome.
    fn pending(&self) -> Option<Start>;

    /// Puts `start` on record. Called before its request leaves.
    fn begin(&mut self, start: &Start) -> Result<(), String>;

    /// Takes the request off the record: user-api answered for it, and
    /// nothing was started under it, or what was has been ended and its key
    /// is refused from then on.
    fn settle(&mut self) -> Result<(), String>;

    /// What to do after an answer that did not settle the start, in the
    /// words of whoever keeps the record: what becomes of the request, and
    /// the way on.
    fn stays_hint(&self, why: Stays) -> String;

    /// What to do about a request on record that is for another purchase
    /// than the one asked for now. Only a record that keeps requests is
    /// asked.
    fn other_hint(&self) -> String {
        String::new()
    }
}

/// A line's [`StartRecord`], which also takes the line user-api names.
pub(crate) trait LineRecord: StartRecord {
    /// Puts line `id` on record the moment user-api names it, started or
    /// not; its request leaves the record with that.
    fn named(&mut self, id: &str) -> Result<(), CliError>;
}

/// The key a start's request carries, from the request on record.
#[derive(Debug, Clone, PartialEq, Eq)]
enum KeyFor {
    /// None on record: a new key, put on record before the request leaves.
    New,
    /// One on record for the same purchase, which got no answer: its key
    /// again, and no new one.
    Again(String),
    /// One on record for another purchase (another plan, region or
    /// address). Its key is not this purchase's, and it may have gone
    /// through: nothing is sent, since starting this one could buy both.
    Other,
}

impl KeyFor {
    fn of(on_record: Option<&Start>, wanted: &Start) -> Self {
        match on_record {
            None => Self::New,
            Some(start) if start.same_purchase(wanted) => Self::Again(start.key.clone()),
            Some(_) => Self::Other,
        }
    }
}

/// Why a start is not settled after a run, and its request stays where it
/// is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stays {
    /// No answer to go by: the same command sends it again.
    Unanswered,
    /// The purchase is still being made: the same command again, shortly.
    InProgress,
    /// user-api answered, and not for this request: whether it went
    /// through is to be looked up, and the request cleared by hand once
    /// nothing was started.
    NotKnown,
    /// A purchase exists under the request, most likely the earlier
    /// request's own, and user-api does not give it to this command. It is
    /// to be looked up, taken up or ended, and the request then cleared by
    /// hand; nothing is sent again.
    Exists,
    /// user-api says it started the product and did not name it: the same,
    /// for a purchase that was made for certain.
    Unnamed,
}

/// What an answer to a start says of its request on record.
///
/// The rule: **a request sent again leaves the record only when the answer
/// is the purchase itself**, a 2xx that names it, **or says that what was
/// bought under its key was ended** (`START_ENDED`, [`failure_code`]): that
/// key is refused for good, so sending it again buys nothing. No other
/// refusal of a request sent again says what became of the first, and the
/// one that names the key (`IDEMPOTENCY_CONFLICT`) says a row made under it
/// exists. A first request, whose key this run made and nobody sent
/// before, also leaves on a certain refusal. A request dropped on a guess
/// is bought again, with a new key, by the next run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    /// 2xx with its id: user-api made the purchase, or answers with the
    /// one made under this key. The request leaves the record with the
    /// product put there.
    Made,
    /// 2xx that says it started the product and does not name it: a
    /// purchase exists that erpc cannot put on record. The request stays.
    Unnamed,
    /// A first request refused for certain: its key had never been sent,
    /// so nothing was made under it. The request leaves the record.
    Refused,
    /// A first request answered 409 `IDEMPOTENCY_CONFLICT`: the key, made
    /// by this run, is another purchase's, which cannot be an earlier
    /// request of erpc's. The request leaves the record, and nothing is
    /// sent again by itself.
    OtherPurchase,
    /// A request sent again and answered 409 `IDEMPOTENCY_CONFLICT`: a
    /// purchase exists under its key, and user-api does not give it to
    /// this command. The key is random and was sent for this purchase
    /// only, so that purchase may well be the earlier request's own. The
    /// request stays, nothing is started and nothing sent again.
    Unmatched,
    /// 409 `START_ENDED`, first request or not: what was bought under this
    /// key has been ended (while it was being started, or later, after it
    /// ran), and user-api refuses the key from then on. The key is never
    /// sent again, so the request leaves the record; buying it again is a
    /// new purchase, with a new key.
    Ended,
    /// 409 `PURCHASE_IN_PROGRESS`: the account's hourly lock is held, by
    /// the first request of this very key perhaps, or the row it made is
    /// not linked yet. The request stays, and the same command sends it
    /// again shortly.
    InProgress,
    /// A request sent again and refused by any other answer: an edge's
    /// 403, a 400, no credit, no stock. It says nothing about the first
    /// request, which may have gone through or be in flight still. The
    /// request stays.
    Unrelated,
    /// A 409 with a code erpc does not know or with none, or a 2xx that
    /// says it started nothing: what became of the request is not known.
    /// It stays.
    NotKnown,
    /// No answer, or one that says only that user-api did not get to it
    /// (a timeout, too many requests, a fault of its own). The request
    /// stays, and the same command sends it again.
    Unanswered,
}

impl Answer {
    /// From the HTTP status of user-api's answer (`None` when none came),
    /// the reply's failure code ([`failure_code`]), whether it says the
    /// product was started (`done`) and names it (`named`), and whether
    /// the request had been sent before (`again`: it was on record when
    /// this run began).
    fn of(status: Option<u16>, code: Option<&str>, done: bool, named: bool, again: bool) -> Self {
        let Some(status) = status else {
            return Self::Unanswered;
        };
        if (200..=299).contains(&status) {
            return match (done, named) {
                (true, true) => Self::Made,
                (true, false) => Self::Unnamed,
                (false, _) => Self::NotKnown,
            };
        }
        if status == 409 && code == Some("PURCHASE_IN_PROGRESS") {
            return Self::InProgress;
        }
        if status == 409 && code == Some("START_ENDED") {
            return Self::Ended;
        }
        // A timeout, too many requests, a fault of user-api's, or nothing
        // it answers a start with: it did not get to the request.
        if matches!(status, 408 | 429) || !(400..=499).contains(&status) {
            return Self::Unanswered;
        }
        let conflict = status == 409 && code == Some("IDEMPOTENCY_CONFLICT");
        // A refusal. A request sent again stays whatever it is refused
        // with: only the purchase itself, or what was bought under its key
        // ended (both above), takes it off the record.
        if again {
            return if conflict {
                Self::Unmatched
            } else {
                Self::Unrelated
            };
        }
        // A first request: its key was made by this run, so no answer to
        // it is about an earlier one. A refusal is certain, but for a 409
        // erpc cannot read: the routes refuse for want of stock, or a
        // region that is down, before they write anything.
        if conflict {
            Self::OtherPurchase
        } else if status != 409 || matches!(code, Some("OUT_OF_STOCK" | "REGION_DOWN")) {
            Self::Refused
        } else {
            Self::NotKnown
        }
    }

    /// What is said of an answer that leaves the request where it is, and
    /// why it stays; `None` for one that takes it off the record, with the
    /// product put there ([`Self::Made`]), because nothing was made under
    /// it, or because what was has been ended and its key is refused
    /// ([`Self::Ended`]). `status` and `reason` are user-api's own.
    fn stays(self, status: &Value, reason: &str) -> Option<(String, Stays)> {
        Some(match self {
            Self::Made | Self::Refused | Self::OtherPurchase | Self::Ended => return None,
            Self::Unnamed => (t!("worker_vps.start.unnamed", status), Stays::Unnamed),
            // Without user-api's own sentence for it, which tells a client
            // to start a new purchase with a new key: here that would buy
            // a second.
            Self::Unmatched => (t!("worker_vps.start.unmatched", status), Stays::Exists),
            Self::InProgress => (
                t!("worker_vps.start.in_progress", status, reason),
                Stays::InProgress,
            ),
            Self::Unrelated => (
                t!("worker_vps.start.unrelated", status, reason),
                Stays::NotKnown,
            ),
            Self::NotKnown => (
                t!("worker_vps.start.not_known", status, reason),
                Stays::NotKnown,
            ),
            Self::Unanswered => {
                let why = t!("worker_vps.start.answered", status, reason);
                (t!("worker_vps.start.unanswered", why), Stays::Unanswered)
            }
        })
    }
}

/// The failure code of user-api's answer to a start. The VPS and UDP
/// Forwarding routes give it as `code` (a UDP Forwarding start's own are
/// `UDP_FORWARDING_CONFLICT` and `UDP_FORWARDING_UPSTREAM_UNAVAILABLE`,
/// which erpc does not tell apart from any other 409 and 502). The gRPC,
/// Shreds and Unlimited routes give a key's conflict, and a duplicate
/// insert's "in progress", as the whole `message`, with no `code`. The
/// gRPC and Shreds routes say that what was bought under a start's key has
/// been ended, and the key is refused from then on, in one sentence
/// ([`FIRST_HOUR_ENDED`]), with no `code`: read as `START_ENDED`, as the
/// ERPC account reads it.
fn failure_code(started: &Value) -> Option<&str> {
    started["code"]
        .as_str()
        .or_else(|| match started["message"].as_str() {
            Some(message @ ("IDEMPOTENCY_CONFLICT" | "PURCHASE_IN_PROGRESS")) => Some(message),
            Some(FIRST_HOUR_ENDED) => Some("START_ENDED"),
            _ => None,
        })
}

/// user-api's whole answer, with no `code`, when what was bought under a
/// start's key has been ended: while it was being started, or, to a
/// request sent again, at any time after (its words say only the first).
/// The start's key is refused for good from then on.
const FIRST_HOUR_ENDED: &str =
    "This purchase was ended while it was starting. Nothing more was granted.";

/// A purchase as a refusal names it: `vps prod_… (amsterdam)`.
pub(crate) fn purchase_name(start: &Start) -> String {
    let at = start.region.as_deref().or(start.ip.as_deref());
    match at {
        Some(at) => format!("{} {} ({at})", start.family, start.product),
        None => format!("{} {}", start.family, start.product),
    }
}

/// What a start's request made the caller ask for the key with.
pub(crate) type Key<'a> = &'a mut dyn FnMut() -> Result<String, String>;

/// What user-api's answer leaves the caller of [`start_on_record`] to do.
#[derive(Debug)]
pub(crate) enum Sent {
    /// The purchase, by the id user-api names it with. The caller puts it
    /// on record, and its request leaves with it.
    Made {
        /// Its id in the account.
        id: String,
        /// user-api's reply.
        started: Value,
    },
    /// Refused: user-api's reply, for the caller to say. Its request is off
    /// the record, but for `stays`: why the record could not be written,
    /// for an answer that should have taken it off ([`Answer::Ended`]), so
    /// that the error says the next run sends its key once more.
    Refused {
        /// user-api's reply.
        started: Value,
        /// Why the request is still on record, when it should not be.
        stays: Option<String>,
    },
}

/// The id user-api names what it started by, under `field` of its reply.
fn named_id(started: &Value, field: &str) -> Option<String> {
    started[field]
        .as_i64()
        .map(|n| n.to_string())
        .or_else(|| started[field].as_str().map(ToOwned::to_owned))
}

/// One start, by way of its record. `wanted` is the purchase, its key not
/// chosen yet; `id_field` is where user-api's reply names what it started;
/// `send` makes the request, asking for the key once the start has been
/// agreed to and is about to leave.
///
/// The request on record for the same purchase is sent again with its key.
/// With none on record a new key goes on record first. One on record for
/// another purchase refuses the start. What comes back decides what
/// becomes of the request ([`Answer`]), here and nowhere else:
///
/// - The purchase itself: returned with its id. The caller puts what was
///   started on record, and the request leaves with it.
/// - A first request refused for certain: the request is taken off the
///   record, and the reply returned for the caller to say.
/// - What was bought under its key has been ended, first request or not
///   ([`Answer::Ended`]): the same; when the record cannot be written, the
///   reply comes back with why, for the error to say that the next run
///   sends the key once more.
/// - Anything else leaves the request where it is, and is an error that
///   says what user-api answered; the record's hint says what becomes of
///   the request and the way on.
pub(crate) async fn start_on_record(
    wanted: &Start,
    id_field: &str,
    record: &mut dyn StartRecord,
    say: &Say,
    send: impl AsyncFnOnce(Key<'_>) -> Result<Value, StartError>,
) -> Result<Sent, CliError> {
    let again = match KeyFor::of(record.pending().as_ref(), wanted) {
        KeyFor::New => None,
        KeyFor::Again(key) => {
            say.line(&t!("worker_vps.start.again"));
            Some(key)
        }
        KeyFor::Other => {
            let was = record.pending().as_ref().map(purchase_name);
            return Err(failed(t!(
                "worker_vps.start.other",
                was = was.unwrap_or_default(),
                now = purchase_name(wanted)
            ))
            .hint(record.other_hint()));
        }
    };
    // Whether this run put a request on record.
    let mut begun = false;
    let outcome = {
        let mut key = || {
            if let Some(key) = &again {
                return Ok(key.clone());
            }
            let key = erpc_ai::actions::purchase_key()?;
            let start = Start {
                key: key.clone(),
                ..wanted.clone()
            };
            record
                .begin(&start)
                .map_err(|error| t!("worker_vps.start.not_on_record", error))?;
            begun = true;
            Ok(key)
        };
        send(&mut key).await
    };
    let started = match outcome {
        Ok(started) => started,
        // Refused before it left, or by user-api before it did anything. A
        // request this run put on record goes; one an earlier run left is
        // as unanswered as it was.
        Err(StartError::NotStarted(why)) => {
            if begun {
                let _ = record.settle();
            }
            return Err(failed(why));
        }
        Err(StartError::Unanswered(why)) => {
            return Err(failed(t!("worker_vps.start.unanswered", why))
                .hint(record.stays_hint(Stays::Unanswered)));
        }
    };
    let http = started["httpStatus"]
        .as_u64()
        .and_then(|status| u16::try_from(status).ok());
    let done = started["done"] == json!(true);
    let id = named_id(&started, id_field);
    let code = failure_code(&started);
    let answer = Answer::of(http, code, done, id.is_some(), again.is_some());
    let (status, reason) = (started["httpStatus"].clone(), reason(&started));
    let Some((message, why)) = answer.stays(&status, &reason) else {
        // It leaves the record: with the purchase, which the caller puts
        // there in the same write, or here, as nothing was made under it or
        // what was has been ended.
        return Ok(match id {
            Some(id) if answer == Answer::Made => Sent::Made { id, started },
            _ => {
                let stays = match record.settle() {
                    Err(error) if answer == Answer::Ended => Some(error),
                    _ => None,
                };
                Sent::Refused { started, stays }
            }
        });
    };
    Err(failed(message).hint(record.stays_hint(why)))
}

/// What is said of a start user-api refused: that its key was another
/// purchase's, or that what was bought under it has been ended (and, by
/// `stays`, that its request could not be taken off the record), when that
/// is what user-api says; else the caller's own hint.
fn refused_hint(started: &Value, stays: Option<&str>, own: Option<String>) -> Option<String> {
    match failure_code(started) {
        Some("IDEMPOTENCY_CONFLICT") => Some(t!("worker_vps.start.other_purchase")),
        Some("START_ENDED") => Some(match stays {
            Some(error) => t!("worker_vps.start.ended_stays", error),
            None => t!("worker_vps.start.ended"),
        }),
        _ => own,
    }
}

/// Whether user-api refused a start for want of stock, or because the
/// region is down: what another region may not lack.
fn elsewhere_may_do(started: &Value) -> bool {
    matches!(
        started["code"].as_str(),
        Some("OUT_OF_STOCK" | "REGION_DOWN")
    )
}

/// The account's API keys for the shared RPC as its dashboard gives them:
/// the primary one first, then its other active keys, each once.
fn account_keys(message: &Value) -> Vec<zeroize::Zeroizing<String>> {
    let others = message["activeApiKeys"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str);
    let mut keys: Vec<zeroize::Zeroizing<String>> = Vec::new();
    for key in message["apiKey"].as_str().into_iter().chain(others) {
        if !key.is_empty() && !keys.iter().any(|kept| kept.as_str() == key) {
            keys.push(zeroize::Zeroizing::new(key.to_owned()));
        }
    }
    keys
}

/// What the shared RPC makes of a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Accepted,
    /// 401 or 403: the key has ended, was revoked, has no plan, or is
    /// limited to other addresses than the one it was tried from.
    Refused,
    /// The RPC could not be asked, or answered something else.
    Unknown,
}

/// What the shared RPC makes of a key, from how it answered the call made
/// with it: the HTTP status, or `None` when no answer came (the RPC was
/// not reached, the connection broke, or nothing came in time).
///
/// Only 401 and 403 are the key's refusal. A rate limit (429), a failure
/// of the RPC's own (5xx), a redirect, any other status and silence say
/// nothing of the key, for it or against it: what becomes of such a key is
/// [`usable`]'s to say.
fn verdict(answered: Option<reqwest::StatusCode>) -> Verdict {
    match answered {
        Some(status) if status.is_success() => Verdict::Accepted,
        Some(reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN) => {
            Verdict::Refused
        }
        _ => Verdict::Unknown,
    }
}

/// Where a key is asked about, and how long the answer is waited for: the
/// shared Solana RPC, which is given 8 seconds for one key. One pair, so
/// that a test reads what [`asked`] is handed.
const QUESTION: (&str, Duration) = (erpc_core::endpoints::SHARED_RPC_URL, Duration::from_secs(8));

/// Asks the shared RPC whether it takes `key`, with a call that costs
/// next to nothing. Nothing of the answer is kept or shown: an error of
/// the HTTP client carries the URL, and the URL carries the key.
async fn asked(key: zeroize::Zeroizing<String>) -> Verdict {
    let (base, wait) = QUESTION;
    asked_at(base, wait, key).await
}

/// [`asked`], of the RPC at `base` and waiting `wait` at most: the pair
/// [`QUESTION`], except in a test, which names a double of its own on
/// loopback.
async fn asked_at(base: &str, wait: Duration, key: zeroize::Zeroizing<String>) -> Verdict {
    let Ok(mut url) = reqwest::Url::parse(base) else {
        return verdict(None);
    };
    url.query_pairs_mut().append_pair("api-key", &key);
    let Ok(client) = crate::rpc::call::client() else {
        return verdict(None);
    };
    let sent = client
        .post(url)
        .timeout(wait)
        .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "getHealth" }))
        .send()
        .await;
    verdict(sent.ok().map(|answer| answer.status()))
}

/// The key to use, of the account's keys in order, and whether the shared
/// RPC accepted it.
///
/// The first it accepts is the one, and no key after it is asked about.
/// A key it could not be asked about is passed over for one it accepts:
/// the RPC being away says nothing for the key either. Only when it
/// accepts none is the first of those it could not be asked about the one
/// (not known to be a bad one), and by then every key was asked about.
/// `None` when it refuses every one.
async fn usable<F, Asking>(
    keys: &[zeroize::Zeroizing<String>],
    ask: F,
) -> Option<(zeroize::Zeroizing<String>, bool)>
where
    F: Fn(zeroize::Zeroizing<String>) -> Asking,
    Asking: Future<Output = Verdict>,
{
    let mut unasked = None;
    for key in keys {
        match ask(key.clone()).await {
            Verdict::Accepted => return Some((key.clone(), true)),
            Verdict::Unknown => {
                unasked.get_or_insert_with(|| key.clone());
            }
            Verdict::Refused => {}
        }
    }
    unasked.map(|key| (key, false))
}

/// What choosing the account's key asks of the outside: user-api for the
/// account's keys, and the shared RPC about one of them. The real one is
/// [`Api`]; a test brings its own, which answers from a script and keeps
/// what it was asked.
pub(crate) trait KeySource {
    /// The account's dashboard, as user-api answers it.
    async fn dashboard(&self) -> Result<Value, CliError>;

    /// What the shared RPC makes of `key`.
    async fn takes(&self, key: zeroize::Zeroizing<String>) -> Verdict;
}

impl KeySource for Api {
    async fn dashboard(&self) -> Result<Value, CliError> {
        self.read(account::DASHBOARD_URL).await
    }

    async fn takes(&self, key: zeroize::Zeroizing<String>) -> Verdict {
        asked(key).await
    }
}

/// Which of the account's keys one is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AccountKey {
    /// The one its dashboard gives as the account's API key.
    Primary,
    /// Another of its active keys.
    Other,
}

impl AccountKey {
    /// As `--json` names it.
    pub(crate) const fn word(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Other => "other",
        }
    }
}

/// What trying the account's keys from this machine came to. It holds a
/// key, and has no `Debug` to print one with.
pub(crate) enum Tried {
    /// A key to use ([`usable`]).
    Usable {
        key: zeroize::Zeroizing<String>,
        /// Whether the shared RPC accepted it. When not, it accepted none
        /// of the account's keys, and this is the first it could not be
        /// asked about: a call made with it tells, and a caller that keeps
        /// the key for later has nothing to go by.
        accepted: bool,
        /// Whether it is the account's primary key.
        which: AccountKey,
    },
    /// It refused every one of them.
    ///
    /// That is this machine's answer, and may not be a server's. A key can
    /// be limited to the addresses it is used from, and one limited to a
    /// server's address is refused here though it works there. Only the
    /// status is read, so a 401 or 403 from anything between this machine
    /// and the RPC reads as a refusal too.
    Refused {
        /// The first of the account's keys: its primary one, when it has
        /// one.
        primary: zeroize::Zeroizing<String>,
        /// How many keys were tried.
        tried: usize,
    },
}

/// The account's keys for the shared RPC, tried from this machine in
/// order, with one `getHealth` each, until one is accepted ([`usable`]).
/// An account can have several, and its primary one can have run out (a
/// key can be given an end date) while another works, so the primary key
/// is not taken on trust.
///
/// # Errors
///
/// user-api's, when the dashboard cannot be read, and that the account
/// has no key. That every key was refused is not an error here, nor that
/// none was accepted and one could not be asked about: what either means
/// depends on where the key is going to be used, so each caller says
/// ([`Tried`]).
pub(crate) async fn keys_tried(from: &impl KeySource) -> Result<Tried, CliError> {
    let reply = from.dashboard().await?;
    let message = &reply["message"];
    let keys = account_keys(message);
    let Some(first) = keys.first().cloned() else {
        return Err(failed(t!("worker_vps.no_api_key")).hint(t!("worker_vps.no_api_key_hint")));
    };
    Ok(match usable(&keys, |key| from.takes(key)).await {
        Some((key, accepted)) => {
            // The primary key is the one the dashboard gives as the
            // account's; the first of an account that has none is another.
            let which = if message["apiKey"].as_str() == Some(key.as_str()) {
                AccountKey::Primary
            } else {
                AccountKey::Other
            };
            Tried::Usable {
                key,
                accepted,
                which,
            }
        }
        None => Tried::Refused {
            primary: first,
            tried: keys.len(),
        },
    })
}

/// That the shared RPC refused all `tried` keys of the account, from this
/// machine, as an error. It carries a count and never a key; the caller
/// adds the hint, which says the way out for what it was doing.
pub(crate) fn keys_refused(tried: usize) -> CliError {
    failed(t!("worker_vps.keys_refused", count = tried))
}

/// The account's API key for a call made from this machine (`erpc rpc
/// call`, `erpc webhook`): of its keys, the first the shared RPC accepts,
/// or, when it accepts none, the first it could not be asked about
/// ([`keys_tried`]): the call itself, which comes next, tells what the
/// key is worth. A key this machine is refused with is of no use to a
/// call made from here, so every key refused is an error.
pub(crate) async fn shared_api_key(
    from: &impl KeySource,
) -> Result<zeroize::Zeroizing<String>, CliError> {
    match keys_tried(from).await? {
        Tried::Usable { key, .. } => Ok(key),
        Tried::Refused { tried, .. } => {
            Err(keys_refused(tried).hint(t!("worker_vps.keys_refused_hint")))
        }
    }
}

/// The signed-in account's keys for the shared RPC, tried from this
/// machine ([`keys_tried`]), for `erpc worker secret put --from-account`.
pub(crate) async fn account_keys_tried() -> Result<Tried, CliError> {
    let api = Api::open().await?;
    keys_tried(&api).await
}

/// A server the worker will run on.
pub(crate) struct Server {
    pub(crate) target: Target,
    pub(crate) resource: Resource,
}

/// The account's VPSs that are running, as (id, address, region, plan).
pub(crate) async fn running(api: &Api) -> Result<Vec<(i64, String, String, Spec)>, CliError> {
    let reply = api
        .read(erpc_ai::ready::vps_status_url().map_err(failed)?)
        .await?;
    Ok(reply["data"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|row| row["status"].as_str() == Some("on"))
        .filter_map(|row| {
            Some((
                row["userVpsId"].as_i64()?,
                row["ip"].as_str()?.to_owned(),
                row["region"].as_str().unwrap_or("").to_owned(),
                running_spec(row),
            ))
        })
        .collect())
}

/// The spec of a running server's `row` (one of the account's VPS status
/// rows): from its product's name, the row's `product`, read as
/// [`Spec::of_title`] reads it; never the name itself.
fn running_spec(row: &Value) -> Spec {
    row["product"]
        .as_str()
        .map(Spec::of_title)
        .unwrap_or_default()
}

/// VPS `id` of the account, made key-only when erpc has not done so yet:
/// one login with its password, which puts the key in and turns password
/// logins off, after a yes from the person or from `--yes`. A server erpc
/// made key-only before is asked nothing.
pub(crate) async fn existing(api: &Api, id: i64, hourly: bool) -> Result<Server, CliError> {
    let reply = api
        .read(erpc_ai::ready::vps_status_url().map_err(failed)?)
        .await?;
    let row =
        erpc_ai::ready::vps_row(&reply, id).ok_or_else(|| failed(t!("worker_vps.vps.none", id)))?;
    let ip = row["ip"]
        .as_str()
        .ok_or_else(|| failed(t!("worker_vps.vps.no_address", id)))?
        .to_owned();
    let region = row["region"].as_str().map(ToOwned::to_owned);
    // Billed by the hour when it was just started so, or when the credit
    // snapshot lists it among the hourly resources, as ending one reads it.
    let hourly = hourly
        || api
            .read(account::CREDIT_SNAPSHOT_URL)
            .await
            .is_ok_and(|snapshot| {
                snapshot["message"]["hourlyResources"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|r| {
                        r["productType"].as_str() == Some("vps")
                            && r["userProductId"].as_i64() == Some(id)
                    })
            });
    let servers = crate::ai::vps_access::SshServers;
    // The login is asked only of a server erpc has not made key-only yet;
    // for one it has, nobody need be there to answer.
    let confirm = if servers.secured(id, &ip) {
        &api.confirm as &dyn Confirm
    } else {
        api.confirm_login()?
    };
    let secured = erpc_ai::servers::secure_vps(
        &api.client,
        &api.token,
        &json!({ "userVpsId": id }),
        Some(confirm),
        Some(&servers),
    )
    .await
    .map_err(failed)?;
    if secured["done"] != json!(true) {
        return Err(failed(t!("worker_vps.vps.not_key_only", id)));
    }
    let target = crate::ai::vps_access::pinned_target(&ip).map_err(failed)?;
    Ok(Server {
        target,
        resource: Resource {
            kind: ResourceKind::Vps,
            id: id.to_string(),
            region,
            hourly,
        },
    })
}

/// The region nearest this machine, by its time zone; Frankfurt when the
/// zone says nothing.
pub(crate) fn nearest_region() -> &'static str {
    let zone = std::env::var("TZ")
        .ok()
        .filter(|z| !z.is_empty())
        .or_else(|| {
            std::fs::read_link("/etc/localtime").ok().and_then(|p| {
                let text = p.to_string_lossy().into_owned();
                text.split_once("zoneinfo/").map(|(_, z)| z.to_owned())
            })
        });
    region_for_zone(zone.as_deref().unwrap_or(""))
}

/// The region nearest a machine in time zone `zone`.
pub(crate) fn region_for_zone(zone: &str) -> &'static str {
    let city = zone.rsplit('/').next().unwrap_or(zone);
    match zone.split('/').next().unwrap_or("") {
        "Asia" => match city {
            "Tokyo" | "Seoul" | "Pyongyang" | "Sakhalin" | "Vladivostok" => "tokyo",
            "Dubai" | "Riyadh" | "Tehran" | "Baku" | "Tbilisi" | "Yerevan" | "Qatar" | "Kuwait" => {
                "frankfurt"
            }
            _ => "singapore",
        },
        "Australia" | "Pacific" | "Antarctica" => "sydney",
        "America" | "US" | "Canada" | "Atlantic" => "ny",
        "Europe" | "Africa" => match city {
            "London" | "Dublin" | "Lisbon" | "Belfast" | "Guernsey" | "Isle_of_Man" | "Jersey" => {
                "london"
            }
            "Amsterdam" | "Brussels" | "Luxembourg" => "amsterdam",
            _ => "frankfurt",
        },
        "Japan" => "tokyo",
        _ => "frankfurt",
    }
}

/// A plan's id, price per hour in cents, and name.
struct Plan {
    id: String,
    cents: f64,
    name: String,
}

/// The name of product `id`, as user-api gives it.
async fn product_name(api: &Api, id: &str) -> Option<String> {
    let url = account::product_url(id).ok()?;
    let product = api.read(&url).await.ok()?;
    product
        .get("message")
        .unwrap_or(&product)
        .get("name")
        .and_then(Value::as_str)
        .map(|n| n.trim().to_owned())
        .filter(|n| !n.is_empty())
}

/// The cheapest plan of hourly `family` the catalogue offers (for a VPS,
/// one to run an app on), or the one asked for.
async fn plan(api: &Api, family: &str, asked: Option<&str>) -> Result<Plan, CliError> {
    let catalog = api.read(hourly::CATALOG_URL).await?;
    let plans: Vec<(String, f64)> = catalog["families"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|f| f["family"].as_str() == Some(family))
        .flat_map(|f| f["plans"].as_array().cloned().unwrap_or_default())
        .filter_map(|p| {
            Some((
                p["productId"].as_str()?.to_owned(),
                p["hourlyCents"].as_f64()?,
            ))
        })
        .collect();
    if let Some(id) = asked {
        let (id, cents) = plans.into_iter().find(|(p, _)| p == id).ok_or_else(|| {
            failed(t!(
                "worker_vps.plan.not_offered",
                id,
                family = family_said(family)
            ))
        })?;
        let name = product_name(api, &id).await.unwrap_or_else(|| id.clone());
        return Ok(Plan { id, cents, name });
    }
    let mut offered = Vec::new();
    for (id, cents) in plans {
        let name = product_name(api, &id).await;
        // The VPS family also sells add-ons, such as the monitoring VPS,
        // which are not servers to run an app on: they are known by their
        // names.
        if family == "vps" && name.as_deref().is_none_or(is_add_on) {
            continue;
        }
        let name = name.unwrap_or_else(|| id.clone());
        offered.push(Plan { id, cents, name });
    }
    offered
        .into_iter()
        .min_by(|a, b| a.cents.total_cmp(&b.cents))
        .ok_or_else(|| failed(t!("worker_vps.plan.none", family = family_said(family))))
}

/// How a plan was chosen, as the line about buying it says.
fn how_chosen(asked_plan: Option<&str>) -> String {
    if asked_plan.is_some() {
        t!("worker_vps.plan.as_asked")
    } else {
        t!("worker_vps.plan.cheapest")
    }
}

/// Why user-api did not start a product, as its reply says.
fn reason(started: &Value) -> String {
    started["message"]
        .as_str()
        .or_else(|| started["error"].as_str())
        .map_or_else(|| t!("worker_vps.no_reason"), ToOwned::to_owned)
}

/// Whether a product of the VPS family is an add-on rather than a server.
fn is_add_on(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("monitoring") || lower.contains("grafana")
}

/// Starts a new hourly VPS, once its price is answered (by the person, or
/// by `--yes`, which says it), and returns it as erpc.toml records it,
/// before it is ready: the caller puts it on record at once, then [`wait`]
/// and [`secure`] make it a server. Its request goes through `record`, so
/// that a start that gets no answer is sent again with the same key.
pub(crate) async fn buy(
    api: &Api,
    region: Option<&str>,
    asked_plan: Option<&str>,
    scope: &str,
    say: &Say,
    record: &mut dyn StartRecord,
) -> Result<Resource, CliError> {
    let region_asked = region.is_some();
    let region = match region {
        Some(r) if REGIONS.contains(&r) => r.to_owned(),
        Some(r) => {
            return Err(CliError::new(
                Code::Usage,
                t!(
                    "worker_vps.buy.bad_region",
                    region = r,
                    regions = REGIONS.join(", ")
                ),
            ));
        }
        None => nearest_region().to_owned(),
    };
    let chosen = plan(api, "vps", asked_plan).await?;
    let (product, cents) = (chosen.id.clone(), chosen.cents);
    let named = worker(&Spec::of_title(&chosen.name));
    say.line(&t!(
        "worker_vps.buy.buying",
        name = named.as_str(),
        product,
        how = how_chosen(asked_plan),
        price = format!("{:.4}", cents / 100.0),
        region,
        why = if region_asked {
            t!("worker_vps.buy.region_asked")
        } else {
            t!("worker_vps.buy.region_nearest")
        }
    ));
    // What `erpc ai`'s start asks names the product by its own name: here
    // it is said as the ERPC Worker it is.
    let confirm = AsWorker {
        inner: api.confirm_start()?,
        named: Named::Start {
            product: &chosen.name,
            worker: named,
        },
    };
    let confirm: &dyn Confirm = &confirm;
    let wanted = Start {
        key: String::new(),
        family: "vps".to_owned(),
        product: product.clone(),
        region: Some(region.clone()),
        ip: None,
    };
    let input = json!({ "family": "vps", "fields": { "productId": product, "region": region } });
    let sent = start_on_record(&wanted, "userVpsId", record, say, async |key| {
        erpc_ai::actions::start_hourly_product_with_key(
            &api.client,
            &api.token,
            &input,
            Some(confirm),
            key,
        )
        .await
    })
    .await?;
    let id = match sent {
        Sent::Made { id, .. } => id,
        // Refused, and its request is off the record but for `stays`
        // (`start_on_record`).
        Sent::Refused { started, stays } => {
            let error = failed(t!(
                "worker_vps.buy.not_started",
                status = started["httpStatus"],
                reason = reason(&started)
            ));
            let own =
                elsewhere_may_do(&started).then(|| t!("worker_vps.buy.other_region_hint", scope));
            return Err(match refused_hint(&started, stays.as_deref(), own) {
                Some(hint) => error.hint(hint),
                None => error,
            });
        }
    };
    say.line(&t!("worker_vps.buy.started", id));
    Ok(Resource {
        kind: ResourceKind::Vps,
        id,
        region: Some(region),
        hourly: true,
    })
}

/// The id of VPS `resource`.
fn vps_id(resource: &Resource) -> Result<i64, CliError> {
    resource
        .id
        .parse()
        .map_err(|_| failed(t!("worker_vps.vps.bad_id", id = resource.id)))
}

/// Waits, up to five minutes, for VPS `resource` (one just bought, or one
/// on record from a deploy that stopped before it was ready) to be up. It
/// asks nothing, so it can run beside a build.
pub(crate) async fn wait(api: &Api, resource: &Resource, say: &Say) -> Result<(), CliError> {
    let id = vps_id(resource)?;
    say.line(&t!("worker_vps.ready.waiting", id));
    let ready = erpc_ai::ready::wait_until_ready(
        &api.client,
        &api.token,
        &json!({ "family": "vps", "userVpsId": id }),
    )
    .await
    .map_err(|e| failed(t!("worker_vps.ready.failed", id, reason = e)))?;
    if ready["ready"] == json!(false) {
        return Err(failed(t!(
            "worker_vps.ready.failed",
            id,
            reason = ready["status"]
                .as_str()
                .map_or_else(|| t!("worker_vps.no_reason"), ToOwned::to_owned)
        )));
    }
    Ok(())
}

/// Once VPS `resource` is up ([`wait`]): makes it key-only, which shows
/// its host key and asks the person, or says it under `--yes`. Nothing
/// else may be printing then.
pub(crate) async fn secure(api: &Api, resource: &Resource) -> Result<Server, CliError> {
    let id = vps_id(resource)?;
    let mut server = existing(api, id, resource.hourly).await?;
    if server.resource.region.is_none() {
        server.resource.region.clone_from(&resource.region);
    }
    Ok(server)
}

/// Ends the hourly VPS `env` runs on, as `erpc worker delete
/// --release-server` asks: on its `--yes` (`yes`), else after the person's
/// yes.
pub(crate) async fn end(env: &Env, say: &Say, yes: bool) -> Result<Value, CliError> {
    let resource = env
        .resource
        .as_ref()
        .filter(|r| r.hourly)
        .ok_or_else(|| failed(t!("worker_vps.end.not_hourly")))?;
    let id: i64 = resource
        .id
        .parse()
        .map_err(|_| failed(t!("worker_vps.vps.bad_id", id = resource.id)))?;
    let product_type = match resource.kind {
        ResourceKind::BareMetal => "bare_metal",
        _ => "vps",
    };
    let kind = resource.kind.as_str();
    let api = Api::open().await?.releasing(yes);
    say.line(&t!("worker_vps.end.ending", kind, id));
    // What `erpc ai`'s end asks names an ERPC Worker by its product's name:
    // here it is said as the ERPC Worker it is.
    let answerer = end_answerer(api.confirm(), product_type, id);
    let ended = erpc_ai::actions::end_hourly_product(
        &api.client,
        &api.token,
        &json!({ "productType": product_type, "userProductId": id }),
        answerer.as_ref().map(|a| a as &dyn Confirm),
    )
    .await
    .map_err(failed)?;
    if ended["done"] != json!(true) {
        return Err(failed(t!(
            "worker_vps.end.failed",
            kind,
            id,
            answer = ended
        )));
    }
    Ok(ended)
}

/// How many looks at the account a VPS on record must be missing from,
/// and how far apart they are, before it is called missing: together
/// longer than user-api may take to list a VPS just bought
/// ([`erpc_ai::ready::UNLISTED`]) and than the credit snapshot is cached
/// ([`account::CREDIT_SNAPSHOT_CACHE`]), which the build checks.
const GONE_WINDOW: (u32, Duration) = (6, Duration::from_secs(15));
const _: () = {
    let (looks, every) = GONE_WINDOW;
    let span = every.as_secs() * (looks as u64 - 1);
    assert!(span > erpc_ai::ready::UNLISTED.as_secs());
    assert!(span > account::CREDIT_SNAPSHOT_CACHE.as_secs());
};

/// What one look at the account shows of a VPS on record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Seen {
    /// Among the account's VPSs, whatever their status, or charged for.
    There,
    /// Neither listed nor charged for.
    Missing,
}

/// An id as user-api writes it, a number or a string of one.
fn id_in(value: &Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_str().and_then(|s| s.parse().ok()))
}

/// The VPSs a credit snapshot charges for by the hour, by id; `None` when
/// it has no list, or a VPS row whose id cannot be read: that could be the
/// one looked for, so the look says nothing.
fn vps_charged_in(snapshot: &Value) -> Option<Vec<i64>> {
    let mut ids = Vec::new();
    for row in snapshot["message"]["hourlyResources"].as_array()? {
        if row["productType"].as_str() == Some("vps") {
            ids.push(id_in(&row["userProductId"])?);
        }
    }
    Some(ids)
}

/// VPS `id` as one look shows it: there when the account's VPS status
/// (`list`, a `/v3/vps/status` reply, which lists a pending VPS too) has
/// it or the account is charged for it by the hour (`charged`, from
/// [`vps_charged_in`]). `None` when the reply has no list, or a row
/// without an id: that says nothing.
fn seen(list: &Value, charged: &[i64], id: i64) -> Option<Seen> {
    let rows = list.get("data")?.as_array()?;
    // By its id, a number or a string of one; a row whose id cannot be
    // read could be this VPS, so the look says nothing.
    let mut listed = false;
    for row in rows {
        listed |= row.get("userVpsId").and_then(id_in)? == id;
    }
    let charged = charged.contains(&id);
    Some(if listed || charged {
        Seen::There
    } else {
        Seen::Missing
    })
}

/// What `looks` looks, `every` apart, find: missing only when every look
/// does; there as soon as one finds it; not known (`None`) as soon as one
/// cannot be read. `waiting` is called once, before the first wait.
async fn missing_throughout<F, Fut>(
    looks: u32,
    every: Duration,
    mut look: F,
    waiting: impl FnOnce(),
) -> Option<Seen>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Seen, CliError>>,
{
    let mut waiting = Some(waiting);
    for n in 0..looks {
        if n > 0 {
            if let Some(say) = waiting.take() {
                say();
            }
            tokio::time::sleep(every).await;
        }
        match look().await {
            Ok(Seen::There) => return Some(Seen::There),
            Ok(Seen::Missing) => {}
            Err(_) => return None,
        }
    }
    Some(Seen::Missing)
}

/// What the account signed in to says of the hourly VPS on record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OnAccount {
    /// Among its VPSs, or charged for.
    There,
    /// Missing from it at every look over more than a minute: ended outside
    /// erpc (in the dashboard, or by support), or a VPS of
    /// another account, which the record cannot tell apart. `account` is
    /// the account signed in to, as erpc names it, for the person to judge.
    Missing { account: String },
    /// Not known: not an hourly VPS, or the account could not be read.
    Unknown,
}

impl OnAccount {
    /// The account it is missing from, when it is.
    pub(crate) fn missing_from(&self) -> Option<&str> {
        match self {
            Self::Missing { account } => Some(account),
            _ => None,
        }
    }
}

/// What the account signed in to says of the hourly VPS `resource` on
/// record: missing only when it is neither among the account's VPSs nor
/// charged for at every one of several looks over more than a minute, so
/// that a VPS bought a moment ago, which user-api can take that long to
/// show, is never missing. A VPS missing from the account signed in to may
/// still be another account's: erpc.toml does not say whose it is, so the
/// caller names the account and leaves the judgement to the person at the
/// terminal. Anything but an hourly VPS is not known.
pub(crate) async fn on_account(api: &Api, resource: &Resource, say: &Say) -> OnAccount {
    let Ok(url) = erpc_ai::ready::vps_status_url() else {
        return OnAccount::Unknown;
    };
    let replies = || async move {
        Ok::<_, CliError>((
            api.read(url).await?,
            api.read(account::CREDIT_SNAPSHOT_URL).await?,
        ))
    };
    let name = || async move {
        account_name(
            erpc_api::get_user(&api.client, &api.token)
                .await
                .ok()
                .as_ref(),
        )
    };
    on_account_by(resource, replies, name, say).await
}

/// [`on_account`] with where its replies come from: `replies` gives the
/// VPS status and the credit snapshot of one look, `name` the account's
/// name, asked only when every look found the VPS missing. The looks are
/// [`GONE_WINDOW`]'s, always.
async fn on_account_by<R, RF, N, NF>(
    resource: &Resource,
    mut replies: R,
    name: N,
    say: &Say,
) -> OnAccount
where
    R: FnMut() -> RF,
    RF: Future<Output = Result<(Value, Value), CliError>>,
    N: FnOnce() -> NF,
    NF: Future<Output = Option<String>>,
{
    if resource.kind != ResourceKind::Vps || !resource.hourly {
        return OnAccount::Unknown;
    }
    let Ok(id) = resource.id.parse::<i64>() else {
        return OnAccount::Unknown;
    };
    let look = || {
        let reply = replies();
        async move {
            let (list, snapshot) = reply.await?;
            look_at(&list, &snapshot, id).ok_or_else(|| failed(t!("worker_vps.gone.no_list", id)))
        }
    };
    let (looks, every) = GONE_WINDOW;
    let seen = missing_throughout(looks, every, look, || {
        say.line(&t!("worker_vps.gone.looking", id));
    })
    .await;
    // Whose account it is missing from: asked only then.
    let account = if seen == Some(Seen::Missing) {
        name().await
    } else {
        None
    };
    judged(seen, account)
}

/// What one look shows of VPS `id`, from the account's VPS status (`list`)
/// and its credit snapshot: [`seen`] with the VPSs [`vps_charged_in`] reads.
fn look_at(list: &Value, snapshot: &Value, id: i64) -> Option<Seen> {
    vps_charged_in(snapshot).and_then(|charged| seen(list, &charged, id))
}

/// The account's name as erpc says it, from the account read (`None` when
/// it could not be): `None` too when it has no name to show, which would
/// leave the person nothing to judge by.
fn account_name(user: Option<&erpc_api::User>) -> Option<String> {
    user.map(erpc_api::User::label_for_display)
        .filter(|name| !name.trim().is_empty())
}

/// Whether a person can be asked what only they can say: at a terminal,
/// and not under `--json` (`quiet`), whose output is for a program.
/// `--yes` answers none of it.
pub(crate) const fn can_ask(quiet: bool, terminal: bool) -> bool {
    !quiet && terminal
}

/// What the looks (`seen`, `None` when one could not be read) and the
/// account's name (`None` when it could not be read) come to: missing
/// only with both, there when a look found it, else not known.
fn judged(seen: Option<Seen>, account: Option<String>) -> OnAccount {
    match (seen, account) {
        (Some(Seen::There), _) => OnAccount::There,
        (Some(Seen::Missing), Some(account)) => OnAccount::Missing { account },
        _ => OnAccount::Unknown,
    }
}

/// How user-api names a data line of each kind.
struct LineProduct {
    /// The hourly family that starts one.
    family: &'static str,
    /// The start reply's field with its id.
    id_field: &'static str,
    /// Its `productType` in the credit snapshot, which ending it takes.
    product_type: &'static str,
    /// Its key in [`account::SERVICE_STATUS_URLS`].
    status_key: &'static str,
    /// How long it may take to become active, and how often to look.
    wait: Duration,
    poll: Duration,
}

const fn line_product(kind: LineKind) -> LineProduct {
    match kind {
        LineKind::Grpc => LineProduct {
            family: "grpc",
            id_field: "userGrpcId",
            product_type: "grpc",
            status_key: "grpc",
            wait: Duration::from_mins(3),
            poll: Duration::from_secs(5),
        },
        LineKind::Shreds => LineProduct {
            family: "shreds-shared",
            id_field: "userShredsId",
            product_type: "shreds",
            status_key: "shreds",
            wait: Duration::from_mins(3),
            poll: Duration::from_secs(5),
        },
        // Two products under one kind: the family and the product type here
        // are Standard's, and `UDP_FAMILIES` has both where it matters
        // (`udp_row`, `is_charged`, `end_line`). It is listed by its own
        // `my` routes, not a status URL, so the status key is never looked
        // up.
        LineKind::Udp => LineProduct {
            family: "udp-forwarding",
            id_field: "subscriptionId",
            product_type: "one_hop_direct",
            status_key: "udp",
            wait: Duration::from_mins(10),
            poll: Duration::from_secs(5),
        },
        // A dedicated server is set up for it: user-api allows 45 minutes.
        LineKind::Unlimited => LineProduct {
            family: "user-unlimited",
            id_field: "userUnlimitedId",
            product_type: "unlimited",
            status_key: "unlimited_rpc",
            wait: Duration::from_mins(50),
            poll: Duration::from_secs(15),
        },
    }
}

/// The hourly products the account is charged for now, as (`productType`,
/// `userProductId`), from the credit snapshot: the record of what is
/// charged, which a status list (set up, or not yet) is not.
pub(crate) async fn charged(api: &Api) -> Result<Vec<(String, i64)>, CliError> {
    let snapshot = api.read(account::CREDIT_SNAPSHOT_URL).await?;
    charged_in(&snapshot).ok_or_else(|| failed(t!("worker_vps.end.no_hourly_list")))
}

/// What a credit snapshot charges for by the hour, as [`charged`] gives
/// it, ids written as numbers or strings; `None` when it has no list.
fn charged_in(snapshot: &Value) -> Option<Vec<(String, i64)>> {
    let rows = snapshot["message"]["hourlyResources"].as_array()?;
    Some(
        rows.iter()
            .filter_map(|r| {
                Some((
                    r["productType"].as_str()?.to_owned(),
                    id_in(&r["userProductId"])?,
                ))
            })
            .collect(),
    )
}

/// Whether a line on record is gone from the account: the one rule deploy
/// and delete both go by. Only a line billed by the hour, seen with its
/// endpoint before, and neither listed nor charged for is gone. A line just
/// started (both can be behind for a minute) or not billed by the hour never
/// is: the operator says so, with `--forget-line`.
/// `on_record` is the line's (billed by the hour, pending: its endpoint
/// never seen).
pub(crate) const fn is_gone(on_record: (bool, bool), listed: bool, charged: bool) -> bool {
    let (hourly, pending) = on_record;
    hourly && !pending && !listed && !charged
}

/// Whether `line` is among what [`charged`] lists. A UDP Forwarding line is
/// charged as either of its products.
pub(crate) fn is_charged(charged: &[(String, i64)], line: &Line) -> bool {
    line.id.parse::<i64>().is_ok_and(|id| {
        charged
            .iter()
            .any(|(t, n)| *n == id && is_product_of(line.kind, t))
    })
}

/// Whether a credit snapshot's `product_type` is one a line of `kind` is
/// charged as.
pub(crate) fn is_product_of(kind: LineKind, product_type: &str) -> bool {
    match kind {
        LineKind::Udp => UDP_FAMILIES.iter().any(|f| f.product_type == product_type),
        kind => line_product(kind).product_type == product_type,
    }
}

/// The account's data line `id` of `kind`, as its status lists it, or
/// `None` when the account has no such line.
pub(crate) async fn line_row(
    api: &Api,
    kind: LineKind,
    id: &str,
) -> Result<Option<Value>, CliError> {
    if kind == LineKind::Udp {
        return Ok(udp_row(api, id).await?.map(|(_, row)| row));
    }
    Ok(line_rows(api, kind)
        .await?
        .into_iter()
        .find(|row| is_row_of(row, id)))
}

/// UDP Forwarding line `id` as its product's `my` list has it, with the
/// product: the Standard list is read first, then the Premium one, and
/// `None` means neither lists it. A `my` reply with no list in it is an
/// error, as [`line_rows`] treats one.
async fn udp_row(api: &Api, id: &str) -> Result<Option<(&'static UdpFamily, Value)>, CliError> {
    for family in &UDP_FAMILIES {
        if let Some(row) = udp_rows(api, family)
            .await?
            .into_iter()
            .find(|row| is_row_of(row, id))
        {
            // The list it is in says what it is; its own word, when it
            // has one, is the same.
            return Ok(Some((udp_family_of(&row).unwrap_or(family), row)));
        }
    }
    Ok(None)
}

/// The account's lines of UDP Forwarding `family`.
async fn udp_rows(api: &Api, family: &UdpFamily) -> Result<Vec<Value>, CliError> {
    let reply = api
        .read_udp(family.my_url)
        .await
        .map_err(|e| udp_unread(family, &e))?;
    reply["data"]
        .as_array()
        .cloned()
        .ok_or_else(|| failed(t!("worker_vps.line.no_list", kind = LineKind::Udp.label())))
}

/// A UDP Forwarding list that could not be read, as the operator is told:
/// a refusal in user-api's own words (it answers one for a route it does
/// not open to erpc's sign-in), anything else as a call that got no
/// answer.
fn udp_unread(family: &UdpFamily, error: &erpc_api::ApiError) -> CliError {
    match error {
        erpc_api::ApiError::Refused { .. } | erpc_api::ApiError::Status(_) => {
            failed(t!("worker_vps.line.udp_refused", name = family.name, error))
        }
        _ => CliError::new(Code::Network, t!("worker_vps.api_silent", error)),
    }
}

/// The addresses a UDP Forwarding line sends from, as its row names them:
/// Standard's one `sourceIp`, Premium's `sourceIps`. Nothing until a node
/// is allocated (null, or an empty string). Sorted, each once, so that the
/// record reads the same however user-api orders them, and the same list
/// is never taken for a change.
///
/// A source that is not an IPv4 address is the error, as user-api gave it
/// (cut to what can be printed): left out, the list would be shorter than
/// what the line sends from, or empty, and an empty list is what "no
/// address named" looks like.
fn udp_sources(row: &Value) -> Result<Vec<Ipv4Addr>, String> {
    let named = |value: &Value| match value {
        Value::Null => None,
        Value::String(s) if s.trim().is_empty() => None,
        Value::String(s) => Some(s.trim().parse::<Ipv4Addr>().map_err(|_| {
            s.chars()
                .filter(|c| !c.is_control())
                .take(64)
                .collect::<String>()
        })),
        other => Some(Err(other.to_string().chars().take(64).collect())),
    };
    let many = row["sourceIps"].as_array().into_iter().flatten();
    let mut sources = std::iter::once(&row["sourceIp"])
        .chain(many)
        .filter_map(named)
        .collect::<Result<Vec<Ipv4Addr>, String>>()?;
    sources.sort_unstable();
    sources.dedup();
    Ok(sources)
}

/// [`udp_sources`] of line `id`, its error as the operator is told.
fn udp_sources_of(id: &str, row: &Value) -> Result<Vec<Ipv4Addr>, CliError> {
    udp_sources(row).map_err(|source| failed(t!("worker_vps.line.udp_bad_source", id, source)))
}

/// The UDP port a UDP Forwarding line on record sends to, from its
/// endpoint (`0.0.0.0:<port>`); `None` while it is pending.
pub(crate) fn udp_port(line: &Line) -> Option<u16> {
    line.endpoint
        .parse::<SocketAddrV4>()
        .ok()
        .map(|address| address.port())
}

/// The addresses UDP Forwarding line `id` sends from now, or `None` when
/// neither list has it: what a deploy reads again, since ERPC may move the
/// line. One that is not an IPv4 address is an error, and the record stays
/// as it was.
pub(crate) async fn udp_sources_now(
    api: &Api,
    id: &str,
) -> Result<Option<Vec<Ipv4Addr>>, CliError> {
    udp_row(api, id)
        .await?
        .map(|(_, row)| udp_sources_of(id, &row))
        .transpose()
}

/// The id of the account's active data line of `kind` that lets in `ip`,
/// if it has one: what `erpc worker run` takes up rather than buy another.
pub(crate) async fn line_letting_in(
    api: &Api,
    kind: LineKind,
    ip: Ipv4Addr,
) -> Result<Option<String>, CliError> {
    let ip = ip.to_string();
    Ok(line_rows(api, kind).await?.iter().find_map(|row| {
        (row["status"] == "active" && line_ips(row).contains(&ip.as_str())).then(|| {
            row["id"]
                .as_i64()
                .map(|n| n.to_string())
                .or_else(|| row["id"].as_str().map(ToOwned::to_owned))
        })?
    }))
}

/// The account's data lines of `kind`, as their status lists them; for UDP
/// Forwarding, both products' lists together.
async fn line_rows(api: &Api, kind: LineKind) -> Result<Vec<Value>, CliError> {
    if kind == LineKind::Udp {
        let mut rows = Vec::new();
        for family in &UDP_FAMILIES {
            rows.extend(udp_rows(api, family).await?);
        }
        return Ok(rows);
    }
    let product = line_product(kind);
    let url = account::SERVICE_STATUS_URLS
        .iter()
        .find(|(k, _)| *k == product.status_key)
        .map(|(_, url)| *url)
        .ok_or_else(|| failed(t!("worker_vps.line.no_status", kind = kind.label())))?;
    let reply = api.read(url).await?;
    // A reply with no list says nothing about the line: not taken as
    // "the account has none", which would let a deploy buy another.
    let rows = [reply.get("data"), reply.get("message")]
        .into_iter()
        .flatten()
        .find_map(Value::as_array)
        .ok_or_else(|| failed(t!("worker_vps.line.no_list", kind = kind.label())))?;
    Ok(rows.clone())
}

/// The addresses a line's status row lets in: one for gRPC and Shreds, a
/// list for Unlimited RPC.
fn line_ips(row: &Value) -> Vec<&str> {
    match &row["whitelistIps"] {
        Value::Array(list) => list.iter().filter_map(Value::as_str).collect(),
        _ => row["whiteListIp"].as_str().into_iter().collect(),
    }
}

/// A line's endpoint as the app dials it. user-api gives gRPC and Shreds
/// as `http://<host>`, served over TLS on 443 too, which is what the app
/// gets; an Unlimited RPC is `http://<address>:<port>`, served without
/// TLS, and kept as it is.
pub(crate) fn line_endpoint(kind: LineKind, given: &str) -> Option<String> {
    if kind == LineKind::Unlimited {
        let given = given.trim_end_matches('/');
        return kind.endpoint_ok(given).then(|| given.to_owned());
    }
    let host = ["https://", "http://"]
        .iter()
        .find_map(|scheme| given.strip_prefix(scheme))?
        .trim_end_matches('/');
    erpc_worker::net::is_host(host).then(|| ["https", host].join("://"))
}

/// A UDP Forwarding plan the catalogue offers: its product, id and price.
#[derive(Debug)]
struct UdpPlan {
    family: &'static UdpFamily,
    id: String,
    cents: f64,
}

/// The UDP Forwarding plans the hourly catalogue offers, both products.
fn udp_plans(catalog: &Value) -> Vec<UdpPlan> {
    UDP_FAMILIES
        .iter()
        .flat_map(|family| {
            catalog["families"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|f| f["family"].as_str() == Some(family.family))
                .flat_map(|f| f["plans"].as_array().cloned().unwrap_or_default())
                .filter_map(move |p| {
                    Some(UdpPlan {
                        family,
                        id: p["productId"].as_str()?.to_owned(),
                        cents: p["hourlyCents"].as_f64()?,
                    })
                })
        })
        .collect()
}

/// The UDP Forwarding plan to start: the one `asked` names, in either
/// product, else the cheapest of both. The product chosen decides the
/// regions the line can send from.
fn choose_udp_plan<'a>(
    offered: &'a [UdpPlan],
    asked: Option<&str>,
) -> Result<&'a UdpPlan, CliError> {
    match asked {
        Some(id) => offered.iter().find(|p| p.id == id).ok_or_else(|| {
            failed(t!(
                "worker_vps.plan.not_offered",
                id,
                family = UDP_FAMILY_NAMES
            ))
        }),
        None => offered
            .iter()
            .min_by(|a, b| a.cents.total_cmp(&b.cents))
            .ok_or_else(|| failed(t!("worker_vps.plan.none", family = UDP_FAMILY_NAMES))),
    }
}

/// Refuses `region` when the product of `chosen` does not send from it,
/// saying which regions it does; when the other product in `offered`
/// does, the hint names its plan.
fn udp_region_ok(chosen: &UdpPlan, region: &str, offered: &[UdpPlan]) -> Result<(), CliError> {
    if chosen.family.regions.contains(&region) {
        return Ok(());
    }
    let error = udp_bad_region(chosen.family, region);
    let elsewhere = offered
        .iter()
        .find(|p| p.family.family != chosen.family.family && p.family.regions.contains(&region));
    Err(match elsewhere {
        Some(other) => error.hint(t!(
            "worker_vps.line.udp_region_elsewhere",
            name = other.family.name,
            region,
            product = other.id
        )),
        None => error,
    })
}

/// The refusal of `region` for UDP Forwarding product `family`, naming the
/// regions it sends from.
fn udp_bad_region(family: &UdpFamily, region: &str) -> CliError {
    CliError::new(
        Code::Usage,
        t!(
            "worker_vps.line.udp_bad_region",
            region,
            name = family.name,
            regions = family.regions.join(", ")
        ),
    )
}

/// Refuses `region` for the plan a UDP Forwarding start would take
/// (`plan`, else the cheapest): asked before a new VPS is bought there.
pub(crate) async fn udp_region_ready(
    api: &Api,
    plan: Option<&str>,
    region: &str,
) -> Result<(), CliError> {
    let offered = udp_plans(&api.read(hourly::CATALOG_URL).await?);
    udp_region_ok(choose_udp_plan(&offered, plan)?, region, &offered)
}

/// The port and region a UDP Forwarding line is started for, which
/// `target` must name.
pub(crate) fn udp_target(target: &LineTarget) -> Result<(u16, &str), CliError> {
    let port = target
        .udp_port
        .ok_or_else(|| failed(t!("worker_vps.line.udp_no_port")))?;
    let region = target.region.as_deref().ok_or_else(udp_no_region)?;
    Ok((port, region))
}

/// The refusal of a UDP Forwarding line for a server whose region erpc
/// does not know (one of the user's own): it needs `--udp-region`.
pub(crate) fn udp_no_region() -> CliError {
    failed(t!("worker_vps.line.udp_no_region")).hint(t!("worker_vps.line.udp_no_region_hint"))
}

/// The account's line of `family` that is started and pointed nowhere, if
/// it has one, other than `except` (the environment's own on record): what a deploy that stopped before pointing it leaves, or a
/// start from the dashboard or `erpc ai` not pointed yet. Standard only,
/// billed by the hour and
/// neither cancelled nor suspended: such a line is charged from its start,
/// so starting another beside it would pay for two. (A Premium line is
/// charged only once it is pointed.)
fn unpointed_udp_line(family: &UdpFamily, rows: &[Value], except: Option<&str>) -> Option<String> {
    if !family.charged_from_start {
        return None;
    }
    rows.iter()
        .find(|row| {
            row["billingCycle"].as_str() == Some("hourly")
                && !matches!(row["status"].as_str(), Some("cancelled" | "suspended"))
                && row["destination"].as_str().is_none_or(str::is_empty)
                && except.is_none_or(|id| !is_row_of(row, id))
        })
        .and_then(|row| {
            row["id"]
                .as_i64()
                .map(|n| n.to_string())
                .or_else(|| row["id"].as_str().map(ToOwned::to_owned))
        })
}

/// Offers the account's unpointed line `id` of `family`
/// ([`unpointed_udp_line`]) to the person at the terminal (`confirm`) in
/// place of a new one, and says whether they took it up. `to` is where the
/// line would send, and the region it would send from.
async fn take_up_unpointed(
    confirm: &dyn Confirm,
    family: &UdpFamily,
    id: &str,
    to: (&str, &str),
) -> bool {
    let (destination, region) = to;
    let ask = erpc_ai::confirm::Confirmation {
        title: t!("worker_vps.adopt.title", name = family.name, id),
        lines: vec![
            (
                t!("worker_vps.adopt.charged"),
                t!("worker_vps.adopt.charged_already"),
            ),
            (
                t!("worker_vps.adopt.sends_to"),
                t!("worker_vps.adopt.destination", destination, region),
            ),
            (
                t!("worker_vps.adopt.otherwise"),
                t!("worker_vps.adopt.a_second"),
            ),
        ],
    };
    confirm.confirm(&ask).await
}

/// What becomes of the account's unpointed line `id` of `family`, by who
/// answers the start: the person is asked ([`take_up_unpointed`]), and
/// `--yes` refuses, naming it: whose line it is (this app's, or another's
/// whose deploy stopped before pointing it) is no price to accept, and
/// taking up another's would leave two records naming one line. With
/// nobody to answer, the start that follows refuses for that reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unpointed {
    Ask,
    Refuse,
    Pass,
}

impl Unpointed {
    const fn by(who: Option<Answerer>) -> Self {
        match who {
            Some(Answerer::Person) => Self::Ask,
            Some(Answerer::Yes) => Self::Refuse,
            None => Self::Pass,
        }
    }
}

/// What a UDP Forwarding start is checked against before what it would
/// follow is bought ([`udp_ready`]).
#[derive(Debug, Default)]
pub(crate) struct UdpCheck<'a> {
    /// The plan asked for (`--udp-plan`); the cheapest when none is.
    pub(crate) plan: Option<&'a str>,
    /// The environment's own UDP Forwarding line on record: the deploy
    /// takes it up, so it is never the line the start stops for.
    pub(crate) on_record: Option<&'a str>,
    /// Whether a UDP Forwarding start is on record, which is sent again.
    pub(crate) pending: bool,
    /// The region the line would send from, when it is known yet.
    pub(crate) region: Option<&'a str>,
    /// Whether nothing was bought by this deploy before the check: what a
    /// refusal then says of what is charged.
    pub(crate) nothing_bought: bool,
    /// The app and environment, as a hint's command names them.
    pub(crate) scope: &'a str,
}

/// What `deploy --udp` would be refused for at the UDP step, asked before
/// the server and the other lines are bought (and again before any line is
/// started, the server known): the plan asked for (or the cheapest), the
/// region it would send from when it is known, its product's list of the
/// account's lines, and, under `--yes`, no line of that product pointed
/// nowhere that the start would stop for ([`Unpointed`]), other than the
/// environment's own on record and unless a start is on record. Asked only
/// at the UDP step, a refusal would leave what was bought before it
/// charged. It only reads.
///
/// # Errors
///
/// What [`udp_start`] would refuse for.
pub(crate) async fn udp_ready(api: &Api, check: &UdpCheck<'_>) -> Result<(), CliError> {
    // The environment's own line, when the account lists it: the deploy
    // takes it up and starts nothing, so no start is judged, only the
    // region it would be pointed from, against its own product (a Premium
    // line in dublin is not refused for Standard's regions).
    let offered = udp_plans(&api.read(hourly::CATALOG_URL).await?);
    if let Some(id) = check.on_record
        && let Some((family, row)) = udp_row(api, id)
            .await
            .map_err(|e| list_refused(&e, check.nothing_bought))?
    {
        // A plan asked for is still one the catalogue offers, and of the
        // line's own product: a line keeps its product, and the deploy
        // takes it up whatever the plan says.
        if let Some(plan) = check.plan {
            let asked = choose_udp_plan(&offered, Some(plan))?;
            if asked.family.family != family.family {
                return Err(CliError::new(
                    Code::Usage,
                    t!(
                        "worker_vps.line.udp_other_product",
                        id,
                        name = family.name,
                        plan,
                        asked = asked.family.name
                    ),
                )
                .hint(t!(
                    "worker_vps.line.udp_other_product_hint",
                    id,
                    plan,
                    scope = check.scope
                )));
            }
        }
        // One that ended or was suspended sends nothing: the deploy would
        // be refused at the UDP step, after the lines before it.
        match row["status"].as_str() {
            Some("cancelled") => {
                return Err(failed(t!("worker_vps.line.udp_cancelled", id))
                    .hint(t!("worker_vps.line.udp_cancelled_hint", id)));
            }
            Some("suspended") => {
                let kind = LineKind::Udp.label();
                return Err(failed(t!("worker_vps.line.suspended", kind, id))
                    .hint(t!("worker_vps.line.suspended_hint")));
            }
            _ => {}
        }
        return match check.region {
            Some(region) if !family.regions.contains(&region) => {
                Err(udp_bad_region(family, region))
            }
            _ => Ok(()),
        };
    }
    let chosen = choose_udp_plan(&offered, check.plan)?;
    if let Some(region) = check.region {
        udp_region_ok(chosen, region, &offered)?;
    }
    let listed = udp_rows(api, chosen.family)
        .await
        .map_err(|e| list_refused(&e, check.nothing_bought))?;
    if !check.pending
        && let Some(id) = unpointed_udp_line(chosen.family, &listed, check.on_record)
        && Unpointed::by(api.start_answerer()) == Unpointed::Refuse
    {
        let name = chosen.family.name;
        return Err(failed(t!("worker_vps.adopt.not_under_yes", name, id))
            .hint(t!("worker_vps.adopt.not_under_yes_hint", id)));
    }
    Ok(())
}

/// A product's list user-api would not give, as the refusal of a UDP
/// Forwarding start: nothing started and nothing charged when nothing was
/// bought before it; else only that no UDP line was started, since what
/// was bought before it is charged, and said so after.
fn list_refused(e: &CliError, nothing_bought: bool) -> CliError {
    let message = if nothing_bought {
        t!("worker_vps.line.udp_not_startable", error = e.message)
    } else {
        t!("worker_vps.line.udp_not_started", error = e.message)
    };
    CliError::new(e.code, message).hint(t!("worker_vps.line.udp_not_startable_hint"))
}

/// What a UDP Forwarding start comes to before anything is started.
enum UdpStart {
    /// The account's unpointed line, taken up in place of a new one.
    TakenUp(String),
    /// A new line of this product, at this plan.
    Buy(&'static UdpFamily, String),
}

/// The part of [`start_line`] that is UDP Forwarding's, before anything is
/// started: the plan, the regions its product sends from, the product's
/// list, and the account's unpointed line, which is offered in place of a
/// new one ([`take_up_unpointed`]) and goes on `record` when taken up.
async fn udp_start(
    api: &Api,
    target: &LineTarget,
    asked_plan: Option<&str>,
    record: &mut dyn LineRecord,
    say: &Say,
) -> Result<UdpStart, CliError> {
    let ip = target.ip;
    let (port, region) = udp_target(target)?;
    let offered = udp_plans(&api.read(hourly::CATALOG_URL).await?);
    let chosen = choose_udp_plan(&offered, asked_plan)?;
    udp_region_ok(chosen, region, &offered)?;
    // The product's list is read before anything is started: every step
    // after the start reads it, so a start whose list is refused would be
    // charged and then go no further.
    // Reached after the server, and perhaps other lines, were bought: the
    // refusal says no UDP line was started, and what is charged is said
    // after it.
    let listed = udp_rows(api, chosen.family)
        .await
        .map_err(|e| list_refused(&e, false))?;
    // Not while a start is on record: the line that start may have made is
    // listed unpointed too, and the start sent again with its key is what
    // finds it.
    let destination = format!("{ip}:{port}");
    let unpointed = record
        .pending()
        .is_none()
        .then(|| unpointed_udp_line(chosen.family, &listed, None))
        .flatten();
    if let Some(id) = unpointed {
        let name = chosen.family.name;
        match Unpointed::by(api.start_answerer()) {
            Unpointed::Ask => {
                let to = (destination.as_str(), region);
                if take_up_unpointed(&api.confirm, chosen.family, &id, to).await {
                    record.named(&id)?;
                    say.line(&t!("worker_vps.line.udp_taken_up", id));
                    return Ok(UdpStart::TakenUp(id));
                }
            }
            Unpointed::Refuse => {
                return Err(failed(t!("worker_vps.adopt.not_under_yes", name, id))
                    .hint(t!("worker_vps.adopt.not_under_yes_hint", id)));
            }
            Unpointed::Pass => {}
        }
    }
    let name = product_name(api, &chosen.id)
        .await
        .unwrap_or_else(|| chosen.id.clone());
    say.line(&t!(
        "worker_vps.line.buying_udp",
        name,
        product = chosen.id,
        how = how_chosen(asked_plan),
        price = format!("{:.4}", chosen.cents / 100.0),
        ip,
        port,
        region,
    ));
    Ok(UdpStart::Buy(chosen.family, chosen.id.clone()))
}

/// Starts an hourly data line of `kind` for the server `target` names,
/// once its price is answered (by the person, or by `--yes` on a deploy,
/// which says it). It may not be active yet, nor let the server in (nor,
/// for UDP Forwarding, send to it): [`wait_line`] sees to that. Its
/// request goes through `record`, as a VPS's does ([`buy`]), and so does
/// the line user-api names.
pub(crate) async fn start_line(
    api: &Api,
    kind: LineKind,
    target: &LineTarget,
    asked_plan: Option<&str>,
    scope: &str,
    say: &Say,
    record: &mut dyn LineRecord,
) -> Result<String, CliError> {
    let product = line_product(kind);
    let ip = target.ip;
    // What makes it this purchase, besides its family and plan: an
    // Unlimited RPC's region, or the address a gRPC or Shreds line lets
    // in. A UDP Forwarding start names neither: where the line sends from
    // and to is set once it is started, so a start sent again for another
    // port or region is still the same purchase.
    let (family, chosen_id, fields, region, let_in) = match kind {
        LineKind::Udp => match udp_start(api, target, asked_plan, record, say).await? {
            UdpStart::TakenUp(id) => return Ok(id),
            // The start route takes no body: the product's one plan is
            // what is started, so the plan chosen names the family.
            UdpStart::Buy(family, product) => (family.family, product, json!({}), None, None),
        },
        LineKind::Unlimited => {
            let region = target.region.as_deref().ok_or_else(|| {
                failed(t!("worker_vps.line.no_region")).hint(t!("worker_vps.line.no_region_hint"))
            })?;
            let chosen = plan(api, product.family, asked_plan).await?;
            say_buying(kind, &chosen, asked_plan, ip, say);
            (
                product.family,
                chosen.id.clone(),
                json!({ "region": region, "productId": chosen.id }),
                Some(region.to_owned()),
                None,
            )
        }
        LineKind::Grpc | LineKind::Shreds => {
            let chosen = plan(api, product.family, asked_plan).await?;
            say_buying(kind, &chosen, asked_plan, ip, say);
            (
                product.family,
                chosen.id.clone(),
                json!({ "ip": ip.to_string(), "productId": chosen.id }),
                None,
                Some(ip.to_string()),
            )
        }
    };
    let confirm = api.confirm_start()?;
    let wanted = Start {
        key: String::new(),
        family: family.to_owned(),
        product: chosen_id,
        region,
        ip: let_in,
    };
    let input = json!({ "family": family, "fields": fields });
    let sent = start_on_record(&wanted, product.id_field, record, say, async |key| {
        erpc_ai::actions::start_hourly_product_with_key(
            &api.client,
            &api.token,
            &input,
            Some(confirm),
            key,
        )
        .await
    })
    .await?;
    let (id, started) = match sent {
        Sent::Made { id, started } => (id, started),
        // Refused, and its request is off the record but for `stays`
        // (`start_on_record`). A line user-api names all the same goes on
        // record (`named`), so that the next deploy finds it rather than
        // buy another.
        Sent::Refused { started, stays } => {
            let error = failed(t!(
                "worker_vps.line.not_started",
                kind = kind.label(),
                status = started["httpStatus"],
                reason = reason(&started)
            ));
            let hint = if let Some(id) = named_id(&started, product.id_field) {
                record.named(&id)?;
                Some(t!("worker_vps.line.made_anyway", id, scope))
            } else {
                refused_hint(&started, stays.as_deref(), None)
            };
            return Err(match hint {
                Some(hint) => error.hint(hint),
                None => error,
            });
        }
    };
    record.named(&id)?;
    if let Some(warning) = started["registerWarning"].as_str() {
        say.line(&t!("worker_vps.line.warned", warning));
    }
    say.line(&t!("worker_vps.line.started", kind = kind.label(), id));
    Ok(id)
}

/// Says what line is about to be bought, for the kinds that let `ip` in.
fn say_buying(kind: LineKind, chosen: &Plan, asked_plan: Option<&str>, ip: Ipv4Addr, say: &Say) {
    say.line(&t!(
        "worker_vps.line.buying",
        kind = kind.label(),
        name = chosen.name,
        product = chosen.id,
        how = how_chosen(asked_plan),
        price = format!("{:.4}", chosen.cents / 100.0),
        ip,
    ));
}

/// Line `id` of `kind` as erpc.toml keeps it, once its status lists it
/// with an endpoint: right after a start, before it is active, so that it
/// is on record however the wait ends. A UDP Forwarding line has no
/// endpoint of user-api's: it is pending once listed, and [`wait_line`]
/// fills in the port it is pointed at and the addresses it sends from.
pub(crate) async fn first_sight(
    api: &Api,
    kind: LineKind,
    id: &str,
    hourly: bool,
    scope: &str,
) -> Result<Line, CliError> {
    first_sight_within(api, kind, id, hourly, scope, (20, Duration::from_secs(3))).await
}

/// [`first_sight`], looking `tries` times with `pause` between
/// (`patience`): a minute as deploy asks, less in a test.
async fn first_sight_within(
    api: &Api,
    kind: LineKind,
    id: &str,
    hourly: bool,
    scope: &str,
    patience: (u32, Duration),
) -> Result<Line, CliError> {
    let (tries, pause) = patience;
    for _ in 0..tries {
        let row = line_row(api, kind, id).await?;
        if kind == LineKind::Udp && row.is_some() {
            return Ok(Line {
                kind,
                id: id.to_owned(),
                endpoint: String::new(),
                hourly,
                sources: Vec::new(),
            });
        }
        if let Some(endpoint) = row.and_then(|row| {
            row["endpoint"]
                .as_str()
                .and_then(|e| line_endpoint(kind, e))
        }) {
            return Ok(Line {
                kind,
                id: id.to_owned(),
                endpoint,
                hourly,
                sources: Vec::new(),
            });
        }
        tokio::time::sleep(pause).await;
    }
    Err(
        failed(t!("worker_vps.line.no_endpoint", kind = kind.label(), id))
            .hint(t!("worker_vps.line.no_endpoint_hint", scope)),
    )
}

/// Lets `ip` in to Unlimited RPC `id`, keeping the addresses it lets in
/// already (`allowed`; user-api replaces the whole list). `Ok(false)` when
/// user-api kept the whitelist but could not apply it to the line's server
/// yet, which it says while the server is still being set up.
async fn let_in(api: &Api, id: &str, ip: Ipv4Addr, allowed: &[&str]) -> Result<bool, CliError> {
    let number = id
        .parse()
        .map_err(|_| failed(t!("worker_vps.line.bad_id", id)))?;
    let list = whitelist(ip, allowed);
    match account::set_unlimited_whitelist(&api.client, &api.token, number, &list).await {
        Ok(_) => Ok(true),
        Err(erpc_api::ApiError::Refused {
            status: 502,
            message,
        }) if message.to_ascii_lowercase().contains("saved") => Ok(false),
        Err(e) => Err(
            failed(t!("worker_vps.line.let_in_failed", ip, id, error = e))
                .hint(t!("worker_vps.line.let_in_hint")),
        ),
    }
}

/// `ip` and the addresses in `allowed`, once each: the whitelist erpc sets.
/// user-api's whitelist takes single IPv4 addresses only, so nothing else
/// can be in `allowed` to keep.
fn whitelist(ip: Ipv4Addr, allowed: &[&str]) -> Vec<Ipv4Addr> {
    let mut list: Vec<Ipv4Addr> = allowed.iter().filter_map(|a| a.parse().ok()).collect();
    if !list.contains(&ip) {
        list.push(ip);
    }
    list
}

/// Waits for data line `id` of `kind` to be active and to let in the
/// server `target` names, and returns it as erpc.toml keeps it. An
/// Unlimited RPC's whitelist is set to the server's address while it is
/// set up, and again once it is active, which is when user-api can apply
/// it to the line's server for certain. A UDP Forwarding line is pointed
/// at the server's address and port ([`wait_udp_line`]).
pub(crate) async fn wait_line(
    api: &Api,
    kind: LineKind,
    id: &str,
    target: &LineTarget,
    hourly: bool,
    say: &Say,
) -> Result<Line, CliError> {
    // A person at a terminal sees a spinner while the line is set up, which
    // can take a while with nothing else to show; its message carries what
    // would otherwise be said in lines, which a spinner's redraws would
    // break. The caller says what came of the wait.
    let spinner = (!say.quiet && crate::cli::ui::stderr_drawn()).then(|| {
        crate::cli::prompt::Spinner::start(&t!(
            "worker_vps.line.waiting_for",
            kind = kind.label(),
            id
        ))
    });
    let tell = |text: String| match &spinner {
        Some(spinner) => spinner.set_message(&text),
        None => say.line(&text),
    };
    let waited = if kind == LineKind::Udp {
        wait_udp_line(
            api,
            id,
            target,
            hourly,
            Pace::of(&line_product(kind)),
            &tell,
        )
        .await
    } else {
        wait_line_saying(api, kind, id, target.ip, hourly, &tell).await
    };
    if let Some(spinner) = spinner {
        spinner.done();
    }
    waited
}

/// Whether a refusal to point a UDP Forwarding line is one to try again
/// next round: user-api is still applying the last change (409
/// `UDP_FORWARDING_PREMIUM_APPLY_IN_PROGRESS`), or a change came within a
/// minute of the one before (429 `UDP_FORWARDING_PREMIUM_CHANGE_TOO_SOON`).
fn point_again_later(error: &erpc_api::ApiError) -> bool {
    match error {
        erpc_api::ApiError::Refused { status: 429, .. } => true,
        erpc_api::ApiError::Refused {
            status: 409,
            message,
        } => message.contains("APPLY_IN_PROGRESS"),
        _ => false,
    }
}

/// How long an active UDP Forwarding line is given to name the addresses
/// it sends from before it is taken as it is, naming none: its port then
/// stays closed unless the operator opens it to any address.
const UDP_SOURCES_GRACE: Duration = Duration::from_secs(60);

/// How long a UDP Forwarding line is waited for: in all, between two
/// looks, and for its addresses once it is active.
#[derive(Debug, Clone, Copy)]
struct Pace {
    wait: Duration,
    poll: Duration,
    grace: Duration,
}

impl Pace {
    const fn of(product: &LineProduct) -> Self {
        Self {
            wait: product.wait,
            poll: product.poll,
            grace: UDP_SOURCES_GRACE,
        }
    }
}

/// Points UDP Forwarding line `id` (`number` to user-api) at `destination`
/// from `region`, and tells so: `Ok(false)` when user-api is still applying
/// the last change, to try again next round ([`point_again_later`]); any
/// other refusal is the error.
async fn point_udp_line(
    api: &Api,
    family: &UdpFamily,
    id: &str,
    number: i64,
    region: &str,
    destination: &str,
    tell: &dyn Fn(String),
) -> Result<bool, CliError> {
    match api
        .set_udp_destination(family.destination_url, number, region, destination)
        .await
    {
        Ok(_) => {
            tell(t!("worker_vps.line.udp_pointed", id, destination, region));
            Ok(true)
        }
        Err(e) if point_again_later(&e) => Ok(false),
        Err(e) => {
            let hint = if erpc_api::udp::pointing_may_pass_later(&e) {
                t!("worker_vps.line.udp_point_hint")
            } else {
                t!("worker_vps.line.udp_point_hint_end")
            };
            Err(failed(t!(
                "worker_vps.line.udp_point_failed",
                id,
                destination,
                region,
                error = e
            ))
            .hint(hint))
        }
    }
}

/// Whether `e` is a refused pointing that comes back the same however often
/// it is tried ([`erpc_api::udp::pointing_may_pass_later`]): the line is
/// then better ended than waited for again.
pub(crate) fn is_refused_for_good(e: &CliError) -> bool {
    e.hint.as_deref() == Some(t!("worker_vps.line.udp_point_hint_end").as_str())
}

/// Whether `e` is [`wait_line`]'s refusal of UDP Forwarding line `id` for
/// being cancelled: it is charged no more, and waiting cannot bring it
/// back, so nothing is said of waiting for it again.
pub(crate) fn is_udp_cancelled(e: &CliError, id: &str) -> bool {
    e.message == t!("worker_vps.line.udp_cancelled", id)
}

/// What is wrong with a UDP Forwarding line, as its row says it, to tell
/// once per text while waiting.
#[derive(Debug, PartialEq, Eq)]
enum UdpTrouble {
    /// A Standard line found no node with a free slot in its region: it
    /// keeps its destination and waits for one, in `provisioning` or
    /// `error`, with the reason in `lastError`.
    Capacity(String),
    /// Any other `lastError`, or `error` with no reason given.
    Error(String),
}

/// The trouble `row` reports, if any. `lastError` is read whatever the
/// status: user-api writes the reason a line waits into it without
/// changing the status, and clears it once the line is placed.
fn udp_trouble(row: &Value) -> Option<UdpTrouble> {
    // user-api's free text, as a terminal may be given it: one line, with
    // nothing it acts on, and no longer than a line should be.
    let error = row["lastError"]
        .as_str()
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .map(|e| {
            crate::storage::clean(e)
                .chars()
                .take(300)
                .collect::<String>()
        });
    let error = error.as_deref();
    let capacity = row["lastAllocationOutcome"].as_str() == Some("region_unavailable");
    match (error, row["status"].as_str()) {
        (Some(e), _) if capacity => Some(UdpTrouble::Capacity(e.to_owned())),
        (Some(e), _) => Some(UdpTrouble::Error(e.to_owned())),
        (None, Some("error")) => Some(UdpTrouble::Error(t!("worker_vps.no_reason"))),
        _ => None,
    }
}

/// Waits for UDP Forwarding line `id` to be active and pointed at the
/// server `target` names, pointing it there when it is not, and returns it
/// with the port the app binds and the addresses the line sends from: none
/// when user-api names none within `pace.grace` of the line being active.
async fn wait_udp_line(
    api: &Api,
    id: &str,
    target: &LineTarget,
    hourly: bool,
    pace: Pace,
    tell: &dyn Fn(String),
) -> Result<Line, CliError> {
    let label = LineKind::Udp.label();
    let (port, region) = udp_target(target)?;
    let number: i64 = id
        .parse()
        .map_err(|_| failed(t!("worker_vps.line.bad_id", id)))?;
    let destination = format!("{}:{port}", target.ip);
    let line = |sources: Vec<Ipv4Addr>| Line {
        kind: LineKind::Udp,
        id: id.to_owned(),
        endpoint: format!("0.0.0.0:{port}"),
        hourly,
        sources,
    };
    let mut last = t!("worker_vps.line.not_listed");
    let started = Instant::now();
    // Pointed once per wait: user-api's row shows the change a little
    // later, and a second change within a minute is refused.
    let mut pointed = false;
    let mut active_since: Option<Instant> = None;
    let mut errors_told: Vec<String> = Vec::new();
    while started.elapsed() < pace.wait {
        if let Some((family, row)) = udp_row(api, id).await? {
            let status = row["status"].as_str().unwrap_or("unknown");
            match status {
                "cancelled" => {
                    return Err(failed(t!("worker_vps.line.udp_cancelled", id))
                        .hint(t!("worker_vps.line.udp_cancelled_hint", id)));
                }
                "suspended" => {
                    return Err(failed(t!("worker_vps.line.suspended", kind = label, id))
                        .hint(t!("worker_vps.line.suspended_hint")));
                }
                _ => {}
            }
            let as_wanted = row["destination"].as_str() == Some(destination.as_str())
                && row["region"].as_str() == Some(region);
            if !as_wanted && !pointed {
                pointed =
                    point_udp_line(api, family, id, number, region, &destination, tell).await?;
            }
            if status == "active" && as_wanted {
                let sources = udp_sources_of(id, &row)?;
                if !sources.is_empty() {
                    return Ok(line(sources));
                }
                // Active and pointed right, with no address named: given a
                // minute, then taken as it is. What its port is opened to
                // is the caller's to decide, and to say.
                let since = *active_since.get_or_insert_with(Instant::now);
                if since.elapsed() >= pace.grace {
                    return Ok(line(Vec::new()));
                }
            } else {
                active_since = None;
            }
            if status != last {
                tell(t!(
                    "worker_vps.line.waiting",
                    id,
                    status,
                    minutes = started.elapsed().as_secs() / 60
                ));
                status.clone_into(&mut last);
            }
            // Said once per text, whatever the status: a Standard line with
            // no free node in its region stays `provisioning` with the
            // reason in `lastError`, and would otherwise wait in silence.
            if let Some(trouble) = udp_trouble(&row) {
                let said = match trouble {
                    UdpTrouble::Capacity(error) => {
                        t!("worker_vps.line.udp_waiting_capacity", id, error)
                    }
                    UdpTrouble::Error(error) => t!("worker_vps.line.udp_error", id, error),
                };
                if !errors_told.contains(&said) {
                    tell(said.clone());
                    errors_told.push(said);
                }
            }
        }
        tokio::time::sleep(pace.poll).await;
    }
    Err(failed(tn!(
        "worker_vps.line.not_active",
        pace.wait.as_secs() / 60,
        kind = label,
        id,
        last
    )))
}

async fn wait_line_saying(
    api: &Api,
    kind: LineKind,
    id: &str,
    ip: Ipv4Addr,
    hourly: bool,
    tell: &dyn Fn(String),
) -> Result<Line, CliError> {
    let product = line_product(kind);
    let mut last = t!("worker_vps.line.not_listed");
    let started = Instant::now();
    let mut kept = false;
    let mut applied = false;
    while started.elapsed() < product.wait {
        if let Some(row) = line_row(api, kind, id).await? {
            let status = row["status"].as_str().unwrap_or("unknown");
            let allowed = line_ips(&row);
            if !allowed.is_empty() && !allowed.contains(&ip.to_string().as_str()) {
                return Err(failed(t!(
                    "worker_vps.line.wrong_ip",
                    kind = kind.label(),
                    id,
                    allowed = allowed.join(", "),
                    ip
                )));
            }
            if kind == LineKind::Unlimited
                && !applied
                && ((allowed.is_empty() && !kept) || status == "active")
            {
                applied = let_in(api, id, ip, &allowed).await?;
                if !kept {
                    tell(if applied {
                        t!("worker_vps.line.lets_in", id, ip)
                    } else {
                        t!("worker_vps.line.lets_in_later", id, ip)
                    });
                }
                kept = true;
            }
            let endpoint = row["endpoint"]
                .as_str()
                .and_then(|e| line_endpoint(kind, e));
            let let_in_now = if kind == LineKind::Unlimited {
                applied
            } else {
                !allowed.is_empty()
            };
            match (status, endpoint) {
                ("active", Some(endpoint)) if let_in_now => {
                    return Ok(Line {
                        kind,
                        id: id.to_owned(),
                        endpoint,
                        hourly,
                        sources: Vec::new(),
                    });
                }
                ("suspended", _) => {
                    return Err(
                        failed(t!("worker_vps.line.suspended", kind = kind.label(), id))
                            .hint(t!("worker_vps.line.suspended_hint")),
                    );
                }
                (status, _) => {
                    if status != last {
                        if kind == LineKind::Unlimited {
                            tell(t!(
                                "worker_vps.line.waiting",
                                id,
                                status,
                                minutes = started.elapsed().as_secs() / 60
                            ));
                        }
                        status.clone_into(&mut last);
                    }
                }
            }
        }
        tokio::time::sleep(product.poll).await;
    }
    Err(failed(tn!(
        "worker_vps.line.not_active",
        product.wait.as_secs() / 60,
        kind = kind.label(),
        id,
        last
    )))
}

/// Which UDP Forwarding product line `id` is, for ending it: the one the
/// credit snapshot charges the id as, else the one whose list has it, else
/// Standard.
async fn udp_product_type(api: &Api, id: i64) -> &'static str {
    let charged_as = charged(api).await.ok().and_then(|charged| {
        charged
            .into_iter()
            .filter(|(_, n)| *n == id)
            .find_map(|(t, _)| UDP_FAMILIES.iter().find(|f| f.product_type == t))
    });
    match charged_as {
        Some(family) => family.product_type,
        None => udp_row(api, &id.to_string())
            .await
            .ok()
            .flatten()
            .map_or(UDP_FAMILIES[0].product_type, |(family, _)| {
                family.product_type
            }),
    }
}

/// Ends hourly data line `line`, after the yes `api` gives for an end
/// ([`Api::confirm`]): `--yes`, in a session [`Api::releasing`] made with
/// it; else the person's.
pub(crate) async fn end_line(api: &Api, line: &Line, say: &Say) -> Result<Value, CliError> {
    let id: i64 = line
        .id
        .parse()
        .map_err(|_| failed(t!("worker_vps.line.bad_id", id = line.id)))?;
    let product_type = match line.kind {
        LineKind::Udp => udp_product_type(api, id).await,
        kind => line_product(kind).product_type,
    };
    say.line(&t!("worker_vps.line.ending", kind = line.kind.label(), id));
    let ended = erpc_ai::actions::end_hourly_product(
        &api.client,
        &api.token,
        &json!({ "productType": product_type, "userProductId": id }),
        api.confirm(),
    )
    .await
    .map_err(failed)?;
    if ended["done"] != json!(true) {
        return Err(failed(t!(
            "worker_vps.line.end_failed",
            kind = line.kind.label(),
            id,
            answer = ended
        )));
    }
    Ok(ended)
}

/// The loopback server that stands in for user-api in tests.
#[cfg(test)]
#[path = "user_api_stub.rs"]
pub(crate) mod stub;

/// The conversation with user-api about a UDP Forwarding line, against
/// [`stub`].
#[cfg(test)]
#[path = "udp_line_tests.rs"]
mod udp_line_tests;

/// In a test: a [`KeySource`] that reaches neither user-api nor the RPC.
#[cfg(test)]
pub(crate) mod fake {
    use std::cell::{Cell, RefCell};

    use serde_json::{Value, json};

    use super::{CliError, KeySource, Verdict};

    /// An account as a script describes it: what user-api answers for its
    /// dashboard, and what the shared RPC makes of each of its keys, which
    /// is that it takes them unless the script says otherwise. It keeps
    /// the keys it was asked about, in order, and counts the reads of the
    /// dashboard.
    pub(crate) struct Scripted {
        reply: Result<Value, CliError>,
        verdicts: Vec<(&'static str, Verdict)>,
        pub(crate) asked: RefCell<Vec<String>>,
        pub(crate) reads: Cell<usize>,
    }

    impl Scripted {
        /// An account whose dashboard answers `message`.
        pub(crate) fn account(message: &Value) -> Self {
            Self::answering(Ok(json!({ "message": message })))
        }

        /// An account whose dashboard read ends as `reply`.
        pub(crate) fn answering(reply: Result<Value, CliError>) -> Self {
            Self {
                reply,
                verdicts: Vec::new(),
                asked: RefCell::new(Vec::new()),
                reads: Cell::new(0),
            }
        }

        /// The same, with the shared RPC making `verdict` of `key`.
        #[must_use]
        pub(crate) fn with(mut self, key: &'static str, verdict: Verdict) -> Self {
            self.verdicts.push((key, verdict));
            self
        }

        /// The keys the shared RPC was asked about, in order.
        pub(crate) fn asked(&self) -> Vec<String> {
            self.asked.borrow().clone()
        }
    }

    impl KeySource for Scripted {
        fn dashboard(&self) -> impl Future<Output = Result<Value, CliError>> {
            self.reads.set(self.reads.get() + 1);
            core::future::ready(self.reply.clone())
        }

        fn takes(&self, key: zeroize::Zeroizing<String>) -> impl Future<Output = Verdict> {
            self.asked.borrow_mut().push(key.as_str().to_owned());
            let verdict = self
                .verdicts
                .iter()
                .find(|(named, _)| *named == key.as_str())
                .map_or(Verdict::Accepted, |(_, verdict)| *verdict);
            core::future::ready(verdict)
        }
    }

    /// The same account, lent: a test that hands it over to be opened can
    /// still look at what it was asked.
    impl KeySource for &Scripted {
        fn dashboard(&self) -> impl Future<Output = Result<Value, CliError>> {
            Scripted::dashboard(self)
        }

        fn takes(&self, key: zeroize::Zeroizing<String>) -> impl Future<Output = Verdict> {
            Scripted::takes(self, key)
        }
    }
}

#[cfg(test)]
mod tests {
    use erpc_worker::manifest::{LineKind, Start};
    use serde_json::{Value, json};

    use super::{
        LineTarget, Say, UDP_FAMILIES, UdpPlan, UdpTrouble, choose_udp_plan, is_add_on,
        line_endpoint, line_ips, region_for_zone, udp_family_of, udp_plans, udp_port,
        udp_region_ok, udp_sources, udp_target, udp_trouble,
    };

    #[tokio::test]
    async fn the_key_the_shared_rpc_takes_is_the_one_used() {
        use super::{Verdict, account_keys, usable};
        // The primary key first, then the others, each once and none empty.
        let keys = account_keys(&json!({
            "apiKey": "primary",
            "activeApiKeys": ["primary", "second", "", "third", "second"],
        }));
        let names: Vec<&str> = keys.iter().map(|k| k.as_str()).collect();
        assert_eq!(names, ["primary", "second", "third"]);
        assert!(account_keys(&json!({ "apiKey": "" })).is_empty());
        assert_eq!(account_keys(&json!({ "apiKey": "only" })).len(), 1);

        // The key picked and whether the RPC accepted it, with the keys it
        // was asked about, in order.
        let picked = |refused: &'static [&'static str], away: &'static [&'static str]| {
            let keys = keys.clone();
            async move {
                let asked = std::cell::RefCell::new(Vec::new());
                let picked = usable(&keys, |key| {
                    asked.borrow_mut().push(key.as_str().to_owned());
                    async move {
                        if refused.contains(&key.as_str()) {
                            Verdict::Refused
                        } else if away.contains(&key.as_str()) {
                            Verdict::Unknown
                        } else {
                            Verdict::Accepted
                        }
                    }
                })
                .await
                .map(|(key, accepted)| (key.as_str().to_owned(), accepted));
                (picked, asked.into_inner().join(" "))
            }
        };
        let (accepted, unconfirmed) = (
            |key: &str| Some((key.to_owned(), true)),
            |key: &str| Some((key.to_owned(), false)),
        );
        // Accepted: the one, and no key after it is asked about.
        assert_eq!(
            picked(&[], &[]).await,
            (accepted("primary"), "primary".to_owned())
        );
        // A primary key that has run out does not hide one that works.
        assert_eq!(
            picked(&["primary"], &[]).await,
            (accepted("second"), "primary second".to_owned())
        );
        assert_eq!(
            picked(&["primary", "second"], &[]).await,
            (accepted("third"), "primary second third".to_owned())
        );
        // Nor does one the RPC could not be asked about: a key it accepts
        // is the one, wherever it comes after.
        assert_eq!(
            picked(&[], &["primary"]).await,
            (accepted("second"), "primary second".to_owned())
        );
        assert_eq!(
            picked(&["second"], &["primary"]).await,
            (accepted("third"), "primary second third".to_owned())
        );
        // None accepted: an RPC that cannot be asked does not make a key
        // a bad one, so the first it could not be asked about is used, and
        // said to be unconfirmed. Every key was asked about by then.
        assert_eq!(
            picked(&[], &["primary", "second", "third"]).await,
            (unconfirmed("primary"), "primary second third".to_owned())
        );
        assert_eq!(
            picked(&["primary"], &["second", "third"]).await,
            (unconfirmed("second"), "primary second third".to_owned())
        );
        assert_eq!(
            picked(&["second", "third"], &["primary"]).await,
            (unconfirmed("primary"), "primary second third".to_owned())
        );
        // Never a key it refused.
        assert_eq!(
            picked(&["primary", "second", "third"], &[]).await,
            (None, "primary second third".to_owned())
        );
    }

    /// The table from what the shared RPC answered to what that says of
    /// the key.
    #[test]
    fn only_401_and_403_are_the_keys_refusal() {
        use super::{Verdict, verdict};
        for (status, expected) in [
            (200, Verdict::Accepted),
            (204, Verdict::Accepted),
            (401, Verdict::Refused),
            (403, Verdict::Refused),
            // The plan's rate limit, the RPC's own failures, a redirect
            // and any other refusal of the request are not the key's.
            (429, Verdict::Unknown),
            (500, Verdict::Unknown),
            (502, Verdict::Unknown),
            (503, Verdict::Unknown),
            (301, Verdict::Unknown),
            (302, Verdict::Unknown),
            (307, Verdict::Unknown),
            (400, Verdict::Unknown),
            (402, Verdict::Unknown),
            (404, Verdict::Unknown),
        ] {
            let answered = reqwest::StatusCode::from_u16(status).expect("a status");
            assert_eq!(verdict(Some(answered)), expected, "HTTP {status}");
        }
        // No answer at all, which is how the HTTP client reports a
        // connection that failed and a wait that ran out alike (each is
        // driven on the wire in the test below).
        assert_eq!(verdict(None), Verdict::Unknown);
    }

    /// What a double of the shared RPC does with a request.
    #[derive(Debug, Clone, Copy)]
    enum Reply {
        /// Answers with this status.
        Status(u16),
        /// Answers 302, with another path of its own to go to.
        Redirect,
        /// Closes the connection without a word: a transport error.
        Hangup,
        /// Keeps the connection and never answers: a timeout.
        Silence,
    }

    /// The requests a double of the shared RPC got: the first line and the
    /// body of each.
    type Got = std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>;

    /// A double of the shared RPC on loopback, which does `reply` with
    /// every request. Returns its URL, and the requests it got.
    fn rpc_double(reply: Reply) -> (String, Got) {
        use std::io::{BufRead as _, BufReader, Read as _, Write as _};
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("a port");
        let port = listener.local_addr().expect("bound").port();
        let got = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = got.clone();
        std::thread::spawn(move || {
            // Connections left open for as long as the double lives.
            let mut open = Vec::new();
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut reader = BufReader::new(stream.try_clone().expect("a second handle"));
                let mut first = String::new();
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    if first.is_empty() {
                        first = line.trim_end().to_owned();
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = v.trim().parse().expect("a length");
                    }
                }
                let mut body = vec![0; length];
                if reader.read_exact(&mut body).is_err() {
                    continue;
                }
                seen.lock()
                    .expect("the requests")
                    .push((first, String::from_utf8_lossy(&body).into_owned()));
                let head = match reply {
                    Reply::Status(status) => format!("HTTP/1.1 {status} Said"),
                    Reply::Redirect => "HTTP/1.1 302 Found\r\nlocation: /elsewhere".to_owned(),
                    Reply::Hangup => continue,
                    Reply::Silence => {
                        open.push(stream);
                        continue;
                    }
                };
                let _ = write!(
                    stream,
                    "{head}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                );
            }
        });
        (format!("http://127.0.0.1:{port}"), got)
    }

    /// The question itself, against a double of the shared RPC: one POST
    /// of `getHealth` with the key in the query, and the verdict from how
    /// it ends.
    #[tokio::test]
    async fn a_key_is_asked_about_with_one_get_health_and_judged_by_how_it_ends() {
        use super::{Verdict, asked_at};
        use std::time::Duration;
        let key = || zeroize::Zeroizing::new("the-key".to_owned());
        for (reply, expected) in [
            (Reply::Status(200), Verdict::Accepted),
            (Reply::Status(401), Verdict::Refused),
            (Reply::Status(403), Verdict::Refused),
            (Reply::Status(429), Verdict::Unknown),
            (Reply::Status(500), Verdict::Unknown),
            (Reply::Redirect, Verdict::Unknown),
            (Reply::Hangup, Verdict::Unknown),
            (Reply::Silence, Verdict::Unknown),
        ] {
            let (url, got) = rpc_double(reply);
            // Silence is waited out, for long enough that the double has
            // read the request by then; the rest answer at once.
            let wait = match reply {
                Reply::Silence => Duration::from_secs(1),
                _ => Duration::from_secs(20),
            };
            let started = std::time::Instant::now();
            assert_eq!(asked_at(&url, wait, key()).await, expected, "{reply:?}");
            // The wait it is handed is the one kept to: silence ends the
            // question after its second, long before the 30 seconds the
            // HTTP client would wait of its own.
            let took = started.elapsed();
            assert!(took < Duration::from_secs(15), "{reply:?}: {took:?}");
            // Asked once: a redirect is not followed, and nothing is sent
            // again after a connection that broke or a wait that ran out.
            let got = got.lock().expect("the requests");
            assert_eq!(got.len(), 1, "{reply:?}: {got:?}");
            let (first, body) = &got[0];
            assert_eq!(first, "POST /?api-key=the-key HTTP/1.1", "{reply:?}");
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(body).expect("JSON"),
                json!({ "jsonrpc": "2.0", "id": 1, "method": "getHealth" }),
                "{reply:?}"
            );
        }
        // An address that is none asks nothing, and says nothing of the key.
        assert_eq!(
            asked_at("not an address", Duration::from_secs(1), key()).await,
            Verdict::Unknown
        );
    }

    /// What the real question is handed: the shared Solana RPC, whatever
    /// chain is called after, and 8 seconds for a key, which the guide
    /// says.
    #[test]
    fn a_key_is_asked_about_at_the_shared_solana_rpc_for_eight_seconds_at_most() {
        let (base, wait) = super::QUESTION;
        let url = reqwest::Url::parse(base).expect("an address");
        assert_eq!(
            (url.scheme(), url.host_str(), url.path(), url.query()),
            ("https", Some("edge.erpc.global"), "/", None)
        );
        assert_ne!(base, erpc_core::endpoints::ETH_RPC_URL);
        assert_eq!(wait, std::time::Duration::from_secs(8));
    }

    /// `shared_api_key`, the function every caller uses, with user-api and
    /// the shared RPC scripted.
    #[tokio::test]
    async fn the_accounts_keys_are_tried_in_order_from_the_primary_one() {
        use super::fake::Scripted;
        use super::{Verdict, shared_api_key};
        // The dashboard lists the primary key among the active ones, and
        // not first: it is still the one tried first.
        let account = || {
            Scripted::account(&json!({
                "apiKey": "primary",
                "activeApiKeys": ["second", "primary", "third"],
            }))
        };
        let picked = |from: &Scripted, key: &zeroize::Zeroizing<String>| {
            (key.as_str().to_owned(), from.asked())
        };
        // Taken: the primary key, and nothing more is asked.
        let from = account();
        let key = shared_api_key(&from).await.expect("a key");
        assert_eq!(
            picked(&from, &key),
            ("primary".to_owned(), vec!["primary".to_owned()])
        );
        assert_eq!(from.reads.get(), 1);
        // The first refused and the second taken: the second.
        let from = account().with("primary", Verdict::Refused);
        let key = shared_api_key(&from).await.expect("a key");
        assert_eq!(
            picked(&from, &key),
            (
                "second".to_owned(),
                vec!["primary".to_owned(), "second".to_owned()]
            )
        );
        // The first could not be asked about and the second is taken: the
        // second, which the RPC is known to take.
        let from = account().with("primary", Verdict::Unknown);
        let key = shared_api_key(&from).await.expect("a key");
        assert_eq!(
            picked(&from, &key),
            (
                "second".to_owned(),
                vec!["primary".to_owned(), "second".to_owned()]
            )
        );
        // None taken, and one the RPC could not be asked about: a call
        // made from here goes on with that one, which is not known to be
        // a bad one, once every key was asked about. The call tells.
        let all = || {
            vec![
                "primary".to_owned(),
                "second".to_owned(),
                "third".to_owned(),
            ]
        };
        let from = account()
            .with("primary", Verdict::Unknown)
            .with("second", Verdict::Refused)
            .with("third", Verdict::Refused);
        let key = shared_api_key(&from).await.expect("a key");
        assert_eq!(picked(&from, &key), ("primary".to_owned(), all()));
        let from = account()
            .with("primary", Verdict::Refused)
            .with("second", Verdict::Unknown)
            .with("third", Verdict::Unknown);
        let key = shared_api_key(&from).await.expect("a key");
        assert_eq!(picked(&from, &key), ("second".to_owned(), all()));
    }

    /// What trying the keys came to, as a test compares it: `Tried` holds
    /// a key and has no `Debug`.
    fn came_to(tried: super::Tried) -> String {
        match tried {
            super::Tried::Usable {
                key,
                accepted,
                which,
            } => {
                let standing = if accepted { "accepted" } else { "unconfirmed" };
                format!("{}: {standing}, {}", key.as_str(), which.word())
            }
            super::Tried::Refused { primary, tried } => {
                format!("{}: refused, {tried} tried", primary.as_str())
            }
        }
    }

    /// `keys_tried` says of the key it gives whether the shared RPC
    /// accepted it, and whether it is the account's primary key.
    #[tokio::test]
    async fn a_key_to_use_is_said_to_be_accepted_or_not_and_primary_or_not() {
        use super::fake::Scripted;
        use super::{Verdict, keys_tried};
        let account = || {
            Scripted::account(&json!({
                "apiKey": "primary",
                "activeApiKeys": ["second", "primary", "third"],
            }))
        };
        let tried = async |from: Scripted| {
            let came = came_to(keys_tried(&from).await.expect("tried"));
            (came, from.asked().join(" "))
        };
        // The primary key accepted: nothing else is asked.
        assert_eq!(
            tried(account()).await,
            (
                "primary: accepted, primary".to_owned(),
                "primary".to_owned()
            )
        );
        // The primary key refused, or not to be asked about, and the
        // second accepted: the second, one of the account's other keys.
        for verdict in [Verdict::Refused, Verdict::Unknown] {
            assert_eq!(
                tried(account().with("primary", verdict)).await,
                (
                    "second: accepted, other".to_owned(),
                    "primary second".to_owned()
                ),
                "{verdict:?}"
            );
        }
        // The primary key not to be asked about, and no other accepted:
        // the primary one, unconfirmed, after every key was asked about.
        assert_eq!(
            tried(
                account()
                    .with("primary", Verdict::Unknown)
                    .with("second", Verdict::Refused)
                    .with("third", Verdict::Refused)
            )
            .await,
            (
                "primary: unconfirmed, primary".to_owned(),
                "primary second third".to_owned()
            )
        );
        // The same of another key, the first of two not to be asked about.
        assert_eq!(
            tried(
                account()
                    .with("primary", Verdict::Refused)
                    .with("second", Verdict::Unknown)
                    .with("third", Verdict::Unknown)
            )
            .await,
            (
                "second: unconfirmed, other".to_owned(),
                "primary second third".to_owned()
            )
        );
        // An account alone with its primary key, which cannot be asked
        // about: that one, unconfirmed.
        let alone = Scripted::account(&json!({ "apiKey": "only" })).with("only", Verdict::Unknown);
        assert_eq!(
            tried(alone).await,
            ("only: unconfirmed, primary".to_owned(), "only".to_owned())
        );
        // An account whose dashboard gives no primary key: the first of
        // its active keys is tried first, and is not said to be primary.
        let no_primary = Scripted::account(&json!({ "activeApiKeys": ["first", "next"] }));
        assert_eq!(
            tried(no_primary).await,
            ("first: accepted, other".to_owned(), "first".to_owned())
        );
    }

    #[tokio::test]
    async fn an_account_whose_keys_are_all_refused_or_that_has_none_is_an_error() {
        use super::fake::Scripted;
        use super::{Verdict, keys_tried, shared_api_key};
        use crate::cli::error::{CliError, Code};
        crate::cli::ui::force_drawn(false);
        // Every key refused: each was tried, once.
        let refused = || {
            Scripted::account(&json!({
                "apiKey": "primary",
                "activeApiKeys": ["second", "primary", "third"],
            }))
            .with("primary", Verdict::Refused)
            .with("second", Verdict::Refused)
            .with("third", Verdict::Refused)
        };
        // What that means is the caller's to say, so it is handed the
        // primary key and how many were tried.
        let from = refused();
        assert_eq!(
            came_to(keys_tried(&from).await.expect("tried")),
            "primary: refused, 3 tried"
        );
        assert_eq!(from.asked(), ["primary", "second", "third"]);
        // For a call made from this machine it is an error. It says where
        // the keys were tried from and what that leaves open, counts them,
        // and names none.
        let from = refused();
        let e = shared_api_key(&from).await.expect_err("none taken");
        assert_eq!(from.asked(), ["primary", "second", "third"]);
        assert_eq!(e.code, Code::Failed);
        assert_eq!(
            e.text(),
            "error: the shared RPC takes none of the account's API keys from this machine (3 \
             tried)\nhint: the keys were tried from this machine, where a key limited to other \
             addresses is refused though it works from those; a key can also have an end date, \
             and the account's RPC plan can have ended: the ERPC dashboard shows both, and makes \
             a new key"
        );
        let said = format!("{} {}", e.text(), e.json());
        for key in ["primary", "second", "third"] {
            assert!(!said.contains(key), "{said}");
        }
        // Said in the language of the run, the count with it.
        for lang in [
            erpc_core::i18n::Lang::Ja,
            erpc_core::i18n::Lang::Zh,
            erpc_core::i18n::Lang::Ru,
        ] {
            let there = crate::cli::i18n::speaking(lang, || {
                super::keys_refused(3).hint(t!("worker_vps.keys_refused_hint"))
            });
            assert_ne!(there.message, e.message, "{lang:?}");
            assert_ne!(there.hint, e.hint, "{lang:?}");
            assert!(there.message.contains('3'), "{}", there.message);
            assert!(!there.text().contains('{'), "{}", there.text());
        }
        // An account with no key at all: said as that, and nothing is
        // asked of the RPC.
        for message in [json!({}), json!({ "apiKey": "", "activeApiKeys": [""] })] {
            let from = Scripted::account(&message);
            let e = shared_api_key(&from).await.expect_err("no key");
            assert_eq!(e.message, "the account has no API key for the shared RPC");
            assert_eq!(e.hint.as_deref(), Some("the ERPC dashboard makes one"));
            assert!(from.asked().is_empty());
        }
        // user-api silent: its error, and nothing is asked of the RPC.
        let silent = CliError::new(Code::Network, "user-api did not answer: timed out");
        let from = Scripted::answering(Err(silent.clone()));
        assert_eq!(shared_api_key(&from).await.expect_err("no reply"), silent);
        assert!(from.asked().is_empty());
    }

    #[test]
    fn a_start_is_answered_by_yes_or_by_the_person_and_refused_without_either() {
        use super::{Answerer, Asked, answerer, nobody};
        use crate::cli::error::Code;
        // --yes answers it, at a terminal or not: a person who passed it is
        // not asked again, and a script or an agent can start what it names.
        for asked in [Asked::Start, Asked::Login] {
            assert_eq!(answerer(asked, Some(true), false), Some(Answerer::Yes));
            assert_eq!(answerer(asked, Some(true), true), Some(Answerer::Yes));
            // Without it, the person at the terminal is asked.
            assert_eq!(answerer(asked, Some(false), true), Some(Answerer::Person));
            assert_eq!(answerer(asked, None, true), Some(Answerer::Person));
            // With neither, nobody answers.
            assert_eq!(answerer(asked, Some(false), false), None);
            assert_eq!(answerer(asked, None, false), None);
        }
        // The refusal says what to pass, in words for whoever ran the
        // command.
        let refused = nobody(Asked::Start, Some(false));
        assert_eq!(refused.code, Code::NeedsTerminal);
        let hint = refused.hint.expect("a hint");
        assert!(hint.contains("--yes"), "{hint}");
        assert!(!refused.message.contains("erpc ai"), "{}", refused.message);
        // A command with no --yes (`run`) is not told to pass one.
        let refused = nobody(Asked::Start, None);
        assert_eq!(refused.code, Code::NeedsTerminal);
        let hint = refused.hint.expect("a hint");
        assert!(!hint.contains("--yes"), "{hint}");
    }

    #[test]
    fn an_end_is_the_persons_to_answer_whatever_yes_says() {
        use super::{Answerer, Asked, answerer};
        // --yes was given: at a terminal the person is still asked, and
        // with nobody there nobody answers. It is never --yes.
        for yes in [Some(true), Some(false), None] {
            assert_eq!(
                answerer(Asked::End, yes, true),
                Some(Answerer::Person),
                "{yes:?}"
            );
            assert_eq!(answerer(Asked::End, yes, false), None, "{yes:?}");
        }
        // The session a deploy --yes makes hands out, for an end, what the
        // decision above says: the person's confirmation, or none.
        let api = super::Api::offline().accepting(true);
        for terminal in [true, false] {
            assert_eq!(
                api.end_answerer(terminal),
                terminal.then_some(Answerer::Person),
                "an end was answered by --yes, or not asked of the person"
            );
        }
        assert!(api.confirm_start().is_ok(), "--yes answers a start");
    }

    #[test]
    fn yes_answers_the_ends_a_delete_release_server_names() {
        use super::{Answerer, Asked, answerer};
        // With --yes each end is said and done, a terminal or not.
        for terminal in [true, false] {
            assert_eq!(
                answerer(Asked::Release, Some(true), terminal),
                Some(Answerer::Yes),
                "{terminal}"
            );
        }
        // Without it, the person at the terminal, or nobody.
        for yes in [Some(false), None] {
            assert_eq!(
                answerer(Asked::Release, yes, true),
                Some(Answerer::Person),
                "{yes:?}"
            );
            assert_eq!(answerer(Asked::Release, yes, false), None, "{yes:?}");
        }
        // The session delete --release-server --yes makes has --yes answer
        // an end, a terminal or not; the one without --yes leaves it to the
        // person.
        for terminal in [true, false] {
            assert_eq!(
                super::Api::offline().releasing(true).end_answerer(terminal),
                Some(Answerer::Yes),
                "{terminal}"
            );
            assert_eq!(
                super::Api::offline()
                    .releasing(false)
                    .end_answerer(terminal),
                terminal.then_some(Answerer::Person),
                "{terminal}"
            );
        }
        // It is for those ends only: its --yes answers no start.
        assert_eq!(super::Api::offline().releasing(true).yes, None);
    }

    #[test]
    fn a_first_login_nobody_can_answer_is_not_refused_as_a_start() {
        use super::{Asked, nobody};
        use crate::cli::error::Code;
        let start = nobody(Asked::Start, Some(false));
        let login = nobody(Asked::Login, Some(false));
        assert_eq!(login.code, Code::NeedsTerminal);
        // It starts nothing and has no price, and says what it does.
        assert_ne!(login.message, start.message);
        assert!(!login.message.contains("by the hour"), "{}", login.message);
        assert!(
            login.message.contains("password logins off"),
            "{}",
            login.message
        );
        let hint = login.hint.expect("a hint");
        assert!(hint.contains("--yes") && !hint.contains("price"), "{hint}");
        // A command with no --yes is not told to pass one.
        let hint = nobody(Asked::Login, None).hint.expect("a hint");
        assert!(!hint.contains("--yes"), "{hint}");
    }

    /// A record kept in memory, as erpc.toml keeps one: the request on
    /// it, and how often one was put there.
    #[derive(Default)]
    struct Kept {
        start: Option<Start>,
        begun: u32,
        /// The record cannot be written.
        read_only: bool,
        /// A request on record cannot be taken off it.
        stuck: bool,
    }

    impl super::StartRecord for Kept {
        fn pending(&self) -> Option<Start> {
            self.start.clone()
        }

        fn begin(&mut self, start: &Start) -> Result<(), String> {
            if self.read_only {
                return Err("the disk is full".to_owned());
            }
            self.start = Some(start.clone());
            self.begun += 1;
            Ok(())
        }

        fn settle(&mut self) -> Result<(), String> {
            if self.stuck {
                return Err("the disk is full".to_owned());
            }
            self.start = None;
            Ok(())
        }

        fn stays_hint(&self, why: super::Stays) -> String {
            match why {
                super::Stays::Unanswered => "run the same command again",
                super::Stays::InProgress => "run the same command again shortly",
                super::Stays::NotKnown => "see the dashboard, then clear it by hand",
                super::Stays::Exists | super::Stays::Unnamed => {
                    "take it up or end it, then clear it by hand"
                }
            }
            .to_owned()
        }

        fn other_hint(&self) -> String {
            "clear it by hand".to_owned()
        }
    }

    /// The id of the purchase a start came back with.
    fn made(sent: super::Sent) -> String {
        match sent {
            super::Sent::Made { id, .. } => id,
            super::Sent::Refused { started, .. } => panic!("refused: {started}"),
        }
    }

    /// The reply a start was refused with, its request off the record.
    fn refused(sent: super::Sent) -> serde_json::Value {
        match sent {
            super::Sent::Refused { started, stays } => {
                assert_eq!(stays, None);
                started
            }
            super::Sent::Made { id, .. } => panic!("made {id}"),
        }
    }

    /// A new VPS in `region`, its key not chosen yet.
    fn vps(region: &str) -> Start {
        Start {
            key: String::new(),
            family: "vps".to_owned(),
            product: "prod_Vps1".to_owned(),
            region: Some(region.to_owned()),
            ip: None,
        }
    }

    const QUIET: Say = Say { quiet: true };

    #[test]
    fn a_purchase_takes_the_key_on_record_only_when_it_is_the_same_purchase() {
        use super::KeyFor;
        let wanted = vps("amsterdam");
        // None on record: a new key.
        assert_eq!(KeyFor::of(None, &wanted), KeyFor::New);
        // The same purchase got no answer: its key again.
        let on_record = Start {
            key: "a".repeat(32),
            ..wanted.clone()
        };
        assert_eq!(
            KeyFor::of(Some(&on_record), &wanted),
            KeyFor::Again("a".repeat(32))
        );
        // Another region, plan or address is another purchase: the key is
        // not sent for it, and no new one is made beside it.
        assert_eq!(KeyFor::of(Some(&on_record), &vps("tokyo")), KeyFor::Other);
        let other_plan = Start {
            product: "prod_Vps2".to_owned(),
            ..wanted.clone()
        };
        assert_eq!(KeyFor::of(Some(&on_record), &other_plan), KeyFor::Other);
        let grpc = |ip: &str| Start {
            key: "b".repeat(32),
            family: "grpc".to_owned(),
            product: "prod_Grpc1".to_owned(),
            region: None,
            ip: Some(ip.to_owned()),
        };
        assert_eq!(
            KeyFor::of(Some(&grpc("203.0.113.10")), &grpc("203.0.113.11")),
            KeyFor::Other
        );
        assert_eq!(
            super::purchase_name(&on_record),
            "vps prod_Vps1 (amsterdam)"
        );
        assert_eq!(
            super::purchase_name(&grpc("203.0.113.10")),
            "grpc prod_Grpc1 (203.0.113.10)"
        );
    }

    /// The UDP Forwarding start routes, as user-api answers them: a row
    /// made under the key comes back as `subscription` with its id (the
    /// same row again for a key sent before, `replayed`); a held hourly
    /// lock is `PURCHASE_IN_PROGRESS`; a key whose row is in another state,
    /// or a create that conflicts, is `UDP_FORWARDING_CONFLICT`; a failure
    /// upstream is a 502 with `UDP_FORWARDING_UPSTREAM_UNAVAILABLE`. Only
    /// the line itself, or a certain refusal of a first request, takes the
    /// request off the record.
    #[test]
    fn a_udp_forwarding_starts_answers_are_judged_as_any_starts_are() {
        use super::Answer::{self, InProgress, Made, NotKnown, Refused, Unanswered, Unrelated};
        let answered = |status: u16, code: &str, again| {
            let reply = json!({ "httpStatus": status, "code": code, "message": "" });
            Answer::of(
                Some(status),
                super::failure_code(&reply),
                false,
                false,
                again,
            )
        };
        for again in [false, true] {
            // The line, `subscriptionId` as erpc-ai surfaces it.
            let made = json!({ "done": true, "subscriptionId": 42, "replayed": again });
            let id = super::named_id(&made, "subscriptionId");
            assert_eq!(id.as_deref(), Some("42"));
            assert_eq!(Answer::of(Some(200), None, true, id.is_some(), again), Made);
            assert_eq!(answered(409, "PURCHASE_IN_PROGRESS", again), InProgress);
            assert_eq!(
                answered(502, "UDP_FORWARDING_UPSTREAM_UNAVAILABLE", again),
                Unanswered
            );
        }
        // A conflict says nothing of what the key made: it stays on record.
        assert_eq!(answered(409, "UDP_FORWARDING_CONFLICT", false), NotKnown);
        assert_eq!(answered(409, "UDP_FORWARDING_CONFLICT", true), Unrelated);
        // No credit for a first request: nothing was made under its key.
        assert_eq!(answered(402, "INSUFFICIENT_HEADROOM", false), Refused);
        assert_eq!(answered(402, "INSUFFICIENT_HEADROOM", true), Unrelated);
    }

    #[test]
    fn an_answer_is_judged_by_its_status_its_code_and_whether_it_was_sent_before() {
        use super::Answer::{
            self, InProgress, Made, NotKnown, OtherPurchase, Refused, Unanswered, Unmatched,
            Unnamed, Unrelated,
        };
        // A refusal: not started, and nothing named.
        let refusal = |status, code, again| Answer::of(Some(status), code, false, false, again);
        for again in [false, true] {
            // No answer, or one that says user-api did not get to it: the
            // request may have arrived.
            assert_eq!(Answer::of(None, None, false, false, again), Unanswered);
            for status in [408, 429, 500, 502, 503, 504, 599, 100, 301, 600] {
                assert_eq!(refusal(status, None, again), Unanswered, "{status}");
            }
            for status in [200, 201, 202] {
                // The purchase itself: started, and named.
                assert_eq!(Answer::of(Some(status), None, true, true, again), Made);
                // Started and not named: it exists, and erpc cannot put it
                // on record.
                assert_eq!(Answer::of(Some(status), None, true, false, again), Unnamed);
                // A 2xx that says it started nothing says too little.
                assert_eq!(
                    Answer::of(Some(status), None, false, false, again),
                    NotKnown
                );
            }
            // Still being made, first send or resend.
            assert_eq!(
                refusal(409, Some("PURCHASE_IN_PROGRESS"), again),
                InProgress
            );
        }
        // A first request: a refusal is certain, as nothing was made under
        // a key never sent before.
        for status in [400, 401, 402, 403, 404, 410, 422] {
            assert_eq!(refusal(status, None, false), Refused, "{status}");
        }
        for code in ["OUT_OF_STOCK", "REGION_DOWN"] {
            assert_eq!(refusal(409, Some(code), false), Refused, "{code}");
        }
        // A key made by this run that is another purchase's is not an
        // earlier request of erpc's: it goes.
        assert_eq!(
            refusal(409, Some("IDEMPOTENCY_CONFLICT"), false),
            OtherPurchase
        );
        // But a 409 erpc cannot read is not taken for a refusal.
        for code in [
            None,
            Some("SOMETHING_NEW"),
            Some("PAID_HOUR_TOKENS_USED_UP"),
        ] {
            assert_eq!(refusal(409, code, false), NotKnown, "{code:?}");
        }
        // A request sent again: the same conflict says a purchase exists
        // under its key, which may well be the earlier request's own.
        assert_eq!(refusal(409, Some("IDEMPOTENCY_CONFLICT"), true), Unmatched);
        // And no other refusal says what became of the first.
        for status in [400, 401, 402, 403, 404, 410, 422] {
            assert_eq!(refusal(status, None, true), Unrelated, "{status}");
        }
        for code in [
            None,
            Some("OUT_OF_STOCK"),
            Some("REGION_DOWN"),
            Some("SOMETHING_NEW"),
        ] {
            assert_eq!(refusal(409, code, true), Unrelated, "{code:?}");
        }
        // The codes count with a 409 only.
        assert_eq!(refusal(400, Some("IDEMPOTENCY_CONFLICT"), true), Unrelated);
        assert_eq!(refusal(400, Some("IDEMPOTENCY_CONFLICT"), false), Refused);
        assert_eq!(
            refusal(503, Some("PURCHASE_IN_PROGRESS"), false),
            Unanswered
        );
    }

    /// The rule, over every answer there can be: a request sent again
    /// leaves the record only when the answer is the purchase itself, or
    /// says that what was bought under its key has been ended.
    #[test]
    fn a_request_sent_again_leaves_the_record_only_on_the_purchase_itself_or_its_end() {
        use super::Answer;
        let status = json!(0);
        let codes = [
            None,
            Some("PURCHASE_IN_PROGRESS"),
            Some("IDEMPOTENCY_CONFLICT"),
            Some("OUT_OF_STOCK"),
            Some("REGION_DOWN"),
            Some("START_ENDED"),
            Some("SOMETHING_NEW"),
        ];
        let statuses = core::iter::once(None).chain((100..=599).map(Some));
        for http in statuses {
            for code in codes {
                for (done, named) in [(false, false), (false, true), (true, false), (true, true)] {
                    let answer = Answer::of(http, code, done, named, true);
                    let leaves = answer.stays(&status, "").is_none();
                    let purchase =
                        http.is_some_and(|http| (200..=299).contains(&http)) && done && named;
                    let ended = http == Some(409) && code == Some("START_ENDED");
                    assert_eq!(
                        leaves,
                        purchase || ended,
                        "{http:?} {code:?} done {done} named {named}: {answer:?}"
                    );
                    assert_eq!(answer == Answer::Made, purchase);
                    assert_eq!(answer == Answer::Ended, ended);
                }
            }
        }
        // A first request leaves on a certain refusal too, and on nothing
        // that leaves its outcome open.
        for (http, code, leaves) in [
            (402, None, true),
            (409, Some("OUT_OF_STOCK"), true),
            (409, Some("IDEMPOTENCY_CONFLICT"), true),
            (409, Some("PURCHASE_IN_PROGRESS"), false),
            (409, Some("START_ENDED"), true),
            (409, None, false),
            (503, None, false),
        ] {
            let answer = Answer::of(Some(http), code, false, false, false);
            assert_eq!(
                answer.stays(&status, "").is_none(),
                leaves,
                "{http} {code:?}: {answer:?}"
            );
        }
    }

    #[test]
    fn a_failure_code_is_read_from_code_or_from_a_message_that_is_one() {
        use super::failure_code;
        // The VPS route.
        let vps = json!({ "code": "PURCHASE_IN_PROGRESS", "message": "Another purchase is already in progress. Please retry shortly." });
        assert_eq!(failure_code(&vps), Some("PURCHASE_IN_PROGRESS"));
        // The gRPC, Shreds and Unlimited routes: the code is the message.
        for code in ["IDEMPOTENCY_CONFLICT", "PURCHASE_IN_PROGRESS"] {
            assert_eq!(failure_code(&json!({ "message": code })), Some(code));
        }
        // A sentence is no code, and neither is a word erpc does not act on.
        for message in [
            "Stored purchase identity is invalid; retry with the same key.",
            "OUT_OF_STOCK",
            "idempotency_conflict",
            "START_ENDED",
            "This purchase was ended while it was starting.",
            "this purchase was ended while it was starting. nothing more was granted.",
            "This purchase was ended while it was starting. Nothing more was granted. Retry.",
            " This purchase was ended while it was starting. Nothing more was granted.",
            "Not so: This purchase was ended while it was starting. Nothing more was granted.",
        ] {
            assert_eq!(failure_code(&json!({ "message": message })), None);
        }
        assert_eq!(failure_code(&json!({})), None);
        // The gRPC and Shreds routes' sentence for a start ended meanwhile,
        // whole, and only with no code of its own.
        let ended = "This purchase was ended while it was starting. Nothing more was granted.";
        assert_eq!(
            failure_code(&json!({ "message": ended })),
            Some("START_ENDED")
        );
        assert_eq!(
            failure_code(&json!({ "code": "SOMETHING_NEW", "message": ended })),
            Some("SOMETHING_NEW")
        );
    }

    /// The end-to-end case, short of user-api: a start times out, and the
    /// same command run again sends the same key.
    #[tokio::test]
    async fn a_start_that_got_no_answer_is_sent_again_with_the_same_key() {
        use super::{StartError, start_on_record};
        let mut record = Kept::default();
        let wanted = vps("amsterdam");
        let mut sent: Vec<String> = Vec::new();
        // The request leaves, and no answer comes back.
        let lost = start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |key| {
            sent.push(key()?);
            Err(StartError::Unanswered("it timed out".to_owned()))
        })
        .await
        .expect_err("no answer");
        assert!(
            lost.message.contains("may or may not have gone through"),
            "{}",
            lost.message
        );
        assert_eq!(lost.hint.as_deref(), Some("run the same command again"));
        // Its key was on record before it left, and stays there.
        let on_record = record.start.clone().expect("on record");
        assert_eq!(on_record.key, sent[0]);
        assert!(on_record.same_purchase(&wanted));
        // Run again: the same key, nothing new on record, and user-api
        // here answers with what it made.
        let answered = start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |key| {
            sent.push(key()?);
            Ok(json!({ "done": true, "httpStatus": 200, "userVpsId": 7 }))
        })
        .await
        .expect("answered");
        assert_eq!(made(answered), "7");
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0], sent[1]);
        assert_eq!(record.begun, 1);
        // The request is the caller's to take off with the VPS put on
        // record: until then it stays.
        assert_eq!(record.start, Some(on_record));
    }

    #[tokio::test]
    async fn an_answer_that_is_none_leaves_the_request_and_a_refusal_before_it_left_takes_it_off() {
        use super::{StartError, start_on_record};
        let wanted = vps("amsterdam");
        // user-api's own fault, or too many requests: as good as no answer.
        for status in [503, 429, 408] {
            let mut record = Kept::default();
            let open = start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |key| {
                key()?;
                Ok(json!({ "done": false, "httpStatus": status, "message": "try later" }))
            })
            .await
            .expect_err("no answer to go by");
            assert!(
                open.message.contains(&status.to_string()),
                "{}",
                open.message
            );
            assert!(open.hint.is_some());
            assert!(record.start.is_some(), "{status}");
        }
        // A refusal of a first request is certain: its key goes, and the
        // reply is returned for the caller to say.
        let mut record = Kept::default();
        let answered = start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |key| {
            key()?;
            Ok(json!({ "done": false, "httpStatus": 402 }))
        })
        .await
        .expect("answered");
        assert_eq!(refused(answered)["httpStatus"], json!(402));
        assert_eq!((record.begun, record.start), (1, None));
        // The session refused after the key went on record: nothing was
        // started under it, and it goes.
        let mut record = Kept::default();
        let refused = start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |key| {
            key()?;
            Err(StartError::NotStarted("the session was refused".to_owned()))
        })
        .await
        .expect_err("refused");
        assert_eq!(refused.message, "the session was refused");
        assert_eq!((record.begun, record.start.clone()), (1, None));
        // The person said no before a key was asked for: nothing was put
        // on record.
        let said_no = start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |_| {
            Err(StartError::NotStarted("the user said no".to_owned()))
        })
        .await;
        assert!(said_no.is_err());
        assert_eq!((record.begun, record.start.clone()), (1, None));
        // And a no to a start an earlier run left unanswered leaves it as
        // unanswered as it was.
        let earlier = Start {
            key: "c".repeat(32),
            ..wanted.clone()
        };
        let mut record = Kept {
            start: Some(earlier.clone()),
            ..Kept::default()
        };
        let said_no = start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |_| {
            Err(StartError::NotStarted("the user said no".to_owned()))
        })
        .await;
        assert!(said_no.is_err());
        assert_eq!(record.start, Some(earlier));
    }

    /// user-api's answer to a start, as `start_hourly_product` passes it
    /// on: the status, and the reply's `code` or `message`.
    fn answer(status: u16, code: Option<&str>, message: &str) -> serde_json::Value {
        let mut reply = json!({ "done": false, "httpStatus": status, "success": false });
        if let Some(code) = code {
            reply["code"] = json!(code);
        }
        if !message.is_empty() {
            reply["message"] = json!(message);
        }
        reply
    }

    /// The answer while the account's hourly lock is held, by the first
    /// request of the same key perhaps, or while its row is not linked.
    fn in_progress() -> serde_json::Value {
        answer(
            409,
            Some("PURCHASE_IN_PROGRESS"),
            "Another purchase is already in progress. Please retry shortly.",
        )
    }

    /// A start left on record by an earlier run that learnt no outcome.
    fn left_by_an_earlier_run(wanted: &Start) -> (Kept, Start) {
        let earlier = Start {
            key: "e".repeat(32),
            ..wanted.clone()
        };
        let record = Kept {
            start: Some(earlier.clone()),
            ..Kept::default()
        };
        (record, earlier)
    }

    /// The sequence that bought twice: a start times out while user-api is
    /// still making the purchase, the rerun is answered 409 in progress,
    /// and the run after that must still send the first key.
    #[tokio::test]
    async fn a_timeout_then_a_409_in_progress_then_a_rerun_send_one_key() {
        use super::{StartError, start_on_record};
        let mut record = Kept::default();
        let wanted = vps("amsterdam");
        let mut sent: Vec<String> = Vec::new();
        start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |key| {
            sent.push(key()?);
            Err(StartError::Unanswered("it timed out".to_owned()))
        })
        .await
        .expect_err("no answer");
        // The rerun: the first request still holds the account's lock.
        let waiting = start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |key| {
            sent.push(key()?);
            Ok(in_progress())
        })
        .await
        .expect_err("still being made is not an outcome");
        assert!(
            waiting.message.contains("still being made"),
            "{}",
            waiting.message
        );
        let hint = waiting.hint.expect("a hint");
        assert!(hint.contains("same command again"), "{hint}");
        // Neither a new request nor another region: either would buy a
        // second while the first completes.
        for wrong in ["new request", "new one", "region"] {
            assert!(!hint.contains(wrong), "{wrong}: {hint}");
        }
        let entry = record.start.clone().expect("the request stays on record");
        assert_eq!(entry.key, sent[0]);
        // The first purchase has completed meanwhile: the third run sends
        // the same key, and here user-api answers with what it made.
        let answered = start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |key| {
            sent.push(key()?);
            Ok(json!({ "done": true, "httpStatus": 200, "userVpsId": 8 }))
        })
        .await
        .expect("answered");
        assert_eq!(made(answered), "8");
        assert_eq!(sent, [entry.key.clone(), entry.key.clone(), entry.key]);
        assert_eq!(record.begun, 1, "one key was made in all");
    }

    #[tokio::test]
    async fn a_first_request_answered_409_in_progress_keeps_its_key() {
        use super::start_on_record;
        let mut record = Kept::default();
        let mut sent: Vec<String> = Vec::new();
        // Its row may have been made before the answer: the key is the
        // only thing that leads back to it.
        let waiting = start_on_record(
            &vps("amsterdam"),
            "userVpsId",
            &mut record,
            &QUIET,
            async |key| {
                sent.push(key()?);
                Ok(in_progress())
            },
        )
        .await
        .expect_err("still being made");
        assert!(
            !waiting.hint.unwrap_or_default().contains("region"),
            "another region would buy a second"
        );
        assert_eq!(record.start.expect("on record").key, sent[0]);
        // The gRPC, Shreds and Unlimited routes answer a duplicate insert
        // with the code as the whole message, and no `code`.
        let mut record = Kept::default();
        let bare = answer(409, None, "PURCHASE_IN_PROGRESS");
        start_on_record(
            &vps("amsterdam"),
            "userVpsId",
            &mut record,
            &QUIET,
            async |key| {
                key()?;
                Ok(bare)
            },
        )
        .await
        .expect_err("still being made");
        assert!(record.start.is_some());
    }

    #[tokio::test]
    async fn a_request_sent_again_and_refused_for_another_reason_stays_on_record() {
        use super::start_on_record;
        let wanted = vps("amsterdam");
        // None of these speaks for the key: an edge's 403, a bad request,
        // no credit, no stock say nothing of the first request, which may
        // have gone through or be in flight still.
        for refusal in [
            answer(403, None, "Forbidden"),
            answer(400, None, "Unknown hourly plan"),
            answer(402, None, "Insufficient credit"),
            answer(409, Some("OUT_OF_STOCK"), "out of stock"),
            answer(409, Some("REGION_DOWN"), "This region is down right now."),
            answer(404, None, ""),
        ] {
            let (mut record, earlier) = left_by_an_earlier_run(&wanted);
            let said = refusal.to_string();
            let refused = start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |key| {
                key()?;
                Ok(refusal)
            })
            .await
            .expect_err("a refusal of the resend is no outcome of the first");
            assert_eq!(record.start, Some(earlier), "{said}");
            assert!(
                refused
                    .message
                    .contains("says nothing about the earlier one"),
                "{said}: {}",
                refused.message
            );
            assert!(
                refused.hint.is_some_and(|hint| hint.contains("clear")),
                "{said}"
            );
        }
        // The same refusals of a first request are certain: nothing was
        // made under a key that had never been sent, and the request goes.
        for refusal in [
            answer(403, None, "Forbidden"),
            answer(402, None, "Insufficient credit"),
            answer(409, Some("OUT_OF_STOCK"), "out of stock"),
            answer(409, Some("REGION_DOWN"), "This region is down right now."),
        ] {
            let mut record = Kept::default();
            let said = refusal.to_string();
            let answered =
                start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |key| {
                    key()?;
                    Ok(refusal)
                })
                .await
                .expect("refused for certain");
            assert_eq!(refused(answered)["done"], json!(false));
            assert_eq!((record.begun, record.start), (1, None), "{said}");
        }
    }

    /// The answer that a request's key belongs to another purchase, as
    /// the VPS route gives it and as the line routes do (the code as the
    /// whole message).
    fn conflicts() -> [serde_json::Value; 2] {
        [
            answer(
                409,
                Some("IDEMPOTENCY_CONFLICT"),
                "This idempotency key belongs to a different VPS purchase. Start a new purchase with a new key.",
            ),
            answer(409, None, "IDEMPOTENCY_CONFLICT"),
        ]
    }

    #[tokio::test]
    async fn a_conflict_answered_to_a_request_sent_again_keeps_it_on_record() {
        use super::start_on_record;
        let wanted = vps("amsterdam");
        for conflict in conflicts() {
            let (mut record, earlier) = left_by_an_earlier_run(&wanted);
            let mut sends = 0;
            let unmatched =
                start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |key| {
                    key()?;
                    sends += 1;
                    Ok(conflict)
                })
                .await
                .expect_err("a purchase exists under the key");
            // The key was sent for this purchase only: what user-api has
            // under it may well be the earlier request's own. The request
            // stays, and nothing is started or sent again.
            assert_eq!(record.start, Some(earlier));
            assert_eq!((sends, record.begun), (1, 0));
            assert!(
                unmatched
                    .message
                    .contains("has a purchase under this request"),
                "{}",
                unmatched.message
            );
            // Neither the answer nor the way on speaks of a new request.
            let said = format!(
                "{} {}",
                unmatched.message,
                unmatched.hint.unwrap_or_default()
            );
            for wrong in ["new request", "makes a new", "new one", "new key"] {
                assert!(!said.contains(wrong), "{wrong}: {said}");
            }
            assert!(said.contains("take it up or end it"), "{said}");
        }
    }

    #[tokio::test]
    async fn a_conflict_answered_to_a_first_request_takes_it_off_the_record() {
        use super::start_on_record;
        // The key was made by this run and never sent before: the purchase
        // it belongs to is not an earlier request of erpc's.
        for conflict in conflicts() {
            let mut record = Kept::default();
            let mut sends = 0;
            let answered = start_on_record(
                &vps("amsterdam"),
                "userVpsId",
                &mut record,
                &QUIET,
                async |key| {
                    key()?;
                    sends += 1;
                    Ok(conflict)
                },
            )
            .await
            .expect("refused, and settled");
            let reply = refused(answered);
            assert_eq!((record.begun, record.start), (1, None));
            // Not sent again by itself.
            assert_eq!(sends, 1);
            let hint = super::refused_hint(&reply, None, None).expect("a hint");
            assert!(hint.contains("another purchase"), "{hint}");
        }
    }

    /// The sequence the gate probed: a start times out and the VPS is
    /// made; the rerun is answered that the key is another purchase's; the
    /// run after that must send the first key still, and nothing new.
    #[tokio::test]
    async fn a_timeout_then_a_conflict_then_a_rerun_send_one_key() {
        use super::{StartError, start_on_record};
        let mut record = Kept::default();
        let wanted = vps("amsterdam");
        let mut sent: Vec<String> = Vec::new();
        start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |key| {
            sent.push(key()?);
            Err(StartError::Unanswered("it timed out".to_owned()))
        })
        .await
        .expect_err("no answer");
        let [conflict, _] = conflicts();
        for run in [2, 3] {
            let conflict = conflict.clone();
            let unmatched =
                start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |key| {
                    sent.push(key()?);
                    Ok(conflict)
                })
                .await;
            assert!(
                unmatched.is_err(),
                "run {run}: a purchase exists under the key"
            );
            assert_eq!(
                record.start.as_ref().map(|start| start.key.clone()),
                Some(sent[0].clone()),
                "run {run}: the request stays on record"
            );
        }
        assert_eq!(sent, [sent[0].clone(), sent[0].clone(), sent[0].clone()]);
        assert_eq!(record.begun, 1, "one key was made in all");
    }

    #[tokio::test]
    async fn a_start_user_api_does_not_name_stays_with_the_way_out() {
        use super::start_on_record;
        // Started, by user-api's word, and no id to put on record.
        for again in [false, true] {
            let wanted = vps("amsterdam");
            let mut record = if again {
                left_by_an_earlier_run(&wanted).0
            } else {
                Kept::default()
            };
            let unnamed = start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |key| {
                key()?;
                Ok(json!({ "done": true, "httpStatus": 202, "success": true }))
            })
            .await
            .expect_err("nothing to put on record");
            assert!(record.start.is_some(), "resend {again}");
            assert!(
                unnamed.message.contains("did not say which"),
                "{}",
                unnamed.message
            );
            // Not "run it again", which would never settle: the way out.
            assert_eq!(
                unnamed.hint.as_deref(),
                Some("take it up or end it, then clear it by hand")
            );
        }
        // A line is named under its own field, by a number or a string.
        for id in [json!(100_002), json!("100002")] {
            let reply = json!({ "done": true, "httpStatus": 200, "userGrpcId": id });
            assert_eq!(
                super::named_id(&reply, "userGrpcId").as_deref(),
                Some("100002")
            );
            assert_eq!(super::named_id(&reply, "userVpsId"), None);
        }
    }

    /// What user-api answered is said without a word about a record: the
    /// record's own hint says what becomes of the request, and
    /// `erpc worker run` keeps none.
    #[tokio::test]
    async fn what_user_api_answered_is_said_without_a_word_about_a_record() {
        use super::{StartError, start_on_record};
        let wanted = vps("amsterdam");
        let replies = [
            in_progress(),
            answer(409, None, "Stored purchase identity is invalid."),
            answer(503, None, "try later"),
            json!({ "done": true, "httpStatus": 202, "success": true }),
            json!({ "done": false, "httpStatus": 200, "success": false }),
        ];
        let mut messages = Vec::new();
        for reply in replies {
            let mut record = Kept::default();
            let error = start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |key| {
                key()?;
                Ok(reply)
            })
            .await
            .expect_err("not settled");
            messages.push(error.message);
        }
        let mut record = Kept::default();
        let lost = start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |key| {
            key()?;
            Err(StartError::Unanswered("it timed out".to_owned()))
        })
        .await
        .expect_err("no answer");
        messages.push(lost.message);
        for message in messages {
            for wrong in ["record", "same command", "same request"] {
                assert!(!message.contains(wrong), "{wrong}: {message}");
            }
        }
    }

    #[tokio::test]
    async fn a_409_with_a_code_erpc_does_not_know_keeps_the_request() {
        use super::start_on_record;
        let wanted = vps("amsterdam");
        // A code of another route, a verdict in place of a code, a sentence
        // and nothing at all: never a reason to make a new key.
        for unknown in [
            answer(409, Some("SOMETHING_NEW"), "a code from a later user-api"),
            answer(
                409,
                None,
                "Stored placement differs from current placement; retry with the original route.",
            ),
            answer(409, None, ""),
            json!({ "done": false, "httpStatus": 409, "success": false, "verdict": "conflict" }),
        ] {
            for resend in [false, true] {
                let mut record = if resend {
                    left_by_an_earlier_run(&wanted).0
                } else {
                    Kept::default()
                };
                let said = unknown.to_string();
                let answer = unknown.clone();
                let not_known =
                    start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |key| {
                        key()?;
                        Ok(answer)
                    })
                    .await
                    .expect_err("not known");
                assert!(record.start.is_some(), "{said}, resend {resend}");
                let hint = not_known.hint.expect("a hint");
                assert!(
                    hint.contains("dashboard") && hint.contains("clear"),
                    "{said}: {hint}"
                );
            }
        }
    }

    #[tokio::test]
    async fn nothing_is_sent_for_another_purchase_or_without_a_record() {
        use super::start_on_record;
        // A request for Amsterdam got no answer; the command now asks for
        // Tokyo. Neither key is sent, and the record is left as it is.
        let earlier = Start {
            key: "d".repeat(32),
            ..vps("amsterdam")
        };
        let mut record = Kept {
            start: Some(earlier.clone()),
            ..Kept::default()
        };
        let refused = start_on_record(
            &vps("tokyo"),
            "userVpsId",
            &mut record,
            &QUIET,
            async |_| unreachable!("sent a start beside one that may have gone through"),
        )
        .await
        .expect_err("refused");
        assert!(
            refused.message.contains("vps prod_Vps1 (amsterdam)")
                && refused.message.contains("vps prod_Vps1 (tokyo)"),
            "{}",
            refused.message
        );
        assert_eq!(refused.hint.as_deref(), Some("clear it by hand"));
        assert_eq!(record.start, Some(earlier));
        // A record that cannot be written: the key is not handed out, so
        // the request does not leave.
        let mut record = Kept {
            read_only: true,
            ..Kept::default()
        };
        let mut left = false;
        let refused = start_on_record(
            &vps("tokyo"),
            "userVpsId",
            &mut record,
            &QUIET,
            async |key| {
                let key = key()?;
                left = true;
                Ok(json!({ "done": true, "httpStatus": 200, "key": key }))
            },
        )
        .await
        .expect_err("not on record");
        assert!(!left);
        assert!(
            refused.message.contains("the disk is full"),
            "{}",
            refused.message
        );
    }

    #[test]
    fn a_refusal_says_the_key_was_another_purchases_or_what_else_to_try() {
        let own = || Some("another region".to_owned());
        // The key is another purchase's: that, whatever else could be said.
        for conflict in [
            answer(409, Some("IDEMPOTENCY_CONFLICT"), "a different purchase"),
            answer(409, None, "IDEMPOTENCY_CONFLICT"),
        ] {
            let said = super::refused_hint(&conflict, None, own()).expect("a hint");
            assert!(said.contains("another purchase"), "{said}");
            // True of a deploy and of a run alike: no word of a record,
            // nor of what the next run does.
            for wrong in ["record", "new request", "again makes"] {
                assert!(!said.contains(wrong), "{wrong}: {said}");
            }
        }
        // Any other refusal keeps the caller's hint, or has none.
        let no_stock = answer(409, Some("OUT_OF_STOCK"), "out of stock");
        assert_eq!(super::refused_hint(&no_stock, None, own()), own());
        let no_credit = answer(402, None, "Insufficient credit");
        assert_eq!(super::refused_hint(&no_credit, None, None), None);
        // Another region is worth a try only where this one had no stock
        // or is down, never for want of credit.
        assert!(super::elsewhere_may_do(&no_stock));
        assert!(super::elsewhere_may_do(&answer(
            409,
            Some("REGION_DOWN"),
            ""
        )));
        assert!(!super::elsewhere_may_do(&no_credit));
        assert!(!super::elsewhere_may_do(&in_progress()));
    }

    #[test]
    fn what_yes_answered_is_still_said() {
        let said = super::accepted_text("Start VPS Plus hourly?\n  Price  €0.07 per hour");
        assert!(
            said.starts_with("Start VPS Plus hourly?\n  Price  €0.07 per hour\n"),
            "{said}"
        );
        assert!(said.contains("--yes"), "{said}");
    }

    /// The assistant stops an erpc deploy it runs after a limit of its
    /// own, which must outlast the longest wait a deploy has: the slowest
    /// line to be ready, with a build and a new server before it.
    #[test]
    fn the_assistants_limit_for_a_deploy_outlasts_the_slowest_line() {
        use core::time::Duration;
        let slowest = LineKind::ALL
            .map(|kind| super::line_product(kind).wait)
            .into_iter()
            .max()
            .expect("a line");
        assert!(
            erpc_ai::commands::DEPLOY_LIMIT >= slowest + Duration::from_mins(30),
            "a line can take {slowest:?}"
        );
    }

    fn catalog() -> Value {
        json!({ "families": [
            { "family": "vps", "plans": [{ "productId": "prod_vps", "hourlyCents": 3.0 }] },
            { "family": "udp-forwarding",
              "plans": [{ "productId": "prod_standard", "hourlyCents": 69.0 }] },
            { "family": "udp-forwarding-premium",
              "plans": [{ "productId": "prod_premium", "hourlyCents": 139.0 }] },
        ] })
    }

    #[test]
    fn a_udp_plan_is_the_cheapest_of_both_products_or_the_one_asked_for() {
        let offered = udp_plans(&catalog());
        assert_eq!(offered.len(), 2);
        let cheapest = choose_udp_plan(&offered, None).expect("offered");
        assert_eq!(cheapest.id, "prod_standard");
        assert_eq!(cheapest.family.family, "udp-forwarding");
        let asked = choose_udp_plan(&offered, Some("prod_premium")).expect("asked");
        assert_eq!(asked.family.name, "UDP Forwarding Premium");
        assert!((asked.cents - 139.0).abs() < f64::EPSILON);
        let unknown = choose_udp_plan(&offered, Some("prod_x")).expect_err("none");
        assert!(
            unknown
                .message
                .contains("udp-forwarding or udp-forwarding-premium"),
            "{}",
            unknown.message
        );
        // An account Premium is not on sale to sees Standard alone.
        let standard_only = udp_plans(&json!({ "families": [
            { "family": "udp-forwarding",
              "plans": [{ "productId": "prod_standard", "hourlyCents": 69.0 }] },
        ] }));
        assert_eq!(standard_only.len(), 1);
        assert!(choose_udp_plan(&standard_only, Some("prod_premium")).is_err());
        assert!(choose_udp_plan(&udp_plans(&json!({})), None).is_err());
    }

    #[test]
    fn a_udp_line_sends_from_a_region_its_product_serves() {
        let offered = udp_plans(&catalog());
        let standard = UdpPlan {
            family: &UDP_FAMILIES[0],
            id: "prod_standard".to_owned(),
            cents: 69.0,
        };
        assert!(udp_region_ok(&standard, "tokyo", &offered).is_ok());
        // Dublin is Premium's alone: the hint names its plan.
        let dublin = udp_region_ok(&standard, "dublin", &offered).expect_err("refused");
        assert!(
            dublin.message.contains("UDP Forwarding Standard") && dublin.message.contains("dublin"),
            "{}",
            dublin.message
        );
        assert!(
            dublin
                .hint
                .as_deref()
                .is_some_and(|h| h.contains("--udp-plan prod_premium")),
            "{:?}",
            dublin.hint
        );
        // Not when Premium is not on sale to the account.
        let standard_only: Vec<UdpPlan> = offered
            .into_iter()
            .filter(|p| p.family.family == "udp-forwarding")
            .collect();
        assert!(
            udp_region_ok(&standard, "dublin", &standard_only)
                .expect_err("refused")
                .hint
                .is_none()
        );
        // Sydney is nobody's.
        let premium = UdpPlan {
            family: &UDP_FAMILIES[1],
            id: "prod_premium".to_owned(),
            cents: 139.0,
        };
        assert!(udp_region_ok(&premium, "dublin", &[]).is_ok());
        assert!(udp_region_ok(&premium, "sydney", &[]).is_err());
    }

    #[test]
    fn a_udp_row_says_which_product_it_is_and_where_it_sends_from() {
        let standard =
            json!({ "id": 7, "productKey": "one_hop_direct", "sourceIp": "198.51.100.20" });
        assert_eq!(
            udp_family_of(&standard).map(|f| f.name),
            Some("UDP Forwarding Standard")
        );
        assert_eq!(
            udp_sources(&standard),
            Ok(vec![
                "198.51.100.20".parse::<std::net::Ipv4Addr>().expect("ip")
            ])
        );
        let premium = json!({
            "id": 8,
            "productKey": "udp_forwarding_premium",
            "sourceIps": ["198.51.100.21", "198.51.100.20", "198.51.100.21"],
        });
        assert_eq!(
            udp_family_of(&premium).map(|f| f.product_type),
            Some("udp_forwarding_premium")
        );
        // Sorted, each once.
        assert_eq!(
            udp_sources(&premium).map(|s| s.iter().map(ToString::to_string).collect::<Vec<_>>()),
            Ok(vec!["198.51.100.20".to_owned(), "198.51.100.21".to_owned()])
        );
        // Nothing until a node is allocated.
        assert_eq!(udp_sources(&json!({ "sourceIp": null })), Ok(Vec::new()));
        assert_eq!(udp_sources(&json!({ "sourceIp": "" })), Ok(Vec::new()));
        assert_eq!(udp_sources(&json!({})), Ok(Vec::new()));
        assert!(udp_family_of(&json!({ "productKey": "grpc" })).is_none());
    }

    #[test]
    fn a_source_that_is_not_an_ipv4_address_is_an_error_that_names_it() {
        // Dropped, it would leave a shorter list, or the empty one that
        // reads as "no address named".
        for (row, named) in [
            (json!({ "sourceIp": "not an address" }), "not an address"),
            (json!({ "sourceIp": "2001:db8::1" }), "2001:db8::1"),
            (json!({ "sourceIp": "198.51.100.0/24" }), "198.51.100.0/24"),
            (
                json!({ "sourceIps": ["198.51.100.20", "edge.example"] }),
                "edge.example",
            ),
            (json!({ "sourceIps": ["198.51.100.20", 7] }), "7"),
            // What is shown is one printable line.
            (json!({ "sourceIp": "a\u{1b}[2Jb\nc" }), "a[2Jbc"),
        ] {
            assert_eq!(udp_sources(&row), Err(named.to_owned()), "{row}");
        }
        let told =
            super::udp_sources_of("7", &json!({ "sourceIp": "2001:db8::1" })).expect_err("refused");
        assert!(
            told.message.contains("`2001:db8::1`") && told.message.contains("line 7"),
            "{}",
            told.message
        );
    }

    #[test]
    fn only_an_hourly_standard_line_pointed_nowhere_is_offered_in_place_of_a_new_one() {
        use super::unpointed_udp_line;
        let (standard, premium) = (&UDP_FAMILIES[0], &UDP_FAMILIES[1]);
        let row = |id: i64, status: &str, destination: Value| json!({ "id": id, "billingCycle": "hourly", "status": status, "destination": destination });
        let unpointed = row(42, "provisioning", Value::Null);
        assert_eq!(
            unpointed_udp_line(standard, std::slice::from_ref(&unpointed), None).as_deref(),
            Some("42")
        );
        // The first such line, past the ones that send somewhere or ended.
        let rows = [
            row(40, "active", json!("203.0.113.9:10001")),
            row(41, "cancelled", Value::Null),
            row(43, "suspended", Value::Null),
            row(44, "active", json!("")),
            unpointed.clone(),
        ];
        assert_eq!(
            unpointed_udp_line(standard, &rows, None).as_deref(),
            Some("44")
        );
        // Not the environment's own line on record: the deploy takes it up.
        assert_eq!(
            unpointed_udp_line(standard, &rows, Some("44")).as_deref(),
            Some("42")
        );
        // Not one billed otherwise, which erpc would then end by the hour.
        let monthly =
            json!({ "id": 45, "billingCycle": "monthly", "status": "active", "destination": null });
        assert_eq!(unpointed_udp_line(standard, &[monthly], None), None);
        // Not a Premium line: it is not charged until it is pointed.
        assert_eq!(unpointed_udp_line(premium, &[unpointed], None), None);
        assert_eq!(unpointed_udp_line(standard, &[], None), None);
    }

    #[test]
    fn a_udp_line_on_record_names_the_port_it_sends_to() {
        use erpc_worker::manifest::Line;
        let line = |endpoint: &str| Line {
            kind: LineKind::Udp,
            id: "7".to_owned(),
            endpoint: endpoint.to_owned(),
            hourly: true,
            sources: Vec::new(),
        };
        assert_eq!(udp_port(&line("0.0.0.0:10001")), Some(10001));
        assert_eq!(udp_port(&line("")), None);
        assert_eq!(udp_port(&line("https://edge.erpc.global")), None);
    }

    #[test]
    fn a_udp_line_needs_a_port_and_a_region_to_be_started_for() {
        let ip: std::net::Ipv4Addr = "203.0.113.10".parse().expect("ip");
        let target = LineTarget {
            ip,
            udp_port: Some(10001),
            region: Some("tokyo".to_owned()),
        };
        assert_eq!(udp_target(&target).expect("both"), (10001, "tokyo"));
        let no_region = LineTarget {
            ip,
            udp_port: Some(10001),
            region: None,
        };
        let e = udp_target(&no_region).expect_err("no region");
        assert!(
            e.hint
                .as_deref()
                .is_some_and(|h| h.contains("--udp-region")),
            "{:?}",
            e.hint
        );
        let no_port = LineTarget {
            ip,
            udp_port: None,
            region: Some("tokyo".to_owned()),
        };
        assert!(udp_target(&no_port).is_err());
    }

    #[test]
    fn a_refusal_to_point_a_udp_line_is_tried_again_only_while_user_api_applies() {
        use erpc_api::ApiError;
        let refused = |status, message: &str| ApiError::Refused {
            status,
            message: message.to_owned(),
        };
        assert!(super::point_again_later(&refused(
            409,
            "a change is being applied (UDP_FORWARDING_PREMIUM_APPLY_IN_PROGRESS)"
        )));
        assert!(super::point_again_later(&refused(
            429,
            "too soon (UDP_FORWARDING_PREMIUM_CHANGE_TOO_SOON)"
        )));
        assert!(!super::point_again_later(&refused(
            409,
            "the region is down (REGION_DOWN)"
        )));
        assert!(!super::point_again_later(&refused(
            422,
            "a public IPv4:port (INVALID_DESTINATION)"
        )));
        assert!(!super::point_again_later(&ApiError::Unauthorized));
    }

    #[test]
    fn a_line_endpoint_is_dialled_over_tls_but_unlimited() {
        // Built, not written out: the endpoint gate reads literals.
        let url = |scheme: &str, rest: &str| [scheme, rest].join("://");
        let host = "edge.erpc.global";
        for given in [url("http", host), url("https", &format!("{host}/"))] {
            assert_eq!(
                line_endpoint(LineKind::Grpc, &given),
                Some(url("https", host))
            );
        }
        assert_eq!(line_endpoint(LineKind::Grpc, host), None);
        assert_eq!(line_endpoint(LineKind::Grpc, "http://"), None);
        let unlimited = url("http", "203.0.113.5:8899");
        assert_eq!(
            line_endpoint(LineKind::Unlimited, &format!("{unlimited}/")),
            Some(unlimited)
        );
        assert_eq!(line_endpoint(LineKind::Unlimited, &url("http", host)), None);
    }

    #[test]
    fn a_line_is_charged_when_the_snapshot_lists_its_type_and_id() {
        use erpc_worker::manifest::Line;
        let line = |kind, id: &str| Line {
            kind,
            id: id.to_owned(),
            endpoint: String::new(),
            hourly: true,
            sources: Vec::new(),
        };
        let charged = vec![
            ("grpc".to_owned(), 100_002),
            ("unlimited".to_owned(), 100_003),
            ("one_hop_direct".to_owned(), 7),
            ("udp_forwarding_premium".to_owned(), 8),
        ];
        assert!(super::is_charged(&charged, &line(LineKind::Grpc, "100002")));
        assert!(super::is_charged(
            &charged,
            &line(LineKind::Unlimited, "100003")
        ));
        // The same id under another type is another product.
        assert!(!super::is_charged(
            &charged,
            &line(LineKind::Shreds, "100002")
        ));
        assert!(!super::is_charged(
            &charged,
            &line(LineKind::Grpc, "100009")
        ));
        // A UDP Forwarding line is charged as either of its products.
        assert!(super::is_charged(&charged, &line(LineKind::Udp, "7")));
        assert!(super::is_charged(&charged, &line(LineKind::Udp, "8")));
        assert!(!super::is_charged(&charged, &line(LineKind::Udp, "9")));
        assert!(!super::is_charged(&charged, &line(LineKind::Grpc, "7")));
    }

    #[test]
    fn letting_the_server_in_keeps_the_others() {
        let ip: std::net::Ipv4Addr = "203.0.113.10".parse().expect("ip");
        assert_eq!(super::whitelist(ip, &[]), [ip]);
        assert_eq!(
            super::whitelist(ip, &["198.51.100.7", "203.0.113.10"]),
            [
                "198.51.100.7".parse::<std::net::Ipv4Addr>().expect("ip"),
                ip
            ]
        );
        assert_eq!(super::whitelist(ip, &["not an address"]), [ip]);
    }

    #[test]
    fn a_line_lets_in_one_address_or_a_list() {
        assert_eq!(
            line_ips(&json!({ "whiteListIp": "203.0.113.5" })),
            ["203.0.113.5"]
        );
        assert_eq!(
            line_ips(&json!({ "whitelistIps": ["203.0.113.5", "203.0.113.6"] })),
            ["203.0.113.5", "203.0.113.6"]
        );
        assert!(line_ips(&json!({ "whitelistIps": null })).is_empty());
    }

    /// Every name an earlier review tried that is in the known form, with
    /// the spec it gives: the name's own words, never more.
    const REVIEWED_IN_FORM: [(&str, &str); 14] = [
        (
            "🛰\u{fe0f} SLV VPS - 1 vCPU AMD EPYC4G x 4 GB DDR5 - 10 GB SSD NVMe4",
            "ERPC Worker (1 vCPU, 4 GB memory, 10 GB NVMe)",
        ),
        (
            "SLV VPS - 1 vCPU - 999999999 GB NVMe",
            "ERPC Worker (1 vCPU, 999999999 GB NVMe)",
        ),
        (
            "SLV VPS - 100 GB NVMe + 100 GB NVMe + 100 GB NVMe - 4 vCPU",
            "ERPC Worker (4 vCPU)",
        ),
        (
            "SLV\tVPS\t-\t1\tvCPU\tx\t4\tGB\tDDR5",
            "ERPC Worker (1 vCPU, 4 GB memory)",
        ),
        ("SLV VPS - 4 GB ECC", "ERPC Worker (4 GB memory)"),
        (
            "SLV VPS - 8 vCPU AMD Ryzen x 32 GB DDR5",
            "ERPC Worker (8 vCPU, 32 GB memory)",
        ),
        (
            "SLV VPS - 1 VCPU X 4 GB DDR5",
            "ERPC Worker (1 vCPU, 4 GB memory)",
        ),
        (
            "SLV VPS - 1 vCPU x 4 GB DDR5 - 10 GB NVMe + 10 GB NVMe",
            "ERPC Worker (1 vCPU, 4 GB memory)",
        ),
        ("SLV VPS - 999 vCPU", "ERPC Worker (999 vCPU)"),
        (
            "SLV VPS - 1 vCPU AMD EPYC4G x 4 GB DDR5 - 10 GB SSD NVMe4",
            "ERPC Worker (1 vCPU, 4 GB memory, 10 GB NVMe)",
        ),
        (
            "SLV VPS - 4 vCPU x 4 GB DDR5 - 10 GB SSD NVMe4 + 100 GB HDD",
            "ERPC Worker (4 vCPU, 4 GB memory)",
        ),
        (
            "SLV VPS - 4 vCPU x 2 GB DDR5",
            "ERPC Worker (4 vCPU, 2 GB memory)",
        ),
        (
            "SLV VPS - 1 vCPU x 4 GB DDR5 - 10 GB SSD + 10 GB SSD",
            "ERPC Worker (1 vCPU, 4 GB memory)",
        ),
        (
            "SLV VPS Max - 16 vCPU x 64 GB RAM - 1 TB SSD",
            "ERPC Worker (16 vCPU, 64 GB memory, 1000 GB SSD)",
        ),
    ];

    /// Every name an earlier review tried that is not in the known form:
    /// none gives a spec.
    const REVIEWED_NOT_IN_FORM: [&str; 160] = [
        "Dual SLV VPS - 1 vCPU AMD EPYC4G x 4 GB DDR5 - 10 GB SSD NVMe4",
        "SLV VPS x2 - 1 vCPU AMD EPYC4G x 4 GB DDR5 - 10 GB SSD NVMe4",
        "2 x SLV VPS - 4 vCPU x 8 GB DDR5 - 100 GB NVMe",
        "SLV VPS (2 servers) - 4 vCPU x 8 GB DDR5",
        "SLV VPS per vCPU - 4 GB DDR5",
        "SLV VPS 2 vCPU 8 GB - 1 vCPU",
        "1 vCPU AMD EPYC4G x 4 GB DDR5 - 10 GB SSD NVMe4",
        "16 vCPU x 64 GB DDR5 - 2 vCPU",
        "SLV VPS - 1 vCPU x 1 TB RAM",
        "SLV VPS - 1 vCPU x 4 TB DDR5",
        "SLV VPS - 1 vCPU - 9999999 TB NVMe",
        "SLV VPS - 1 vCPU - 4294967296 GB NVMe",
        "SLV VPS - 1 vCPU + 4 GB DDR5",
        "SLV VPS - 1 vCPU + 4 GB DDR5 - 10 GB NVMe",
        "SLV VPS - 4 vCPU x 8 GB DDR5 + 100 GB NVMe",
        "SLV VPS - 100 GB NVMe + 8 GB DDR5",
        "SLV VPS - 4 vCPU + x 8 GB DDR5",
        "SLV VPS - 4 vCPU x 8 GB DDR5 + 8 GB DDR5",
        "SLV VPS - 4 GB DDR5 + 1 vCPU",
        "SLV VPS – 1 vCPU x 4 GB DDR5",
        "SLV VPS — 1 vCPU x 4 GB DDR5",
        "SLV VPS -- 1 vCPU x 4 GB DDR5",
        "SLV VPS - 1 vCPU AMD AMD AMD x 4 GB DDR5 DDR5",
        "SLV VPS - 1 vCPU Intel AMD x 4 GB RAM ECC",
        "SLV VPS - 10 GB HDD SSD",
        "SLV VPS - 10 GB NVMe HDD",
        "SLV VPS - 10 GB SSD HDD",
        "SLV VPS - 4 GB DDR5 SSD",
        "SLV VPS - 01 vCPU x 04 GB DDR5",
        "SLV VPS - 1 vCPU x 0 GB DDR5",
        "SLV VPS - 0 vCPU",
        "SLV VPS - 1 vCPU x 4 GB DDR5 -",
        "- 1 vCPU x 4 GB DDR5",
        "- - 1 vCPU",
        "SLV VPS - Tokyo - 1 vCPU",
        "SLV VPS - 1 vCPU x 4 GB DDR5 - 10 GB SSD NVMe4 - 1 vCPU",
        "SLV VPS - 1 vCPU x 4 GB DDR5 x 4 GB DDR5",
        "SLV VPS - 1 vCPU AMD x x 4 GB DDR5",
        "SLV VPS - 8 vCPU AMD Ryzen 9 7950X x 32 GB DDR5",
        "SLV VPS - 1 vcpu x 4 gb ddr5",
        "SLV VPS - 1 vCPU x 4 Gb DDR5",
        "SLV VPS - 1 vCPU x 4 GiB DDR5",
        "SLV VPS - 1 vCPU x 4096 MB DDR5",
        "SLV VPS - 1 vCPU x 4GB DDR5",
        "SLV VPS - 1 vCPU, x 4 GB DDR5",
        "SLV VPS - 1 vCPU x 4 GB DDR5 - 10 GB NVMe x",
        "SLV VPS - 1 vCPU x 4 GB DDR5 - x 10 GB NVMe",
        "SLV VPS - 1 vCPU x 4 GB DDR5 - 10 GB NVMe - 10 GB NVMe",
        "SLV VPS - 1 vCPU x 4 GB DDR5 - 10 GB NVMe ++ 10 GB NVMe",
        "SLV VPS - 1 vCPU x 4 GB DDR5 - 10 GB NVMe+10 GB NVMe",
        "SLV VPS - 1 vCPU x 4 GB DDR5 - 10 GB NVMe +10 GB NVMe",
        "SLV VPS - 1 vCPU x 4 GB DDR5 - 10 GB NVMe + ",
        "SLV VPS - 1 vCPU x 4 GB DDR5 - + 10 GB NVMe",
        "SLV VPS - 1 vCPU x 4 GB DDR5 + - 10 GB NVMe",
        "SLV VPS - 4 vCPU - 2 GB DDR5 - 2 GB DDR5",
        "SLV VPS - 4 vCPU x 2 GB DDR5 - 2 GB DDR5",
        "SLV VPS - 1 vCPU AMD EPYC4G x 4 GB DDR5 - 10 GB SSD NVMe4 2",
        "SLV VPS - 1 vCPU AMD EPYC4G 2 x 4 GB DDR5",
        "SLV VPS - 2 1 vCPU",
        "SLV VPS - 1 vCPU 2",
        "SLV VPS - 1 2 vCPU",
        "SLV VPS - 1 vCPU x 2 4 GB DDR5",
        "SLV VPS - 1 vCPU x 4 GB 2 DDR5",
        "SLV VPS - 1 vCPU x 4 GB DDR5 2",
        "SLV VPS - 10 GB 2 NVMe",
        "SLV VPS - 10 TB 2 NVMe",
        "SLV VPS - ２ vCPU",
        "SLV VPS - 1 vCPU x 4 ＧＢ DDR5",
        "SLV VPS - 1 vCPU x 4 GB DDR5 - 10 GB NVMe4 NVMe4",
        "SLV VPS - 1 vCPU x 4 GB DDR5 - 10 GB SSD SSD SSD",
        "SLV VPS - 1 vCPU x 4 GB DDR5 - 10 GB nvme3 hdd",
        "SLV VPS - 1 vCPU AMD EPYC4G x 4 GB DDR5 - 10 GB SSD NVMe4 x 2",
        "SLV VPS - 1 vCPU AMD EPYC4G x 4 GB DDR5 - 10 GB SSD NVMe4 x2",
        "SLV VPS - 4 vCPU x 4 GB DDR5 ECC x 2 - 50 GB NVMe",
        "SLV VPS - 4 vCPU x 8 GB DDR5 - 960 GB SSD NVMe4 (x2)",
        "SLV VPS - 4 vCPU x 8 GB DDR5 - 960 GB NVMe x 2",
        "SLV VPS - 2 vCPU x 2 - 8 GB DDR5",
        "SLV VPS - 4 vCPU x 16 GB DDR5 - 2 x 1 TB NVMe",
        "SLV VPS - 8 vCPU - 32 GB DDR5 RAM - 2 × 960 GB NVMe",
        "SLV VPS - 2vCPU x 4GB DDR5 - 40GB NVMe",
        "SLV VPS - 4 vCPU x 8 GB DDR5 - 960 GB NVMe×2",
        "SLV VPS - 4 vCPU x 8 GB DDR5 - 960 GB NVMex2",
        "SLV VPS - 4 vCPU x 8 GB DDR5 - 960 GB SSD NVMe4x2",
        "SLV VPS - 4 vCPU x 8 GB DDR5 - 960 GB NVMe *2",
        "SLV VPS - 4 vCPU x 8 GB DDR5 - 960 GB NVMe * 2",
        "SLV VPS - 4 vCPU x 8 GB DDR5 - 2 * 960 GB NVMe",
        "SLV VPS - 4 vCPU x 8 GB DDR5 - 960 GB NVMe 2 pcs",
        "SLV VPS - 4 vCPU x 8 GB DDR5 - Dual 960 GB NVMe",
        "SLV VPS - 4 vCPU x 8 GB DDR5 - 960 GB NVMe (2 disks)",
        "SLV VPS - 4 vCPU x 8 GB DDR5 - 960 GB NVMe RAID1 x 2",
        "SLV VPS - 4 vCPU x 8 GB DDR5 - 960 GB NVMe RAID 1",
        "SLV VPS - 4 vCPU x 8 GB DDR5 - 960 GB NVMe RAID 10",
        "SLV VPS - 4 vCPU x 8 GB DDR5 – 960 GB NVMe – x 2",
        "SLV VPS – 4 vCPU x 8 GB DDR5 – 960 GB NVMe x 2",
        "SLV VPS - 4 vCPU x 8 GB DDR5 / 960 GB NVMe x 2",
        "SLV VPS - 4 vCPU x 8 GB DDR5 | 2 x 480 GB SSD",
        "SLV VPS - 4 vCPU x 8 GB DDR5 - 960 GB NVMe (x 2)",
        "SLV VPS - 4 vCPU x 8 GB DDR5 - 960 GB NVMe ( x2 )",
        "SLV VPS - 4 vCPU x 8 GB DDR5 - 960 GB NVMe [2x]",
        "SLV VPS - 4 vCPU x 8 GB DDR5 - (2x) 960 GB NVMe",
        "SLV VPS - 4 vCPU x 8 GB DDR5 - 2x960 GB NVMe",
        "SLV VPS - 4 vCPU x 8 GB DDR5 - 960 GB x 2 NVMe",
        "SLV VPS - 4 vCPU x 8 GB DDR5 - 960 GB NVMe 2x",
        "SLV VPS - 4 vCPU x 8 GB DDR5 - 960 GB NVMe 2 x",
        "SLV VPS - 4 vCPU x 8 GB DDR5 - 960 GB NVMe, x 2",
        "SLV VPS - 4 vCPU x 8 GB DDR5 - 960 GB NVMe,x2",
        "SLV VPS - 4 vCPU x 8 GB DDR5 - 960 GB NVMe x 02",
        "SLV VPS - 4 vCPU x 8 GB DDR5 - 960 GB NVMe x 10",
        "SLV VPS - 4 vCPU x 8 GB DDR5 - 960 GB NVMe x 100",
        "SLV VPS - 2 x 4 vCPU - 16 GB DDR5",
        "SLV VPS - 4 vCPU x 2 - 16 GB DDR5",
        "SLV VPS - 4 vCPUs x 2 - 16 GB DDR5",
        "SLV VPS - 4 vCPU (x2) - 16 GB DDR5",
        "SLV VPS - 16 GB DDR5 x 2 - 100 GB NVMe",
        "SLV VPS - 16 GB DDR5 2x - 100 GB NVMe",
        "SLV VPS - 16 GB DDR5 (2x8 GB) - 100 GB NVMe",
        "SLV VPS - 16 GB DDR5 (2 x 8 GB) - 100 GB NVMe",
        "SLV VPS - 2 x 8 GB DDR5 - 100 GB NVMe",
        "SLV VPS - 4 vCPU x 8 GB DDR5 x2 - 100 GB NVMe",
        "SLV VPS - 4 vCPU x 8 GB DDR5 RAM x2 - 100 GB NVMe",
        "SLV VPS - 8 vCPU AMD Ryzen 9 7950X x 32 GB DDR5 - 100 GB NVMe",
        "SLV VPS - 8 vCPU AMD EPYC 9 x 32 GB DDR5 - 100 GB NVMe",
        "SLV VPS - 8 vCPU AMD EPYC 9 - 32 GB DDR5 - 100 GB NVMe",
        "SLV VPS - 8 vCPU Intel Xeon 2 x 32 GB DDR5",
        "SLV VPS - 8 vCPU Gen 4 x 32 GB DDR5",
        "SLV VPS - 4 vCPU x 8 GB DDR5 - 960 GB NVMe Gen4 x 4 lanes",
        "SLV VPS - 1 TB NVMe x 2",
        "SLV Super VPS - 16 vCPU x 64 GB DDR5 - 2 x 1.92 TB NVMe",
        "SLV Super VPS - 16 vCPU x 64 GB DDR5 - 1.92 TB NVMe x 2",
        "SLV Premium VPS - 32 vCPU x 128 GB DDR5 - 3.84 TB NVMe",
        "SLV VPS - 4 vCPU x 8 GB DDR5 - 960 GB SSD NVMe4 x 2 + 100 GB HDD",
        "SLV VPS - 4 vCPU x 8 GB - 960 GB NVMe",
        "🛰\u{fe0f} SLV VPS - 1 vCPU AMD EPYC4G x 4 GB DDR5 - 10 GB SSD NVMe4 ×2",
        "SLV VPS - 4 vCPU x 8 GB DDR5 - 2 x 960 GB NVMe",
        "SLV VPS - 4 vCPU x 4 GB DDR5 x 2 - 50 GB NVMe",
        "SLV VPS - 2 x 4 vCPU - 16 GB DDR5 - 2x 480 GB SSD",
        "SLV VPS - 8 GB RAM x2 - 100 GB SSD",
        "SLV VPS - 2 vCPU x 8 GB DDR5, 40 GB NVMe x 2",
        "SLV VPS - 4 GB DDR5 2 x - 40 GB NVMe",
        "SLV VPS - 4 GB DDR5 2x - 40 GB NVMe",
        "SLV VPS - 4 GB DDR5 2x 480 GB SSD",
        "SLV VPS - 4 vCPU, DDR5 x 2 - 50 GB NVMe",
        "SLV VPS - 4 vCPU 8 GB DDR5 x 2 - 50 GB NVMe",
        "SLV VPS - 8 GB DDR5 - 100 GB NVMe + backup x 2",
        "SLV VPS - 4 GB DDR5 2 x 480 GB SSD",
        "SLV VPS - 4 GB DDR5 - NVMe x 2",
        "SLV VPS - 4 GB DDR5 , NVMe x 2",
        "SLV VPS - 4 GB DDR5, NVMe x 2",
        "SLV VPS - 8 vCPU AMD Ryzen 9 7950X 32 GB DDR5",
        "SLV VPS - 2 vCPU × 8 GB DDR5 - 40 GB NVMe",
        "🛰\u{fe0f} SLV VPS - 1 vCPU AMD EPYC4G x 4 GB DDR5 - 10 GB SSD NVMe4x2",
        "🛰\u{fe0f} SLV VPS - 1 vCPU AMD EPYC4G x 4 GB DDR5 - 10 GB SSD NVMe4×2",
        "🛰\u{fe0f} SLV VPS - 1 vCPU AMD EPYC4G x 4 GB DDR5 - 10 GB SSD NVMe4 x 2",
        "🛰\u{fe0f} SLV VPS - 1 vCPU AMD EPYC4G x 4 GB DDR5 - 10 GB SSD NVMe4 * 2",
        "🛰\u{fe0f} SLV VPS - 1 vCPU AMD EPYC4G x 4 GB DDR5 - 2 * 10 GB SSD NVMe4",
        "🛰\u{fe0f} SLV VPS - 1 vCPU AMD EPYC4G x 4 GB DDR5 - 10 GB SSD NVMe4 2 pcs",
        "🛰\u{fe0f} SLV VPS - 1 vCPU AMD EPYC4G x 4 GB DDR5 - Dual 10 GB SSD NVMe4",
        "🛰\u{fe0f} SLV VPS - 1 vCPU AMD EPYC4G x 4 GB DDR5x2 - 10 GB SSD NVMe4",
        "🛰\u{fe0f} SLV VPS - 1 vCPU AMD EPYC4G x 4 GB DDR5 - 960 GB SSD NVMe4 x 2 + 100 GB HDD",
        "SLV VPS - 8 vCPU AMD EPYC 9654 x 32 GB DDR5 - 100 GB NVMe",
    ];

    #[test]
    fn every_name_the_reviews_tried_gives_only_what_it_says() {
        use super::{Spec, worker};
        // Every name the reviews tried.
        for (title, said) in REVIEWED_IN_FORM {
            assert_eq!(worker(&Spec::of_title(title)), said, "{title:?}");
        }
        for title in REVIEWED_NOT_IN_FORM {
            assert_eq!(Spec::of_title(title), Spec::default(), "{title:?}");
        }
        // The product's own name, word by word too.
        for title in [
            "Dual SLV VPS - 1 vCPU",
            "SLV VPS x2 - 1 vCPU",
            "2 x SLV VPS - 1 vCPU",
            "SLV VPS (2 servers) - 1 vCPU",
            "SLV VPS per vCPU - 4 GB DDR5",
            "- 1 vCPU",
        ] {
            assert_eq!(Spec::of_title(title), Spec::default(), "{title:?}");
        }
        for name in [
            "🛰️ SLV VPS",
            "🛰 SLV VPS",
            "SLV VPS Max",
            "SLV Super VPS",
            "Premium VPS",
            "VPS Plus",
        ] {
            assert_eq!(
                worker(&Spec::of_title(&format!("{name} - 2 vCPU"))),
                "ERPC Worker (2 vCPU)",
                "{name}"
            );
        }
        // `+` joins disks only; units are GB and TB as written; a size
        // too large to count, a nought first, a word twice, a disk of two
        // kinds and a CPU of two makers give none.
        for title in [
            "SLV VPS - 1 vCPU + 4 GB DDR5",
            "SLV VPS - 4 GB DDR5 + 1 vCPU",
            "SLV VPS - 4 vCPU x 8 GB DDR5 + 100 GB NVMe",
            "SLV VPS - 1 vCPU + 4 GB DDR5 - 10 GB NVMe",
            "SLV VPS - 10 GB NVMe - 10 GB NVMe + 10 GB NVMe",
            "SLV VPS - 10 GB NVMe + 10 GB NVMe - 10 GB NVMe",
            "SLV VPS - 1 vCPU - 10 GB NVMe - 10 GB NVMe + 10 GB NVMe",
            "SLV VPS - 2 vCPU - 4 GB DDR5 + 8 GB DDR5",
            "SLV VPS - 1 vCPU x 4 gb DDR5",
            "SLV VPS - 1 vCPU x 4 Gb DDR5",
            "SLV VPS - 1 vCPU x 1 TB RAM",
            "SLV VPS - 1 vCPU - 9999999 TB NVMe",
            "SLV VPS - 01 vCPU",
            "SLV VPS - 1 vCPU x 04 GB DDR5",
            "SLV VPS - 1 vCPU AMD AMD",
            "SLV VPS - 4 GB DDR5 DDR5",
            "SLV VPS - 10 GB SSD HDD",
            "SLV VPS - 10 GB NVMe HDD",
            "SLV VPS - 1 vCPU Intel AMD",
            "SLV VPS - 1 vCPU Xeon AMD",
            "SLV VPS - 1 vCPU EPYC AMD",
        ] {
            assert_eq!(Spec::of_title(title), Spec::default(), "{title:?}");
        }
        assert_eq!(
            worker(&Spec::of_title("SLV VPS - 1 vCPU - 4294967 TB NVMe")),
            "ERPC Worker (1 vCPU, 4294967000 GB NVMe)"
        );
    }

    #[test]
    fn a_spec_is_read_from_a_name_only_in_the_known_form() {
        use super::{Spec, worker};
        // In the known form, part by part.
        for (title, said) in [
            (
                "🛰️ SLV VPS - 1 vCPU AMD EPYC4G x 4 GB DDR5 - 10 GB SSD NVMe4",
                "ERPC Worker (1 vCPU, 4 GB memory, 10 GB NVMe)",
            ),
            (
                "SLV VPS Max - 16 vCPU x 64 GB RAM - 1 TB SSD",
                "ERPC Worker (16 vCPU, 64 GB memory, 1000 GB SSD)",
            ),
            (
                "SLV VPS - 4 vCPU Intel Xeon - 16 GB DDR4 ECC - 480 GB HDD",
                "ERPC Worker (4 vCPU, 16 GB memory, 480 GB disk)",
            ),
            (
                "SLV VPS - 8 vCPU AMD Ryzen x 32 GB DDR5 - 100 GB NVMe3",
                "ERPC Worker (8 vCPU, 32 GB memory, 100 GB NVMe)",
            ),
            ("SLV VPS - 2 vCPU", "ERPC Worker (2 vCPU)"),
            // Words are read whatever their case.
            (
                "slv vps - 1 VCPU amd epyc4g X 4 GB ddr5",
                "ERPC Worker (1 vCPU, 4 GB memory)",
            ),
            // Disks joined by `+`: no disk said.
            (
                "SLV VPS - 4 vCPU x 8 GB DDR5 - 100 GB NVMe + 100 GB HDD",
                "ERPC Worker (4 vCPU, 8 GB memory)",
            ),
        ] {
            assert_eq!(worker(&Spec::of_title(title)), said, "{title}");
        }
        // Anything else gives none at all: a count, however written, a word
        // not in the form, a second disk or memory, another part.
        for title in [
            // Counts.
            "SLV VPS - 1 vCPU AMD EPYC4G x 4 GB DDR5 - 10 GB SSD NVMe4 x 2",
            "SLV VPS - 1 vCPU AMD EPYC4G x 4 GB DDR5 - 10 GB SSD NVMe4 x2",
            "SLV VPS - 4 vCPU x 4 GB DDR5 ECC x 2 - 50 GB NVMe",
            "SLV VPS - 4 vCPU x 8 GB DDR5 - 960 GB SSD NVMe4 (x2)",
            "🛰️ SLV VPS - 1 vCPU AMD EPYC4G x 4 GB DDR5 - 10 GB SSD NVMe4x2",
            "🛰️ SLV VPS - 1 vCPU AMD EPYC4G x 4 GB DDR5 - 10 GB SSD NVMe4×2",
            "🛰️ SLV VPS - 1 vCPU AMD EPYC4G x 4 GB DDR5x2 - 10 GB SSD NVMe4",
            "🛰️ SLV VPS - 1 vCPU AMD EPYC4G x 4 GB DDR5 - 10 GB SSD NVMe4 * 2",
            "🛰️ SLV VPS - 1 vCPU AMD EPYC4G x 4 GB DDR5 - 2 * 10 GB SSD NVMe4",
            "🛰️ SLV VPS - 1 vCPU AMD EPYC4G x 4 GB DDR5 - 10 GB SSD NVMe4 2 pcs",
            "🛰️ SLV VPS - 1 vCPU AMD EPYC4G x 4 GB DDR5 - Dual 10 GB SSD NVMe4",
            "SLV VPS - 4 vCPU x 8 GB DDR5 - 2 x 960 GB NVMe",
            "SLV VPS - 2 x 4 vCPU - 16 GB DDR5 - 2x 480 GB SSD",
            "SLV VPS - 8 GB RAM x2 - 100 GB SSD",
            // A word, a sign or a number not in the form.
            "SLV VPS - 2 vCPU × 8 GB DDR5 - 40 GB NVMe",
            "SLV VPS - 8 vCPU AMD Ryzen 9 7950X x 32 GB DDR5",
            "SLV VPS - 1 vCPU AMD EPYC4G x 4 GB DDR5 - 10 GB SSD NVMe4 Promo",
            "SLV VPS - 1 vCPU Turbo x 4 GB DDR5",
            "SLV VPS - 4 GB GDDR6",
            "SLV VPS - 4 vCPUs - 8 GB DDR5",
            "SLV VPS - 1000 vCPU",
            "SLV VPS - 0 vCPU - 8 GB DDR5",
            "SLV VPS - 1 vCPU x 4 GB",
            "SLV VPS - 4 vCPU, 8 GB DDR5",
            "SLV VPS - Promo - 1 vCPU",
            "SLV VPS - 1 vCPU - - 4 GB DDR5",
            "SLV VPS - 100 GB NVMe +",
            "SLV VPS - 100 GB NVMe + backup",
            // A second of a kind.
            "SLV VPS - 1 vCPU - 2 vCPU",
            "SLV VPS - 8 GB DDR5 - 1 vCPU x 4 GB DDR5",
            "SLV VPS - 1 vCPU AMD x",
            "SLV VPS - 1 vCPU x 4 GB DDR5 - 8 GB DDR5",
            "SLV VPS - 10 GB NVMe - 20 GB HDD",
            // No parts.
            "1 vCPU AMD EPYC4G x 4 GB DDR5",
            "SLV VPS",
            "",
        ] {
            assert_eq!(Spec::of_title(title), Spec::default(), "{title}");
            assert_eq!(worker(&Spec::of_title(title)), "ERPC Worker", "{title}");
        }
    }

    #[test]
    fn a_server_is_an_erpc_worker_with_its_spec_never_its_products_name() {
        use super::{Disk, Spec, family_said, running_spec, worker, worker_id};
        let title = "🛰️ SLV VPS - 1 vCPU AMD EPYC4G x 4 GB DDR5 - 10 GB SSD NVMe4";
        let spec = Spec::of_title(title);
        assert_eq!(
            spec,
            Spec {
                cores: Some(1),
                memory_gb: Some(4),
                disk_gb: Some(10),
                disk: Disk::Nvme,
            }
        );
        assert_eq!(
            worker(&spec),
            "ERPC Worker (1 vCPU, 4 GB memory, 10 GB NVMe)"
        );
        assert_eq!(
            worker_id(100_001, &spec),
            "ERPC Worker 100001 (1 vCPU, 4 GB memory, 10 GB NVMe)"
        );
        // Another product's words: an SSD, a size in TB, "RAM".
        assert_eq!(
            worker(&Spec::of_title(
                "SLV VPS Max - 16 vCPU x 64 GB RAM - 1 TB SSD"
            )),
            "ERPC Worker (16 vCPU, 64 GB memory, 1000 GB SSD)"
        );
        // A name that says nothing of it: the id, never the name.
        for odd in ["Mystery plan", "", "SLV VPS"] {
            let spec = Spec::of_title(odd);
            assert_eq!(spec, Spec::default(), "{odd}");
            assert_eq!(worker(&spec), "ERPC Worker");
            assert_eq!(worker_id(7, &spec), "ERPC Worker 7");
        }
        // What the account gives: cores and memory, or cores alone.
        assert_eq!(
            worker(&Spec::sized(Some(2), Some(8))),
            "ERPC Worker (2 vCPU, 8 GB memory)"
        );
        assert_eq!(worker(&Spec::sized(Some(2), None)), "ERPC Worker (2 vCPU)");
        // A row of the account's running servers: its product's name read
        // for the spec, else its version's; never shown as it is.
        // A row in the shape the account's VPS status rows have: its
        // product's name read for the spec, in the known form or not at all.
        let row = |product: &str| {
            json!({ "userVpsId": 100_001, "subscriptionItemId": "si_1", "priceId": "price_1",
                "product": product, "price": 78, "status": "on", "region": "tokyo",
                "ip": "203.0.113.9", "username": "solv" })
        };
        assert_eq!(running_spec(&row(title)), spec);
        assert_eq!(
            worker_id(100_001, &running_spec(&row("SLV VPS - 1 vCPU x 4 GB DDR5"))),
            "ERPC Worker 100001 (1 vCPU, 4 GB memory)"
        );
        assert_eq!(running_spec(&row("EPYC VPS+")), Spec::default());
        assert_eq!(
            worker_id(100_001, &running_spec(&row("EPYC VPS+"))),
            "ERPC Worker 100001"
        );
        assert_eq!(running_spec(&json!({})), Spec::default());
        // A name under another field is not the row's product.
        assert_eq!(
            running_spec(&json!({ "productName": title, "vpsVersion": "2 vCPU x 8 GB DDR5" })),
            Spec::default()
        );
        // The family a plan is refused for.
        assert_eq!(family_said("vps"), "ERPC Worker");
        assert_eq!(family_said("grpc"), "grpc");
    }

    #[tokio::test]
    async fn the_start_and_end_questions_say_the_product_as_the_erpc_worker_it_is() {
        use std::cell::RefCell;

        use erpc_ai::confirm::{Confirm, Confirmation};

        use super::{AsWorker, Named, Spec, end_answerer, worker};

        /// Says yes, and keeps what it was asked.
        #[derive(Default)]
        struct Asked(RefCell<Vec<Confirmation>>);
        impl Confirm for Asked {
            fn confirm<'a>(
                &'a self,
                ask: &'a Confirmation,
            ) -> core::pin::Pin<Box<dyn Future<Output = bool> + 'a>> {
                self.0.borrow_mut().push(ask.clone());
                Box::pin(async { true })
            }
        }
        let title = "🛰️ SLV VPS - 1 vCPU AMD EPYC4G x 4 GB DDR5 - 10 GB SSD NVMe4";
        let asked = Asked::default();
        let named = AsWorker {
            inner: &asked,
            named: Named::Start {
                product: title,
                worker: worker(&Spec::of_title(title)),
            },
        };
        let ask = Confirmation {
            title: format!("Start {title} hourly? It is charged until it is ended."),
            lines: vec![
                ("Product".to_owned(), title.to_owned()),
                ("Price".to_owned(), "€0.0123 per hour".to_owned()),
            ],
        };
        assert!(named.confirm(&ask).await, "the answer is the person's");
        let shown = asked.0.borrow()[0].text();
        assert!(
            shown.starts_with(
                "Start ERPC Worker (1 vCPU, 4 GB memory, 10 GB NVMe) hourly? It is charged"
            ),
            "{shown}"
        );
        assert!(!shown.contains("VPS") && !shown.contains("SLV"), "{shown}");
        assert!(shown.contains("€0.0123 per hour"), "{shown}");
        // The end of ERPC Worker 100001: its product's name, and the
        // `(vps 100001)` erpc ai puts after it, said as the ERPC Worker.
        let ending = end_answerer(Some(&asked), "vps", 100_001).expect("someone to ask");
        let ask = Confirmation {
            title: format!(
                "End {title}? It stops, and stops being charged; this cannot be undone."
            ),
            lines: vec![
                ("Product".to_owned(), format!("{title} (vps 100001)")),
                ("Price now".to_owned(), "€0.0123 per hour".to_owned()),
            ],
        };
        assert!(ending.confirm(&ask).await, "the answer is the person's");
        let shown = asked.0.borrow()[1].text();
        assert!(
            shown.starts_with("End ERPC Worker 100001 (1 vCPU, 4 GB memory, 10 GB NVMe)? It stops"),
            "{shown}"
        );
        assert!(
            shown.contains("Product    ERPC Worker 100001 (1 vCPU, 4 GB memory, 10 GB NVMe)\n"),
            "{shown}"
        );
        assert!(
            !shown.to_lowercase().contains("vps") && !shown.contains("SLV"),
            "{shown}"
        );
        // With no product's name, erpc ai says the type: still the ERPC Worker.
        let ask = Confirmation {
            title: "End vps? It stops, and stops being charged; this cannot be undone.".to_owned(),
            lines: vec![("Product".to_owned(), "vps (vps 100001)".to_owned())],
        };
        assert!(ending.confirm(&ask).await);
        let shown = asked.0.borrow()[2].text();
        assert!(
            shown.starts_with("End ERPC Worker 100001? It stops"),
            "{shown}"
        );
        assert!(!shown.to_lowercase().contains("vps"), "{shown}");
        // A bare-metal server's end is said as erpc ai says it; nobody to
        // ask is nobody.
        let bare = end_answerer(Some(&asked), "bare_metal", 7).expect("someone to ask");
        let ask = Confirmation {
            title: "End Bare Metal X? It stops.".to_owned(),
            lines: vec![(
                "Product".to_owned(),
                "Bare Metal X (bare_metal 7)".to_owned(),
            )],
        };
        assert!(bare.confirm(&ask).await);
        assert_eq!(asked.0.borrow()[3], ask);
        assert!(end_answerer(None, "vps", 100_001).is_none());
    }

    #[test]
    fn an_erpc_worker_is_named_so_in_every_language_with_its_spec_translated() {
        use super::{Spec, worker_id};
        let spec = Spec::of_title("SLV VPS - 1 vCPU AMD EPYC4G x 4 GB DDR5 - 10 GB SSD NVMe4");
        for (lang, said) in [
            (
                erpc_core::i18n::Lang::Ja,
                "ERPC Worker 100001（1 vCPU、メモリ 4 GB、NVMe 10 GB）",
            ),
            (
                erpc_core::i18n::Lang::Zh,
                "ERPC Worker 100001（1 vCPU，内存 4 GB，NVMe 10 GB）",
            ),
            (
                erpc_core::i18n::Lang::Ru,
                "ERPC Worker 100001 (1 vCPU, 4 ГБ памяти, 10 ГБ NVMe)",
            ),
        ] {
            let named = crate::cli::i18n::speaking(lang, || worker_id(100_001, &spec));
            assert_eq!(named, said);
            assert!(!named.contains("VPS"), "{named}");
        }
    }

    #[test]
    fn the_monitoring_vps_is_not_a_server_to_run_an_app_on() {
        assert!(is_add_on("📊 SLV VPS for Advanced Monitoring"));
        assert!(!is_add_on(
            "🛰️ SLV VPS - 1 vCPU AMD EPYC4G x 4 GB DDR5 - 10 GB SSD NVMe4"
        ));
    }

    #[test]
    fn a_time_zone_picks_the_nearest_region() {
        for (zone, region) in [
            ("Asia/Tokyo", "tokyo"),
            ("Asia/Hong_Kong", "singapore"),
            ("Europe/Amsterdam", "amsterdam"),
            ("Europe/Berlin", "frankfurt"),
            ("Europe/London", "london"),
            ("America/Los_Angeles", "ny"),
            ("Australia/Sydney", "sydney"),
            ("", "frankfurt"),
            ("UTC", "frankfurt"),
        ] {
            assert_eq!(region_for_zone(zone), region, "{zone}");
        }
    }

    #[test]
    fn a_line_that_never_became_active_is_said_in_the_chosen_language() {
        use erpc_core::i18n::Lang;
        let say = || {
            tn!(
                "worker_vps.line.not_active",
                3,
                kind = "gRPC",
                id = "100002",
                last = "pending"
            )
        };
        let english = say();
        assert_eq!(
            english,
            "gRPC line 100002 did not become active in 3 minutes (it is pending)"
        );
        for lang in [Lang::Ja, Lang::Ru] {
            let said = crate::cli::i18n::speaking(lang, say);
            assert_ne!(said, english);
            assert!(!said.contains('{'), "{said}");
            assert!(
                said.contains("100002") && said.contains("pending"),
                "{said}"
            );
        }
        // Russian says three minutes as a few.
        assert!(crate::cli::i18n::speaking(Lang::Ru, say).contains("3 минуты"));
    }

    /// One look finds a VPS on record there when the account lists it, at
    /// any status (a pending one included), or charges for it by the hour,
    /// by an id written as a number or a string; missing when neither; and
    /// says nothing when the reply has no list or a row has no id.
    #[test]
    fn a_vps_is_there_when_listed_or_charged_and_missing_only_when_neither() {
        use super::{Seen, seen, vps_charged_in};
        let listed = json!({ "data": [
            { "userVpsId": 100_001, "status": "pending" },
            { "userVpsId": "200002", "status": "on", "ip": "203.0.113.10" },
        ] });
        let empty = json!({ "data": [] });
        assert_eq!(seen(&listed, &[], 100_001), Some(Seen::There));
        assert_eq!(seen(&listed, &[], 200_002), Some(Seen::There));
        assert_eq!(seen(&empty, &[100_001], 100_001), Some(Seen::There));
        assert_eq!(seen(&empty, &[], 100_001), Some(Seen::Missing));
        assert_eq!(seen(&listed, &[], 300_003), Some(Seen::Missing));
        assert_eq!(seen(&empty, &[200_002], 100_001), Some(Seen::Missing));
        // No list, or a row that could be this VPS, is no answer.
        assert_eq!(seen(&json!({}), &[], 100_001), None);
        assert_eq!(seen(&json!({ "data": null }), &[], 100_001), None);
        assert_eq!(seen(&json!({ "message": [] }), &[], 100_001), None);
        let unreadable = json!({ "data": [{ "status": "on" }] });
        assert_eq!(seen(&unreadable, &[], 100_001), None);
        let not_a_number = json!({ "data": [{ "userVpsId": "a1" }] });
        assert_eq!(seen(&not_a_number, &[], 100_001), None);

        // The snapshot's VPSs: other products with the same number are not
        // one; a VPS row without a readable id, or no list, says nothing.
        let snapshot = |rows: serde_json::Value| json!({ "message": { "hourlyResources": rows } });
        assert_eq!(
            vps_charged_in(&snapshot(json!([
                { "productType": "vps", "userProductId": 100_001 },
                { "productType": "vps", "userProductId": "200002" },
                { "productType": "bare_metal", "userProductId": 300_003 },
                { "productType": "erpc_plan", "userProductId": "x" },
            ]))),
            Some(vec![100_001, 200_002])
        );
        assert_eq!(
            vps_charged_in(&snapshot(
                json!([{ "productType": "vps", "userProductId": "x" }])
            )),
            None
        );
        assert_eq!(
            vps_charged_in(&snapshot(json!([{ "productType": "vps" }]))),
            None
        );
        assert_eq!(vps_charged_in(&json!({ "message": {} })), None);
    }

    /// The looks and the account's name come to "missing" only with both:
    /// a look that could not be read, or a name that could not, is not
    /// known, which keeps the record.
    #[test]
    fn missing_needs_every_look_and_the_accounts_name() {
        use super::{OnAccount, Seen, judged};
        let name = || Some("Example Account".to_owned());
        assert_eq!(
            judged(Some(Seen::Missing), name()),
            OnAccount::Missing {
                account: "Example Account".to_owned()
            }
        );
        assert_eq!(judged(Some(Seen::Missing), None), OnAccount::Unknown);
        assert_eq!(judged(None, name()), OnAccount::Unknown);
        assert_eq!(judged(None, None), OnAccount::Unknown);
        assert_eq!(judged(Some(Seen::There), name()), OnAccount::There);
        assert_eq!(judged(Some(Seen::There), None), OnAccount::There);
    }

    /// A VPS is missing only when every look finds it so: one look that
    /// finds it there, the last one included, says it is there, and one
    /// that cannot be read says nothing is known, after which nothing more
    /// is looked at. The person is told once, before the first wait, and not
    /// when the first look settles it.
    #[tokio::test]
    async fn a_vps_is_missing_only_when_every_look_finds_it_missing() {
        use super::{Seen, failed, missing_throughout};
        use core::time::Duration;
        use std::cell::Cell;

        async fn run(answers: &[Result<Seen, &str>]) -> (Option<Seen>, usize, usize) {
            let (looks, told) = (Cell::new(0_usize), Cell::new(0_usize));
            let looks_allowed = u32::try_from(answers.len()).expect("few");
            let seen = missing_throughout(
                looks_allowed,
                Duration::ZERO,
                || {
                    let n = looks.get();
                    looks.set(n + 1);
                    let answer = answers[n].map_err(failed);
                    async move { answer }
                },
                || told.set(told.get() + 1),
            )
            .await;
            (seen, looks.get(), told.get())
        }

        let missing = [Ok(Seen::Missing); 6];
        assert_eq!(run(&missing).await, (Some(Seen::Missing), 6, 1));

        let mut there_last = missing;
        there_last[5] = Ok(Seen::There);
        assert_eq!(run(&there_last).await, (Some(Seen::There), 6, 1));

        let first = [Ok(Seen::There), Ok(Seen::Missing)];
        assert_eq!(run(&first).await, (Some(Seen::There), 1, 0));

        let unreadable = [Ok(Seen::Missing), Err("no answer"), Ok(Seen::Missing)];
        assert_eq!(run(&unreadable).await, (None, 2, 1));
        let unreadable_last = [Ok(Seen::Missing), Ok(Seen::Missing), Err("no answer")];
        assert_eq!(run(&unreadable_last).await.0, None);
    }

    /// Only an hourly VPS can be missing: of a bare-metal server, a VPS not
    /// billed by the hour or one without a number nothing is known, and
    /// the account is not asked.
    #[tokio::test]
    async fn only_an_hourly_vps_can_be_missing() {
        use erpc_worker::manifest::{Resource, ResourceKind};

        type Replies =
            core::future::Ready<Result<(serde_json::Value, serde_json::Value), super::CliError>>;

        use super::{OnAccount, on_account_by};
        let say = Say { quiet: true };
        let resource = |kind, id: &str, hourly| Resource {
            kind,
            id: id.to_owned(),
            region: None,
            hourly,
        };
        let unasked = || -> Replies { panic!("the account is not to be asked") };
        let unnamed =
            || -> core::future::Ready<Option<String>> { panic!("no name is to be asked") };
        for r in [
            resource(ResourceKind::BareMetal, "100001", true),
            resource(ResourceKind::Vps, "100001", false),
            resource(ResourceKind::Vps, "", true),
            resource(ResourceKind::Vps, "not-a-number", true),
        ] {
            assert_eq!(
                on_account_by(&r, unasked, unnamed, &say).await,
                OnAccount::Unknown,
                "{r:?}"
            );
        }
        let missing = OnAccount::Missing {
            account: "Example Account".to_owned(),
        };
        assert_eq!(missing.missing_from(), Some("Example Account"));
        assert_eq!(OnAccount::There.missing_from(), None);
        assert_eq!(OnAccount::Unknown.missing_from(), None);
    }

    /// An id is read as user-api writes it, a number or a string of one.
    #[test]
    fn an_id_is_a_number_or_a_string_of_one() {
        use super::id_in;
        assert_eq!(id_in(&json!(100_001)), Some(100_001));
        assert_eq!(id_in(&json!("100001")), Some(100_001));
        assert_eq!(id_in(&json!("vps-1")), None);
        assert_eq!(id_in(&json!(null)), None);
    }

    /// The charges are read with ids as numbers or strings; no list is no
    /// answer.
    #[test]
    fn the_charges_are_read_with_ids_as_numbers_or_strings() {
        use super::charged_in;
        let snapshot = json!({ "message": { "hourlyResources": [
            { "productType": "grpc", "userProductId": 200_002 },
            { "productType": "shreds", "userProductId": "300003" },
            { "productType": "vps" },
        ] } });
        assert_eq!(
            charged_in(&snapshot),
            Some(vec![
                ("grpc".to_owned(), 200_002),
                ("shreds".to_owned(), 300_003)
            ])
        );
        assert_eq!(charged_in(&json!({ "message": {} })), None);
    }

    /// The whole reading of the account, with its replies given: a reply
    /// with no list, or one that fails, is not known; a VPS charged but not
    /// listed is there; missing at every look and with the account's name
    /// read is missing, and only then is the name asked for; a name that
    /// cannot be read, or is empty, leaves it not known.
    #[tokio::test(start_paused = true)]
    async fn the_account_is_read_through_every_look_and_its_name() {
        use super::{OnAccount, account_name, look_at, on_account_by};
        use core::time::Duration;
        use erpc_worker::manifest::{Resource, ResourceKind};
        use std::cell::Cell;

        let vps = Resource {
            kind: ResourceKind::Vps,
            id: "100001".to_owned(),
            region: None,
            hourly: true,
        };
        let say = Say { quiet: true };
        let snapshot = |rows: serde_json::Value| json!({ "message": { "hourlyResources": rows } });
        let empty = || (json!({ "data": [] }), snapshot(json!([])));
        let named = || async { Some("Example Account".to_owned()) };
        let unnamed = || async { None };

        // Every look of the window is made, and the waits between them are
        // taken in full: more than a VPS just bought can take to be listed
        // and than the snapshot is cached.
        let looks = Cell::new(0);
        let replies = || {
            looks.set(looks.get() + 1);
            async { Ok(empty()) }
        };
        let started = tokio::time::Instant::now();
        assert_eq!(
            on_account_by(&vps, replies, named, &say).await,
            OnAccount::Missing {
                account: "Example Account".to_owned()
            }
        );
        assert_eq!(looks.get(), 6, "every look is made");
        let waited = started.elapsed();
        assert!(waited >= Duration::from_secs(75), "{waited:?}");
        assert!(waited > erpc_ai::ready::UNLISTED, "{waited:?}");
        assert!(
            waited > erpc_api::account::CREDIT_SNAPSHOT_CACHE,
            "{waited:?}"
        );
        assert_eq!(
            on_account_by(&vps, || async { Ok(empty()) }, unnamed, &say).await,
            OnAccount::Unknown
        );
        let charged = || async {
            Ok((
                json!({ "data": [] }),
                snapshot(json!([{ "productType": "vps", "userProductId": "100001" }])),
            ))
        };
        let never = || async { panic!("the name is asked only of a missing VPS") };
        assert_eq!(
            on_account_by(&vps, charged, never, &say).await,
            OnAccount::There
        );
        let no_list = || async { Ok((json!({}), snapshot(json!([])))) };
        assert_eq!(
            on_account_by(&vps, no_list, never, &say).await,
            OnAccount::Unknown
        );
        let no_snapshot = || async { Ok((json!({ "data": [] }), json!({ "message": {} }))) };
        assert_eq!(
            on_account_by(&vps, no_snapshot, never, &say).await,
            OnAccount::Unknown
        );
        let failing = || async { Err(super::failed("no answer")) };
        assert_eq!(
            on_account_by(&vps, failing, never, &say).await,
            OnAccount::Unknown
        );

        // One look, from its two replies.
        let listed = json!({ "data": [{ "userVpsId": "100001", "status": "pending" }] });
        assert_eq!(
            look_at(&listed, &snapshot(json!([])), 100_001),
            Some(super::Seen::There)
        );
        assert_eq!(look_at(&listed, &json!({}), 100_001), None);

        // The name shown, or none.
        let user = |name: Option<&str>| -> erpc_api::User {
            serde_json::from_value(json!({ "uid": "", "username": name })).expect("a user")
        };
        assert_eq!(
            account_name(Some(&user(Some("Example Account")))),
            Some("Example Account".to_owned())
        );
        assert_eq!(account_name(Some(&user(None))), None, "nothing to show");
        assert_eq!(account_name(Some(&user(Some("  ")))), None);
        assert_eq!(account_name(None), None);
    }

    #[test]
    fn a_udp_row_tells_its_trouble_whatever_its_status() {
        // A Standard line with no free node in its region: still
        // `provisioning`, the reason in `lastError`.
        let waiting = json!({
            "status": "provisioning",
            "region": "tokyo",
            "destination": "203.0.113.7:10001",
            "lastAllocationOutcome": "region_unavailable",
            "lastError": "no eligible node with a free slot in the selected region",
        });
        assert_eq!(
            udp_trouble(&waiting),
            Some(UdpTrouble::Capacity(
                "no eligible node with a free slot in the selected region".to_owned()
            ))
        );
        let moving =
            json!({ "status": "provisioning", "lastError": " node left service; reassigning " });
        assert_eq!(
            udp_trouble(&moving),
            Some(UdpTrouble::Error(
                "node left service; reassigning".to_owned()
            ))
        );
        let silent = json!({ "status": "error", "lastError": null });
        assert_eq!(
            udp_trouble(&silent),
            Some(UdpTrouble::Error("no reason given".to_owned()))
        );
        let blank = json!({ "status": "error", "lastError": "  " });
        assert_eq!(
            udp_trouble(&blank),
            Some(UdpTrouble::Error("no reason given".to_owned()))
        );
        for status in ["provisioning", "applying", "active"] {
            let fine = json!({ "status": status, "lastError": null });
            assert_eq!(udp_trouble(&fine), None, "{status}");
        }
        // user-api's text reaches the terminal as one line with nothing it
        // acts on, and cut to a line's length.
        let hostile = json!({
            "status": "error",
            "lastError": format!("bad\u{1b}[2J\r\nfake\u{9b}\u{202e}{}", "x".repeat(500)),
        });
        let Some(UdpTrouble::Error(said)) = udp_trouble(&hostile) else {
            panic!("an error");
        };
        assert!(
            !said.contains(['\u{1b}', '\r', '\n', '\u{9b}', '\u{202e}']),
            "{said:?}"
        );
        assert_eq!(said.chars().count(), 300);
    }

    #[tokio::test]
    async fn a_start_ended_while_it_was_starting_leaves_the_record_and_its_key_is_not_sent_again() {
        use super::start_on_record;
        let ended = || {
            answer(
                409,
                None,
                "This purchase was ended while it was starting. Nothing more was granted.",
            )
        };
        let wanted = vps("amsterdam");
        // Sent again by this run, the key an earlier run left: it leaves
        // the record, refused, with the hint that says so.
        let (mut record, _) = left_by_an_earlier_run(&wanted);
        let sent = start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |key| {
            key()?;
            Ok(ended())
        })
        .await
        .expect("refused, off the record");
        assert_eq!(record.start, None);
        let reply = refused(sent);
        let hint = super::refused_hint(&reply, None, Some("elsewhere".to_owned())).expect("a hint");
        assert!(hint.contains("has been ended"), "{hint}");
        assert!(hint.contains("new key"), "{hint}");
        assert!(hint.contains("one hour at the least"), "{hint}");
        assert!(hint.contains("dashboard"), "{hint}");
        // A first request answered so: the same.
        let mut record = Kept::default();
        let sent = start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |key| {
            key()?;
            Ok(ended())
        })
        .await
        .expect("refused, off the record");
        assert_eq!(record.start, None);
        assert_eq!(record.begun, 1);
        refused(sent);
        // The next run starts it afresh: a new key, never the ended one.
        let (mut record, earlier) = left_by_an_earlier_run(&wanted);
        start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |key| {
            key()?;
            Ok(ended())
        })
        .await
        .expect("refused");
        let mut sent_with = String::new();
        let _ = start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |key| {
            sent_with = key()?;
            Ok(ended())
        })
        .await;
        assert_ne!(sent_with, earlier.key);
        assert!(!sent_with.is_empty());
    }

    #[test]
    fn an_ended_start_is_said_in_every_language() {
        use erpc_core::i18n::Lang;
        let reply = answer(
            409,
            None,
            "This purchase was ended while it was starting. Nothing more was granted.",
        );
        // Words that would tell the person to end, stop or cancel
        // something: in English as whole words, elsewhere as phrases.
        let english_end = ["end", "cancel", "stop", "terminate", "delete", "release"];
        let other_end = [
            "終了してください",
            "終了できます",
            "終了すると",
            "解約",
            "停止してください",
            "请终止",
            "可以终止",
            "终止它",
            "取消",
            "завершите",
            "завершить",
            "отмените",
            "остановите",
        ];
        for (lang, needles) in [
            (
                Lang::En,
                [
                    "new key",
                    "charged by the hour from its start until it was ended, one hour at the least",
                    "dashboard",
                ],
            ),
            (
                Lang::Ja,
                [
                    "新しいキー",
                    "開始から終了までの分が時間単位で、少なくとも 1 時間分",
                    "ダッシュボード",
                ],
            ),
            (
                Lang::Zh,
                [
                    "新密钥",
                    "从开通到终止期间可能已按小时计费，至少一个小时",
                    "控制面板",
                ],
            ),
            (
                Lang::Ru,
                [
                    "новым ключом",
                    "с запуска до завершения могли списывать оплату почасово, не меньше чем за один час",
                    "панели управления",
                ],
            ),
        ] {
            let hint = crate::cli::i18n::speaking(lang, || super::refused_hint(&reply, None, None))
                .expect("a hint");
            for needle in needles {
                assert!(hint.contains(needle), "{lang:?}: {hint}");
            }
            let words: Vec<String> = hint
                .split(|c: char| !c.is_alphanumeric())
                .map(str::to_lowercase)
                .collect();
            for end in english_end {
                assert!(!words.iter().any(|w| w == end), "{lang:?}: {hint}");
            }
            for end in other_end {
                assert!(!hint.contains(end), "{lang:?}: {hint}");
            }
            // Not the first hour alone: a request sent again may meet a line
            // that ran for hours before it was ended.
            for first_hour in ["first hour", "最初の 1 時間", "第一个小时", "первый час"]
            {
                assert!(!hint.contains(first_hour), "{lang:?}: {hint}");
            }
            // The words of the [start] section: キー, 密钥, not the Latin
            // "key".
            if lang != Lang::En {
                assert!(!hint.contains("key"), "{lang:?}: {hint}");
            }
        }
        // Each language's hint is the text reviewed for it, whole: no list
        // of words to avoid is complete.
        for (lang, reviewed) in [
            (Lang::En, ENDED_EN),
            (Lang::Ja, ENDED_JA),
            (Lang::Zh, ENDED_ZH),
            (Lang::Ru, ENDED_RU),
        ] {
            let hint = crate::cli::i18n::speaking(lang, || super::refused_hint(&reply, None, None));
            assert_eq!(hint.as_deref(), Some(reviewed), "{lang:?}");
        }
    }

    /// The ended start's hint, as reviewed, in each language.
    const ENDED_EN: &str = "user-api says what was bought under this start's key has been ended, and refuses the key from now on: it may have been charged by the hour from its start until it was ended, one hour at the least, which the dashboard shows. erpc takes the request off its record and does not send its key again; starting it again is a new purchase, with a new key, and its price is said again";
    const ENDED_JA: &str = "user-api によると、この開始のキーで買ったものは既に終了しており、このキーは今後受け付けられません。開始から終了までの分が時間単位で、少なくとも 1 時間分、課金された可能性があり、ダッシュボードで確認できます。erpc はこのリクエストを記録から外し、そのキーは二度と送信しません。もう一度開始すると、新しいキーでの新しい購入になり、価格もあらためて示します";
    const ENDED_ZH: &str = "user-api 表示，以此次开通的密钥购买的内容已被终止，今后不再接受该密钥：从开通到终止期间可能已按小时计费，至少一个小时，可在控制面板中查看。erpc 会将此请求从记录中移除，不再发送其密钥；再次开通即为使用新密钥的新购买，价格会再次显示";
    const ENDED_RU: &str = "user-api сообщает, что купленное по ключу этого запуска уже завершено, и больше этот ключ не принимает: с запуска до завершения могли списывать оплату почасово, не меньше чем за один час, это видно в панели управления. erpc убирает запрос из записей и больше не отправляет его ключ; новый запуск — это новая покупка с новым ключом, и цена будет названа снова";

    /// What [`super::start_on_record`] came back with, refused: the reply,
    /// and why its request is still on record, if it should not be.
    fn refused_and_why(sent: super::Sent) -> (serde_json::Value, Option<String>) {
        match sent {
            super::Sent::Refused { started, stays } => (started, stays),
            super::Sent::Made { id, .. } => panic!("made {id}"),
        }
    }

    #[tokio::test]
    async fn an_ended_start_that_cannot_leave_the_record_says_so_in_its_error() {
        use super::start_on_record;
        let ended = || {
            answer(
                409,
                None,
                "This purchase was ended while it was starting. Nothing more was granted.",
            )
        };
        let wanted = vps("amsterdam");
        // Sent again, and a first request: the error says the request is
        // still on record, and that the next run sends its key once more.
        let (mut sent_again, earlier) = left_by_an_earlier_run(&wanted);
        sent_again.stuck = true;
        let mut first = Kept {
            stuck: true,
            ..Kept::default()
        };
        for record in [&mut sent_again, &mut first] {
            let sent = start_on_record(&wanted, "userVpsId", record, &QUIET, async |key| {
                key()?;
                Ok(ended())
            })
            .await
            .expect("refused");
            let (reply, stays) = refused_and_why(sent);
            assert_eq!(stays.as_deref(), Some("the disk is full"));
            assert!(record.start.is_some());
            let hint = super::refused_hint(&reply, stays.as_deref(), None).expect("a hint");
            assert!(
                hint.contains("could not take the request off its record (the disk is full)"),
                "{hint}"
            );
            assert!(hint.contains("sends its key once more"), "{hint}");
            assert!(!hint.contains("does not send its key again"), "{hint}");
        }
        assert_eq!(sent_again.start, Some(earlier));
        // Other refusals that take a first request off the record say
        // nothing of it, as before, even when the record cannot be written.
        for refusal in [
            answer(402, None, "Insufficient credit"),
            answer(409, Some("IDEMPOTENCY_CONFLICT"), ""),
            answer(409, Some("OUT_OF_STOCK"), "out of stock"),
        ] {
            let mut record = Kept {
                stuck: true,
                ..Kept::default()
            };
            let said = refusal.to_string();
            let sent = start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |key| {
                key()?;
                Ok(refusal)
            })
            .await
            .expect("refused");
            assert_eq!(refused_and_why(sent).1, None, "{said}");
        }
    }

    #[test]
    fn an_ended_start_still_on_record_is_said_in_every_language_as_reviewed() {
        use erpc_core::i18n::Lang;
        let reply = answer(
            409,
            None,
            "This purchase was ended while it was starting. Nothing more was granted.",
        );
        for (lang, reviewed) in [
            (Lang::En, STAYS_EN),
            (Lang::Ja, STAYS_JA),
            (Lang::Zh, STAYS_ZH),
            (Lang::Ru, STAYS_RU),
        ] {
            let hint = crate::cli::i18n::speaking(lang, || {
                super::refused_hint(&reply, Some("the disk is full"), None)
            });
            assert_eq!(
                hint.as_deref(),
                Some(reviewed.replace("{error}", "the disk is full").as_str()),
                "{lang:?}"
            );
        }
    }

    /// The hint for an ended start still on record, as reviewed, in each
    /// language.
    const STAYS_EN: &str = "user-api says what was bought under this start's key has been ended, and refuses the key from now on: it may have been charged by the hour from its start until it was ended, one hour at the least, which the dashboard shows. erpc could not take the request off its record ({error}): the next run of the same command sends its key once more";
    const STAYS_JA: &str = "user-api によると、この開始のキーで買ったものは既に終了しており、このキーは今後受け付けられません。開始から終了までの分が時間単位で、少なくとも 1 時間分、課金された可能性があり、ダッシュボードで確認できます。erpc はこのリクエストを記録から外せませんでした（{error}）。同じコマンドを次に実行すると、そのキーをもう一度送信します";
    const STAYS_ZH: &str = "user-api 表示，以此次开通的密钥购买的内容已被终止，今后不再接受该密钥：从开通到终止期间可能已按小时计费，至少一个小时，可在控制面板中查看。erpc 无法将此请求从记录中移除（{error}）：下次运行同一命令时会再发送一次其密钥";
    const STAYS_RU: &str = "user-api сообщает, что купленное по ключу этого запуска уже завершено, и больше этот ключ не принимает: с запуска до завершения могли списывать оплату почасово, не меньше чем за один час, это видно в панели управления. erpc не удалось убрать запрос из записей ({error}): при следующем запуске той же команды его ключ будет отправлен ещё раз";
}
