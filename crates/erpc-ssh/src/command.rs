// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! What erpc may run on a node: a fixed set of commands.
//!
//! The remote side of `ssh` hands its command to a shell, so a command built
//! by joining strings is one quoting mistake from running something else.
//! Each command here is a fixed shell line with typed arguments, and every
//! argument is checked to be one that needs no quoting at all before it is
//! put inside single quotes. Secrets never appear on the line: they go in on
//! standard input.

/// A path on the node that erpc may write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemotePath(String);

/// The directories erpc writes under on a node.
pub const WRITABLE_ROOTS: [&str; 1] = ["/opt/erpc/"];

/// Why a value cannot go on a remote command line.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CommandError {
    /// The path is not an absolute path of plain names under a writable root.
    #[error("{0:?} is not a path erpc writes on a node")]
    Path(String),
    /// A run id, digest or play is not of its form.
    #[error("{0:?} is not a run erpc can start")]
    Run(String),
}

impl RemotePath {
    /// A path of plain names (letters, digits, `.`, `_`, `-`) under one of the
    /// [`WRITABLE_ROOTS`], with no `.` or `..` component.
    ///
    /// # Errors
    ///
    /// Returns [`CommandError::Path`] for anything else.
    pub fn new(path: &str) -> Result<Self, CommandError> {
        let refuse = || CommandError::Path(path.to_owned());
        let rest = WRITABLE_ROOTS
            .iter()
            .find_map(|root| path.strip_prefix(root))
            .ok_or_else(refuse)?;
        let plain = |part: &str| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        };
        if !rest.split('/').all(plain) {
            return Err(refuse());
        }
        Ok(Self(path.to_owned()))
    }

    /// The path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn parent(&self) -> &str {
        self.0.rsplit_once('/').map_or("/", |(dir, _)| dir)
    }
}

/// A run's id: `r-`, then 8 to 40 lowercase letters, digits and `-`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunId(String);

impl RunId {
    /// Checks the form.
    ///
    /// # Errors
    ///
    /// Returns [`CommandError::Run`] for anything else.
    pub fn new(id: &str) -> Result<Self, CommandError> {
        let ok = id.strip_prefix("r-").is_some_and(|rest| {
            (8..=40).contains(&rest.len())
                && rest
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        });
        if ok {
            Ok(Self(id.to_owned()))
        } else {
            Err(CommandError::Run(id.to_owned()))
        }
    }

    /// The id.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The run's directory on the node.
    #[must_use]
    pub fn dir(&self) -> String {
        format!("/opt/erpc/runs/{}", self.0)
    }
}

/// What a run starts: the bundle's digest and the play to run in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunStart {
    /// The run.
    pub run: RunId,
    /// The SHA-256 of `bundle.tar.gz`, 64 lowercase hex digits.
    pub sha256: String,
    /// The entry play, a path inside the bundle.
    pub play: String,
}

impl RunStart {
    /// Checks the digest and the play path.
    ///
    /// # Errors
    ///
    /// Returns [`CommandError::Run`] when either is not of its form.
    pub fn new(run: RunId, sha256: &str, play: &str) -> Result<Self, CommandError> {
        let digest_ok = sha256.len() == 64
            && sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        let play_ok = !play.is_empty()
            && play.split('/').all(|part| {
                !part.is_empty()
                    && part != "."
                    && part != ".."
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            });
        if !digest_ok || !play_ok {
            return Err(CommandError::Run(format!("{sha256} {play}")));
        }
        Ok(Self {
            run,
            sha256: sha256.to_owned(),
            play: play.to_owned(),
        })
    }
}

/// Immutable hashes for all executable input uploaded for a new run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunPrepare {
    start: RunStart,
    runner: String,
    helper: String,
}

impl RunPrepare {
    /// Validate the script digests before constructing a shell command.
    ///
    /// # Errors
    /// Returns [`CommandError::Run`] for an invalid digest.
    pub fn new(start: &RunStart, runner: &str, helper: &str) -> Result<Self, CommandError> {
        let start = RunStart::new(start.run.clone(), &start.sha256, &start.play)?;
        RunStart::new(start.run.clone(), runner, &start.play)?;
        RunStart::new(start.run.clone(), helper, &start.play)?;
        Ok(Self {
            start,
            runner: runner.to_owned(),
            helper: helper.to_owned(),
        })
    }
}

/// Hosts to ping from a node, each checked like a connection target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PingTargets(Vec<String>);

impl PingTargets {
    /// Up to 32 host names or addresses.
    ///
    /// # Errors
    ///
    /// Returns [`CommandError::Run`] for an empty or too long list, or a host
    /// that could be read as an option or as more than one word.
    pub fn new(hosts: &[&str]) -> Result<Self, CommandError> {
        if hosts.is_empty() || hosts.len() > 32 {
            return Err(CommandError::Run(format!("{} hosts to ping", hosts.len())));
        }
        for host in hosts {
            crate::config::check_host(host).map_err(|e| CommandError::Run(e.to_string()))?;
        }
        Ok(Self(hosts.iter().map(|h| (*h).to_owned()).collect()))
    }
}

/// Lists the `NVMe` disks of 800 GB or more that hold nothing, one line each:
/// `free <disk> <bytes> clean` for a disk with no partition table,
/// `free <disk> <bytes> empty-partitions <p1,p2>` for one whose partitions
/// are all empty, and `skip <disk> <why>` for every other disk. A partition
/// is empty when it has no filesystem, RAID or LVM signature, nothing holds
/// it, it is not mounted, `/etc/fstab` does not name it, and no UEFI boot
/// entry points at it. The node runs this before a deploy, and the deploy
/// play runs it again before it wipes anything, so both read the same rule.
pub const FREE_DISKS_SCRIPT: &str = r#"export LC_ALL=C
for d in /sys/block/nvme*n*; do
  [ -e "$d" ] || continue
  n=${d##*/}
  case "$n" in *p[0-9]*) continue;; esac
  bytes=$(( $(cat "$d/size") * 512 ))
  if [ "$bytes" -lt 800000000000 ]; then echo "skip $n smaller than 800 GB"; continue; fi
  if [ -n "$(lsblk -nro MOUNTPOINTS "/dev/$n" | tr -d ' \n')" ]; then echo "skip $n mounted"; continue; fi
  if [ -n "$(ls -A "$d/holders" 2>/dev/null)" ]; then echo "skip $n held by $(ls "$d/holders" | tr '\n' ' ')"; continue; fi
  parts=$(lsblk -nro NAME,TYPE "/dev/$n" | awk '$2 == "part" { print $1 }')
  if [ -z "$parts" ]; then
    sig=$(sudo -n blkid -p -o value -s TYPE "/dev/$n" 2>/dev/null)
    if [ -n "$sig" ]; then echo "skip $n holds $sig"; else echo "free $n $bytes clean"; fi
    continue
  fi
  why=""
  boot=$(sudo -n efibootmgr -v 2>/dev/null | tr 'A-Z' 'a-z')
  for p in $parts; do
    sig=$(sudo -n blkid -p -o value -s TYPE "/dev/$p" 2>/dev/null)
    pu=$(lsblk -nro PARTUUID "/dev/$p" | tr 'A-Z' 'a-z')
    if [ -n "$sig" ]; then why="$p holds $sig"
    elif [ -n "$(ls -A "/sys/class/block/$p/holders" 2>/dev/null)" ]; then why="$p is held"
    elif grep -v '^[[:space:]]*#' /etc/fstab | grep -qw -- "/dev/$p"; then why="$p is in /etc/fstab"
    elif [ -n "$pu" ] && grep -v '^[[:space:]]*#' /etc/fstab | tr 'A-Z' 'a-z' | grep -q -- "$pu"; then why="$p is in /etc/fstab"
    elif [ -n "$pu" ] && printf '%s' "$boot" | grep -q -- "$pu"; then why="$p is a boot entry"
    fi
    [ -n "$why" ] && break
  done
  if [ -n "$why" ]; then echo "skip $n $why"; else echo "free $n $bytes empty-partitions $(echo $parts | tr ' ' ',')"; fi
done
true
"#;

/// A keypair file on a node or another machine, to read once into
/// 1Password: an absolute path of plain characters ending in `.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyFilePath(String);

impl KeyFilePath {
    /// Checks `path`.
    ///
    /// # Errors
    ///
    /// Returns [`CommandError::Path`] for a relative path, `..`, empty or `.`
    /// parts, characters that would need quoting, or another extension.
    pub fn new(path: &str) -> Result<Self, CommandError> {
        let plain = path.len() <= 255
            && path.starts_with('/')
            && std::path::Path::new(path)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("json"))
            && path
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-'))
            && path[1..]
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != "..");
        if plain {
            Ok(Self(path.to_owned()))
        } else {
            Err(CommandError::Path(path.to_owned()))
        }
    }

    /// The path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The prefix of each line `Ping` prints: the host, then `ping`'s summary.
pub const PING_PREFIX: &str = "erpc-ping";

/// The line `FollowRun` prints between the run's log and its result.
pub const RESULT_MARKER: &str = "@@erpc-result@@";

/// A command erpc runs on a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteCommand {
    /// Hash-bound isolated Kaia endpoint-node controller.
    KaiaControl(crate::kaia::Control),
    /// Fixed Kaia journal selection.
    KaiaLogs {
        /// Maximum requested journal lines.
        lines: u32,
        /// Whether to continue streaming new records.
        follow: bool,
    },
    /// Confirm the owned Kaia firewall run and exact bundle.
    KaiaFirewallConfirm {
        /// Isolated owner-qualified entrypoint.
        control: crate::kaia::Control,
        /// Exact immutable firewall run and bundle receipt.
        token: crate::firewall::FirewallToken,
    },
    /// The kernel and machine: `uname -srm`.
    Uname,
    /// Owned Polygon native lifecycle or read-only journal operation.
    Polygon(crate::polygon::Command),
    /// The distribution: `/etc/os-release`.
    OsRelease,
    /// Writes standard input to a login-private regular file. An isolated root
    /// initializer creates traversable, root-owned namespace ancestors and a
    /// private login-owned leaf without adopting unsafe existing paths. Under
    /// `/opt/erpc/uploads` it takes two shapes only, streamed without a bound:
    /// the agent or restic as one file in `agent/` or `restic/`, and a
    /// worker's release in `<worker>/<release>/…`, nested as shipped, with
    /// every directory from the release down the login's; any other shape
    /// there is refused before anything is read or created. A path outside
    /// `/opt/erpc/uploads` takes a run's rules (`/opt/erpc/runs/<run>/<file>`):
    /// a bounded file in its one directory.
    WriteFile(RemotePath),
    /// The SHA-256 of a file, to check what was written arrived whole.
    Sha256(RemotePath),
    /// Removes one file erpc wrote.
    Remove(RemotePath),
    /// Starts a run's `node-run.sh` as a transient systemd unit, as the login
    /// user, so it carries on if the connection drops.
    StartRun(RunStart),
    /// Seals the SHA-bound upload before systemd opens its log. The isolated
    /// preparation program is supplied on standard input.
    PrepareRun(RunPrepare),
    /// Prints a run's log as it grows until the run ends, then
    /// [`RESULT_MARKER`] and its `result.json`. Attaches to a run that is
    /// already going, or reprints one that ended.
    FollowRun(RunId),
    /// Pings each host three times from the node and prints, for each, a
    /// line of [`PING_PREFIX`], the host and `ping`'s last summary line.
    Ping(PingTargets),
    /// The validator's state, as `key=value` lines: `service` (its unit's
    /// systemd state), `identity_link` (where `identity.json` leads),
    /// `identity` (its public key), and `health` and `slot` from the local
    /// RPC port. Run as `solv`.
    ValidatorStatus {
        /// The validator's RPC port, bound to 127.0.0.1.
        rpc_port: u16,
        /// The full Firedancer: the `firedancer` unit, the identity read with
        /// erpc's keypair helper (the host has no Solana CLI), and no command
        /// line to read the voting flag from.
        firedancer: bool,
    },
    /// [`FREE_DISKS_SCRIPT`]: which disks hold nothing and may become the
    /// validator's.
    FreeDisks,
    /// Prints a keypair file, to read it once into 1Password. Its output is
    /// a secret: the caller wipes it.
    ReadKeyFile(KeyFilePath),
    /// Restarts the `solv` service, so the validator starts from the startup
    /// script as it is now.
    RestartSolv,
    /// The host's facts as `key=value` lines: machine, memory, processors,
    /// free space, systemd's version, whether there is a TPM, and the address
    /// erpc's connection comes from.
    NodeFacts,
    /// Original Arc host operations through an externally authenticated helper.
    ArcControl(crate::arc::Control),
    /// An Arc node's journal.
    ArcLogs {
        /// Which layer.
        layer: crate::arc::Layer,
        /// How many lines from the end.
        lines: u32,
        /// Keep printing new lines.
        follow: bool,
    },
    /// Dedicated Arc validator preparation runtime journals, separate from RPC.
    ArcValidatorLogs {
        /// Original native component to inspect.
        layer: crate::arc::Layer,
        /// Bounded journal tail requested by the caller.
        lines: u32,
        /// Stream new journal lines.
        follow: bool,
    },
    /// An Ethereum node's facts as `key=value` lines: the OS, machine,
    /// memory, processors, the x86-64-v3 features, free space, and the
    /// address erpc's connection comes from.
    EthFacts,
    /// NEAR owner-checked lifecycle operation.
    NearControl {
        /// Closed operation.
        action: crate::near::Action,
        /// Bounded public ownership contract.
        contract: crate::near::Contract,
    },
    /// NEAR service journal.
    NearLogs {
        /// Number of lines.
        lines: u32,
        /// Continue following.
        follow: bool,
    },
    /// Confirm the exact NEAR firewall operation over fresh SSH.
    NearFirewallConfirm {
        /// Caller-owned operation token.
        token: crate::firewall::FirewallToken,
    },
    /// Nitro follower control request, with concealed credentials only on stdin.
    NitroControl,
    /// Dedicated BSC controller with the public request on stdin.
    BscControl(super::bsc::Control),
    /// Read the fixed BSC journal.
    BscLogs {
        /// Maximum recent lines.
        lines: u32,
        /// Continue following output.
        follow: bool,
    },
    /// Confirm the exact BSC firewall preparation through fresh SSH.
    BscFirewallConfirm {
        /// Isolated owner-qualified entrypoint.
        control: super::bsc::Control,
        /// Caller-owned run and bundle identity.
        token: crate::firewall::FirewallToken,
    },
    /// Original Arbitrum assertion-validator controller; private input is stdin only.
    NitroValidatorControl,
    /// Read a successful sealed run public result without trusting task logs.
    NitroValidatorResult(RunId),
    /// Private original-wallet pre-stage through one completed authenticated run.
    /// Only public source/result hashes are arguments; the secret stays on stdin.
    NitroValidatorStage {
        /// Successful original public authorization run.
        run: RunId,
        /// Exact compiled bundle digest.
        bundle: String,
        /// Complete carried helper profile digest.
        helpers: String,
        /// Public authorization request digest.
        request: String,
    },
    /// Original Robinhood Defensive host controller in its fixed network namespace.
    RobinhoodValidatorControl {
        /// Testnet selects only the independently qualified testnet namespace.
        testnet: bool,
    },
    /// Read a completed Defensive run; request digest binds its exact network.
    RobinhoodValidatorResult(RunId),
    /// Original Robinhood private custody/provider input through a sealed run.
    RobinhoodValidatorStage {
        /// Fixed network profile; never inferred from a private request.
        testnet: bool,
        /// Completed public authorization run.
        run: RunId,
        /// Complete bundle digest.
        bundle: String,
        /// Complete helper digest.
        helpers: String,
        /// Original public request digest.
        request: String,
    },
    /// Read the exact completed Robinhood admission observation, without native changes.
    RobinhoodAdmissionResult(RunId),
    /// Logs from dedicated Nitro follower services.
    NitroLogs {
        /// Closed choice of Robinhood or Arbitrum family.
        robinhood: bool,
        /// Number of lines.
        lines: u32,
        /// Continue following the journal.
        follow: bool,
    },
    /// Confirm an exact Nitro firewall operation through fresh SSH.
    NitroFirewallConfirm {
        /// Closed choice of Robinhood or Arbitrum family.
        robinhood: bool,
        /// Exact caller-owned operation and bundle.
        token: crate::firewall::FirewallToken,
    },
    /// Fixed validator controller; all request content goes on stdin.
    EthValidatorControl,
    /// Journal of the validator and its owned supporting clients.
    EthValidatorLogs {
        /// Number of recent lines.
        lines: u32,
        /// Follow new messages.
        follow: bool,
    },
    /// Avalanche public health and validation observations.
    AvaxStatus,
    /// Read-only remote contract preflight.
    AvaxCheckContract {
        /// Expected ownership.
        contract: crate::avax::Contract,
        /// Allow an empty host only during init.
        allow_missing: bool,
    },
    /// Avalanche ordered service operation.
    AvaxService {
        /// Required remote ownership.
        contract: crate::avax::Contract,
        /// Service action.
        action: crate::arc::Action,
    },
    /// Avalanche journal.
    AvaxLogs {
        /// Recent journal line count.
        lines: u32,
        /// Stream new records.
        follow: bool,
    },
    /// Avalanche identity custody over stdin/stdout.
    AvaxIdentity {
        /// Required remote ownership.
        contract: crate::avax::Contract,
        /// Custody operation.
        action: crate::avax::IdentityAction,
    },
    /// Avalanche firewall confirmation.
    AvaxFirewallConfirm {
        /// Exact operation and bundle submitted by the caller.
        token: crate::avax::FirewallToken,
        /// Required remote ownership.
        contract: crate::avax::Contract,
    },
    /// TRON operation with immutable public ownership.
    Tron(crate::tron::Command),
    /// Dedicated native Solana ownership and stdin lifecycle operations.
    SolanaNative(crate::solana_native::Command),

    /// Monad native controller and bounded journals.
    Monad(crate::monad::Command),

    /// Authenticated Hyperliquid non-validator controller.
    Hyperliquid(crate::hyperliquid::Command),
    /// Authenticated separate AQA publisher controller.
    HyperliquidAqa(crate::hyperliquid_aqa::Command),
    /// Sui node probe or lifecycle operation.
    Sui(crate::sui::Command),
    /// Owned Bitcoin controller, with all request fields on stdin.
    BitcoinControl {
        /// Fixed controller source carried by the compiled chain backend. This
        /// is public program text, never request data or a secret. The SSH
        /// operation rejects any bytes outside its pinned source digest.
        program: &'static str,
    },
    /// Bitcoin's journal after ownership verification.
    BitcoinLogs {
        /// Lines to read.
        lines: u32,
        /// Follow new lines.
        follow: bool,
    },
    /// Closed follower commands; contracts and credentials travel on stdin.
    Rollup(crate::rollup::Command),
    /// An erpc worker: its agent, its `ctl` verbs, its journal.
    Worker(crate::worker::Command),
    /// An Ethereum node's state as `key=value` lines, from its own ports.
    EthStatus,
    /// Original Ethereum RPC authority; closed public request supplied on stdin.
    EthAuthority,
    /// An Ethereum node's journal.
    EthLogs {
        /// Which layer.
        layer: crate::arc::Layer,
        /// How many lines from the end.
        lines: u32,
        /// Keep printing new lines.
        follow: bool,
    },
    /// A Solana RPC node's state as `key=value` lines, its identity read the
    /// way its validator unit makes it.
    SolanaRpcStatus,
    /// Starts, stops or restarts a Solana RPC node's validator or Old
    /// Faithful.
    SolanaRpcService {
        /// What to do.
        action: crate::arc::Action,
        /// To which service.
        service: crate::solana_rpc::Service,
    },
    /// A Solana RPC node's validator log, or a unit's journal.
    SolanaRpcLogs {
        /// Which log.
        source: crate::solana_rpc::LogSource,
        /// How many lines from the end.
        lines: u32,
        /// Keep printing new lines.
        follow: bool,
    },
    /// Confirms a Solana RPC node's new firewall table from a fresh
    /// connection.
    SolanaRpcFirewallConfirm {
        /// Exact operation and submitted bundle.
        token: crate::firewall::FirewallToken,
    },
    /// Puts the public key on standard input in the login user's
    /// `authorized_keys`.
    VpsAuthorizeKey,
    /// Turns password logins off; standard input's first line is the login
    /// password, for `sudo` if it asks.
    VpsHarden,
    /// Allows SSH only from a list of addresses, under a rollback timer.
    VpsAllowSsh(crate::vps::AllowList),
    /// Keeps the allow list just applied, from a fresh connection.
    VpsConfirmAllow,
    /// Takes the allow list away.
    VpsOpenSsh,
    /// The address the connection comes from, as `controller=<address>`.
    VpsController,
}

impl RemoteCommand {
    /// The line the node's shell runs.
    #[must_use]
    #[allow(clippy::too_many_lines)] // Keep the typed command renderer exhaustive as backends are added.
    pub fn line(&self) -> String {
        match self {
            Self::Polygon(command) => command.line(),
            Self::KaiaControl(command) => command.shell(),
            Self::KaiaLogs { lines, follow } => crate::kaia::logs(*lines, *follow),
            Self::KaiaFirewallConfirm { control, token } => crate::kaia::confirm(control, token),
            Self::Uname => "uname -srm".to_owned(),
            Self::OsRelease => "cat /etc/os-release".to_owned(),
            Self::WriteFile(path) => write_file(path),
            Self::Sha256(path) => format!("sha256sum -- '{}'", path.as_str()),
            Self::PrepareRun(prepared) => format!(
                "sudo -n /usr/bin/python3 -I - seal '{}' '{}' \
                 \"$(id -u)\" \"$(id -g)\" '{}' '{}'",
                prepared.start.run.dir(),
                prepared.start.sha256,
                prepared.runner,
                prepared.helper,
            ),
            Self::StartRun(start) => {
                let dir = start.run.dir();
                let id = start.run.as_str();
                format!(
                    "sudo -n systemd-run --quiet --collect --unit='erpc-{id}' \
                     --uid=\"$(id -u)\" --gid=\"$(id -g)\" \
                     --setenv=HOME=\"$HOME\" --setenv=USER=\"$(id -un)\" \
                     --property=WorkingDirectory='{dir}' \
                     --property=StandardOutput='append:{dir}/log' --property=StandardError='append:{dir}/log' \
                     /bin/bash '{dir}/node-run.sh' '{dir}' '{sha}' '{play}'",
                    sha = start.sha256,
                    play = start.play,
                )
            }
            Self::Ping(targets) => {
                let hosts: Vec<String> = targets.0.iter().map(|h| format!("'{h}'")).collect();
                format!(
                    "for h in {}; do printf '{PING_PREFIX} %s ' \"$h\"; \
                     ping -n -c 3 -W 2 -q -- \"$h\" 2>/dev/null | tail -n 1; echo; done; true",
                    hosts.join(" ")
                )
            }
            Self::FollowRun(run) => {
                let dir = run.dir();
                let id = run.as_str();
                format!(
                    "d='{dir}'; u='erpc-{id}'; i=0; \
                     until [ -e \"$d/log\" ] || [ $i -ge 100 ]; do sleep 0.1; i=$((i+1)); done; \
                     ( while [ ! -e \"$d/result.json\" ] && systemctl is-active --quiet \"$u\"; do sleep 1; done ) & w=$!; \
                     tail -n +1 -F --pid=\"$w\" \"$d/log\" 2>/dev/null; \
                     echo '{RESULT_MARKER}'; cat \"$d/result.json\" 2>/dev/null; true"
                )
            }
            Self::Remove(path) => format!("rm -f -- '{}'", path.as_str()),
            Self::FreeDisks => FREE_DISKS_SCRIPT.to_owned(),
            Self::ReadKeyFile(path) => format!("cat -- '{}'", path.as_str()),
            Self::RestartSolv => "sudo -n systemctl restart solv".to_owned(),
            Self::NodeFacts => crate::arc::NODE_FACTS.to_owned(),
            Self::ArcControl(control) => control.command(),
            Self::ArcLogs {
                layer,
                lines,
                follow,
            } => crate::arc::logs(*layer, *lines, *follow),
            Self::ArcValidatorLogs {
                layer,
                lines,
                follow,
            } => crate::arc::validator_logs(*layer, *lines, *follow),
            Self::VpsAuthorizeKey => crate::vps::AUTHORIZE_KEY.to_owned(),
            Self::VpsHarden => crate::vps::HARDEN.to_owned(),
            Self::VpsAllowSsh(list) => crate::vps::allow(list),
            Self::VpsConfirmAllow => crate::vps::CONFIRM_ALLOW.to_owned(),
            Self::VpsOpenSsh => crate::vps::OPEN.to_owned(),
            Self::VpsController => "printf 'controller=%s\\n' \"${SSH_CLIENT%% *}\"".to_owned(),
            Self::NearControl { action, contract } => super::near::control(*action, contract),
            Self::NearLogs { lines, follow } => super::near::logs(*lines, *follow),
            Self::NearFirewallConfirm { token } => super::near::confirm(token),

            Self::BscControl(control) => control.shell(),
            Self::BscLogs { lines, follow } => super::bsc::logs(*lines, *follow),
            Self::BscFirewallConfirm { control, token } => super::bsc::confirm(control, token),
            Self::NitroControl => super::python::nitro_control(),
            Self::NitroValidatorControl => super::python::nitro_validator_control(),
            Self::NitroValidatorResult(run) => super::nitro::public_result(run),
            Self::NitroValidatorStage {
                run,
                bundle,
                helpers,
                request,
            } => super::nitro::private_stage(run, bundle, helpers, request),
            Self::RobinhoodValidatorControl { testnet } => {
                super::python::robinhood_validator_control(*testnet)
            }
            Self::RobinhoodValidatorResult(run) => super::nitro::robinhood_validator_result(run),
            Self::RobinhoodValidatorStage {
                testnet,
                run,
                bundle,
                helpers,
                request,
            } => super::nitro::robinhood_private_stage(*testnet, run, bundle, helpers, request),
            Self::RobinhoodAdmissionResult(run) => super::nitro::robinhood_admission_result(run),
            Self::NitroLogs {
                robinhood,
                lines,
                follow,
            } => super::nitro::logs(*robinhood, *lines, *follow),
            Self::NitroFirewallConfirm { robinhood, token } => {
                super::nitro::confirm(*robinhood, token)
            }
            Self::EthValidatorControl => crate::eth_validator::control(),
            Self::EthValidatorLogs { lines, follow } => crate::eth_validator::logs(*lines, *follow),
            Self::AvaxStatus => crate::avax::status(),
            Self::AvaxCheckContract {
                contract,
                allow_missing,
            } => contract.check(*allow_missing),
            Self::AvaxService { action, contract } => crate::avax::service(*action, *contract),
            Self::AvaxLogs { lines, follow } => crate::avax::logs(*lines, *follow),
            Self::AvaxIdentity { action, contract } => crate::avax::identity(*action, *contract),
            Self::AvaxFirewallConfirm { contract, token } => crate::avax::confirm(*contract, token),
            Self::Sui(command) => command.shell(),
            Self::Tron(command) => command.shell(),
            Self::SolanaNative(command) => command.shell(),

            Self::Monad(command) => command.shell(),

            Self::Hyperliquid(command) => command.shell(),
            Self::HyperliquidAqa(command) => command.shell(),
            Self::BitcoinControl { program } => crate::bitcoin::control(program),
            Self::BitcoinLogs { lines, follow } => crate::bitcoin::logs(*lines, *follow),
            Self::Rollup(command) => command.shell(),
            Self::Worker(command) => command.shell(),
            Self::EthFacts => crate::eth::NODE_FACTS.to_owned(),
            Self::EthStatus => crate::eth::status(),
            Self::EthAuthority => crate::eth_authority::control(),
            Self::EthLogs {
                layer,
                lines,
                follow,
            } => crate::eth::logs(*layer, *lines, *follow),
            Self::SolanaRpcStatus => crate::solana_rpc::status(),
            Self::SolanaRpcService { action, service } => {
                crate::solana_rpc::service(*action, *service)
            }
            Self::SolanaRpcLogs {
                source,
                lines,
                follow,
            } => crate::solana_rpc::logs(*source, *lines, *follow),
            Self::SolanaRpcFirewallConfirm { token } => crate::solana_rpc::confirm_firewall(token),
            Self::ValidatorStatus {
                rpc_port,
                firedancer,
            } => validator_status(*rpc_port, *firedancer),
        }
    }
}

/// Write a validated path using the same private-directory policy as before.
fn write_file(path: &RemotePath) -> String {
    let program = include_str!("upload.py").replace('\'', "'\\''");
    format!(
        "sudo -n /usr/bin/python3 -I -c '{program}' '{}' \"$(id -u)\" \"$(id -g)\"",
        path.as_str(),
    )
}

/// [`RemoteCommand::ValidatorStatus`]'s line.
fn validator_status(rpc_port: u16, firedancer: bool) -> String {
    let rpc = |method: &str| local_rpc(rpc_port, method);
    if firedancer {
        format!(
            "printf 'service=%s\\n' \"$(systemctl is-active firedancer 2>/dev/null)\"; \
             printf 'identity_link=%s\\n' \"$(readlink -f \"$HOME/identity.json\" 2>/dev/null)\"; \
             printf 'identity=%s\\n' \"$(/usr/bin/python3 -I /usr/local/bin/erpc-keypair.py pubkey \"$HOME/identity.json\" 2>/dev/null)\"; \
             printf 'health=%s\\n' \"$({})\"; \
             printf 'slot=%s\\n' \"$({})\"; true",
            rpc("getHealth"),
            rpc("getSlot")
        )
    } else {
        format!(
            "export PATH=\"$HOME/.local/share/solana/install/active_release/bin:$PATH\"; \
             printf 'service=%s\\n' \"$(systemctl is-active solv 2>/dev/null)\"; \
             printf 'identity_link=%s\\n' \"$(readlink -f \"$HOME/identity.json\" 2>/dev/null)\"; \
             printf 'identity=%s\\n' \"$(solana-keygen pubkey \"$HOME/identity.json\" 2>/dev/null)\"; \
             printf 'health=%s\\n' \"$({})\"; \
             printf 'slot=%s\\n' \"$({})\"; \
             pid=$(systemctl show -p MainPID --value solv 2>/dev/null); \
             printf 'running_vote=%s\\n' \"$(tr '\\0' '\\n' < /proc/$pid/cmdline 2>/dev/null | grep -A1 -x -e --vote-account -e --no-voting | tr '\\n' ' ')\"; true",
            rpc("getHealth"),
            rpc("getSlot")
        )
    }
}

/// A JSON-RPC call to the validator's port on 127.0.0.1, printing its answer.
fn local_rpc(port: u16, method: &str) -> String {
    format!(
        "curl -s -m 5 -H 'Content-Type: application/json' \
         -d '{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"{method}\"}}' \
         http://127.0.0.1:{port} 2>/dev/null"
    )
}

#[cfg(test)]
mod tests {
    use super::{CommandError, RemoteCommand, RemotePath};

    #[test]
    fn only_a_plain_absolute_json_path_is_read_as_a_key() {
        use super::KeyFilePath;
        for ok in [
            "/home/solv/testnet-validator-keypair.json",
            "/home/op/.slv/keys/Abc123.json",
        ] {
            assert!(KeyFilePath::new(ok).is_ok(), "{ok}");
        }
        for bad in [
            "home/solv/key.json",
            "/home/solv/../root/key.json",
            "/home/solv//key.json",
            "/home/solv/key.txt",
            "/home/solv/k'ey.json",
            "/home/solv/$(id).json",
            "/home/solv/key json.json",
        ] {
            assert!(KeyFilePath::new(bad).is_err(), "{bad}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_free_disks_script_is_valid_shell() {
        let checked = std::process::Command::new("bash")
            .args(["-n", "-c", super::FREE_DISKS_SCRIPT])
            .status()
            .expect("bash");
        assert!(checked.success());
    }

    #[cfg(unix)]
    #[test]
    fn the_status_line_is_valid_shell_and_asks_only_the_local_port() {
        for firedancer in [false, true] {
            let line = RemoteCommand::ValidatorStatus {
                rpc_port: 7211,
                firedancer,
            }
            .line();
            assert!(line.contains("http://127.0.0.1:7211"), "{line}");
            assert_eq!(line.contains("is-active firedancer"), firedancer, "{line}");
            let checked = std::process::Command::new("bash")
                .args(["-n", "-c", &line])
                .status()
                .expect("bash");
            assert!(checked.success(), "{line}");
        }
    }

    #[test]
    fn only_plain_paths_under_the_writable_root_are_accepted() {
        assert!(RemotePath::new("/opt/erpc/runs/r-1/bundle.tar.gz").is_ok());
        for bad in [
            "/etc/passwd",
            "/opt/erpc/../etc/passwd",
            "/opt/erpc/runs/./x",
            "/opt/erpc/runs//x",
            "/opt/erpc/",
            "/opt/erpc/a b",
            "/opt/erpc/a'b",
            "/opt/erpc/$(id)",
            "/opt/erpc/a;rm",
            "opt/erpc/x",
            "/opt/erpcx/y",
        ] {
            assert_eq!(
                RemotePath::new(bad),
                Err(CommandError::Path(bad.to_owned())),
                "{bad}"
            );
        }
    }

    #[test]
    fn writing_a_file_keeps_it_private_and_takes_its_content_from_stdin() {
        let path = RemotePath::new("/opt/erpc/runs/r-1/bundle.tar.gz").expect("path");
        let line = RemoteCommand::WriteFile(path).line();
        assert!(
            line.starts_with("sudo -n /usr/bin/python3 -I -c '"),
            "{line}"
        );
        assert!(line.contains("sys.stdin.buffer"), "{line}");
        assert!(line.contains("O_NOFOLLOW"), "{line}");
        assert!(line.contains("0o755"), "{line}");
        assert!(
            line.ends_with("'/opt/erpc/runs/r-1/bundle.tar.gz' \"$(id -u)\" \"$(id -g)\""),
            "{line}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_upload_line_is_valid_shell() {
        let path = RemotePath::new(
            "/opt/erpc/uploads/bot-default/20261029T121314Z-1a2b3c4d/config/settings.json",
        )
        .expect("path");
        let line = RemoteCommand::WriteFile(path).line();
        let checked = std::process::Command::new("bash")
            .args(["-n", "-c", &line])
            .status()
            .expect("bash");
        assert!(checked.success(), "{line}");
    }

    #[test]
    fn preparing_a_run_binds_archive_and_both_scripts_before_start() {
        let run = super::RunId::new("r-20261026t120000-abcdef").unwrap();
        let digest = "a".repeat(64);
        let start = super::RunStart::new(run, &digest, "play.yml").unwrap();
        let prepared = super::RunPrepare::new(&start, &"b".repeat(64), &"c".repeat(64)).unwrap();
        let command = RemoteCommand::PrepareRun(prepared).line();
        assert!(command.starts_with("sudo -n /usr/bin/python3 -I - seal "));
        for digest in [&digest, &"b".repeat(64), &"c".repeat(64)] {
            assert!(command.contains(digest));
        }
        for bad in ["", "a' ; command", &"d".repeat(63)] {
            assert!(super::RunPrepare::new(&start, bad, &digest).is_err());
            assert!(super::RunPrepare::new(&start, &digest, bad).is_err());
        }
        let mut invalid = start;
        invalid.sha256 = "a' ; command".into();
        assert!(super::RunPrepare::new(&invalid, &digest, &digest).is_err());
    }

    #[test]
    fn a_run_takes_only_ids_digests_and_plays_of_their_form() {
        use super::{RunId, RunStart};
        let run = RunId::new("r-20261023t120000-abc123").expect("id");
        let digest = "a".repeat(64);
        let start = RunStart::new(
            run.clone(),
            &digest,
            "ansible/erpc-testnet-validator/deploy.yml",
        )
        .expect("start");
        let line = RemoteCommand::StartRun(start).line();
        assert!(
            line.contains("--unit='erpc-r-20261023t120000-abc123'"),
            "{line}"
        );
        assert!(
            line.ends_with(&format!(
                "'{digest}' 'ansible/erpc-testnet-validator/deploy.yml'"
            )),
            "{line}"
        );
        for bad in [
            "r-short",
            "x-20261023t120000",
            "r-20261023T120000",
            "r-2026;rm -rf /",
        ] {
            assert!(RunId::new(bad).is_err(), "{bad}");
        }
        for (digest, play) in [
            ("A".repeat(64), "a.yml".to_owned()),
            ("a".repeat(63), "a.yml".to_owned()),
            ("a".repeat(64), "../a.yml".to_owned()),
            ("a".repeat(64), "a b.yml".to_owned()),
        ] {
            assert!(
                RunStart::new(run.clone(), &digest, &play).is_err(),
                "{digest} {play}"
            );
        }
        assert!(
            RemoteCommand::FollowRun(run)
                .line()
                .contains("@@erpc-result@@")
        );
    }

    #[test]
    fn only_hosts_go_into_a_ping() {
        use super::PingTargets;
        let line = RemoteCommand::Ping(
            PingTargets::new(&["ny.testnet.block-engine.jito.wtf", "203.0.113.5"]).expect("hosts"),
        )
        .line();
        assert!(
            line.contains("for h in 'ny.testnet.block-engine.jito.wtf' '203.0.113.5';"),
            "{line}"
        );
        for bad in ["-f", "a b", "a;id", "$(id)", ""] {
            assert!(PingTargets::new(&[bad]).is_err(), "{bad:?}");
        }
        assert!(PingTargets::new(&[]).is_err());
    }

    #[test]
    fn the_read_only_commands_are_fixed() {
        assert_eq!(RemoteCommand::Uname.line(), "uname -srm");
        assert_eq!(RemoteCommand::OsRelease.line(), "cat /etc/os-release");
    }
}
