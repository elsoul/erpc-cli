// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Private keys and secrets left on the server: key files, seed phrases,
//! keystores without encryption, secrets in environment files, in running
//! processes' environments and in shell histories.
//!
//! The search walks a fixed list of directories under the root. Each
//! directory and file is opened relative to its parent's descriptor, so a
//! directory swapped for a link while the walk runs leads nowhere new. The
//! walk never follows a symbolic link, never leaves the filesystem a
//! directory it starts from is on (a home under `/home` may be one of its
//! own), skips the directories chains keep their databases in, reads only
//! regular files of at most [`FILE_LIMIT`] bytes and the last
//! [`TAIL_LIMIT`] bytes of a shell history, and stops at its [`BUDGET`]. On
//! Linux an entry is first opened as a path only, so no device is opened
//! and no pipe waited on. The one read outside the walk is the identity
//! file each running validator was given, read where the validator reads
//! it, through links and on any filesystem, and only if it is a regular
//! file.
//!
//! Contents go into one buffer that is wiped after every file. What leaves
//! this module for the request is a kind, a role, a class of place and of
//! access, and a count; the paths go apart, into [`Places`], for the
//! operator's own screen.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use erpc_api::security_check::{Access, Coverage, KeyGroup, KeyKind, KeyLocation, KeyRole, Keys};
use zeroize::{Zeroize as _, Zeroizing};

use super::procs::Budget;

/// What the search may spend before it stops and reports itself partial.
pub(super) const BUDGET: Budget = Budget {
    entries: 200_000,
    time: Duration::from_secs(20),
};

/// The largest file read whole.
const FILE_LIMIT: usize = 64 * 1024;
/// How much of the end of a shell history is read, and the largest process
/// environment read (a larger one makes the search partial).
const TAIL_LIMIT: usize = 1024 * 1024;
/// How deep below a start the walk goes; deeper makes the search partial.
/// The walk holds one descriptor per level.
const MAX_DEPTH: usize = 48;
/// How many places are kept per group to show.
const PLACES_SHOWN: usize = 10;

/// A directory the walk starts from, under the root.
struct Start {
    path: &'static str,
    location: KeyLocation,
    /// Whether each directory in it is a home that may be a filesystem of
    /// its own.
    homes: bool,
}

const STARTS: &[Start] = &[
    Start {
        path: "root",
        location: KeyLocation::RootHome,
        homes: false,
    },
    Start {
        path: "home",
        location: KeyLocation::Home,
        homes: true,
    },
    Start {
        path: "etc",
        location: KeyLocation::Etc,
        homes: false,
    },
    Start {
        path: "opt",
        location: KeyLocation::Opt,
        homes: false,
    },
    Start {
        path: "srv",
        location: KeyLocation::Srv,
        homes: false,
    },
    Start {
        path: "var/lib/docker/volumes",
        location: KeyLocation::Docker,
        homes: false,
    },
    Start {
        path: "var/lib",
        location: KeyLocation::Var,
        homes: false,
    },
    Start {
        path: "tmp",
        location: KeyLocation::Tmp,
        homes: false,
    },
    Start {
        path: "var/tmp",
        location: KeyLocation::Tmp,
        homes: false,
    },
];

/// Directories not entered, by their path under the root: Docker's image
/// layers, and its volumes, which are a start of their own.
const SKIPPED_PATHS: &[&str] = &["var/lib/docker/overlay2", "var/lib/docker/volumes"];

/// Directories not entered wherever they are: the names chains give the
/// directories that hold their ledgers, snapshots and databases.
const CHAIN_DATA: &[&str] = &[
    "ledger",
    "accounts",
    "snapshots",
    "rocksdb",
    "chaindata",
    "geth",
    "nodes",
    "data",
];

/// Where each key group was found, in the order of the request's groups.
/// It is shown on the operator's screen and goes nowhere else.
#[derive(Default)]
pub(crate) struct Places(Vec<Shown>);

/// The places of one group.
#[derive(Default)]
pub(crate) struct Shown {
    /// The first places, as paths with control characters escaped.
    pub(crate) paths: Vec<String>,
    /// How many more places there are.
    pub(crate) more: u64,
}

impl Places {
    /// The places of the group at `index` in the request.
    pub(crate) fn of(&self, index: usize) -> Option<&Shown> {
        self.0.get(index)
    }
}

type GroupKey = (KeyKind, KeyRole, KeyLocation, Access);

/// What was found so far, grouped as the request carries it.
#[derive(Default)]
struct Found {
    groups: BTreeMap<GroupKey, (u64, Shown)>,
}

impl Found {
    fn add(&mut self, key: GroupKey, count: usize, place: String) {
        if count == 0 {
            return;
        }
        let (total, shown) = self.groups.entry(key).or_default();
        *total = total.saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
        if shown.paths.len() < PLACES_SHOWN {
            shown.paths.push(place);
        } else {
            shown.more += 1;
        }
    }

    /// The request's groups with `coverage`, lowered to partial when a
    /// count had to be capped or groups dropped, and their places.
    fn finish(self, coverage: Coverage) -> (Keys, Places) {
        let mut capped = false;
        let (items, places): (Vec<KeyGroup>, Vec<Shown>) = self
            .groups
            .into_iter()
            .map(|((kind, role, location, access), (total, shown))| {
                capped |= total > u64::from(KeyGroup::MAX_COUNT);
                let count = u32::try_from(total)
                    .unwrap_or(u32::MAX)
                    .min(KeyGroup::MAX_COUNT);
                (
                    KeyGroup {
                        kind,
                        role,
                        location,
                        access,
                        count,
                    },
                    shown,
                )
            })
            .unzip();
        let keys = Keys::new(
            if capped {
                coverage.at_most_partial()
            } else {
                coverage
            },
            items,
        );
        let mut places = places;
        places.truncate(keys.items().len());
        (keys, Places(places))
    }
}

/// One buffer for every file's contents, wiped after each use.
struct Buffer(Zeroizing<Vec<u8>>);

impl Buffer {
    fn new() -> Self {
        Self(Zeroizing::new(vec![0; TAIL_LIMIT + 1]))
    }

    /// Hands at most `limit` bytes of `source` to `check`, then wipes them.
    /// `Ok(None)` when `source` holds more than `limit` and `whole` is set.
    fn read<R>(
        &mut self,
        source: &mut impl Read,
        limit: usize,
        whole: bool,
        check: impl FnOnce(&[u8]) -> R,
    ) -> std::io::Result<Option<R>> {
        let buffer = &mut self.0[..=limit.min(TAIL_LIMIT)];
        let mut filled = 0;
        let mut failed = None;
        while filled < buffer.len() {
            match source.read(&mut buffer[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => {
                    failed = Some(e);
                    break;
                }
            }
        }
        let result = match failed {
            Some(e) => Err(e),
            None if filled > limit && whole => Ok(None),
            None => Ok(Some(check(&buffer[..filled.min(limit)]))),
        };
        buffer[..filled].zeroize();
        result
    }
}

/// A path under `root` as it is on the server, safe to print.
fn place(root: &Path, path: &Path) -> String {
    let inside = path.strip_prefix(root).unwrap_or(path);
    printable(&Path::new("/").join(inside).to_string_lossy())
}

/// `text` with control and bidirectional formatting characters escaped, so
/// a file's name cannot rewrite the operator's terminal.
fn printable(text: &str) -> String {
    let bidi = |c: char| {
        matches!(
            c,
            '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}'..='\u{202e}'
        )
    };
    let isolate = |c: char| matches!(c, '\u{2066}'..='\u{2069}');
    text.chars()
        .map(|c| {
            if c.is_control() || bidi(c) || isolate(c) {
                c.escape_unicode().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// The device a directory below is held to, `None` when it is on another
/// filesystem than its start. A home directory may be a filesystem of its
/// own, so a start of homes takes each one's own.
fn descend(homes: bool, depth: usize, start_dev: u64, dev: u64) -> Option<u64> {
    if homes && depth == 0 {
        Some(dev)
    } else {
        (dev == start_dev).then_some(start_dev)
    }
}

/// Who can reach a directory, as the modes of the directories above it
/// allow.
#[derive(Clone, Copy)]
struct Reach {
    others: bool,
    group: bool,
}

impl Reach {
    const ALL: Self = Self {
        others: true,
        group: true,
    };

    /// The reach of a directory with `mode` inside this one.
    const fn through(self, mode: u32) -> Self {
        Self {
            others: self.others && mode & 0o001 != 0,
            group: self.group && mode & 0o011 != 0,
        }
    }

    /// Who can read a file with `mode` in a directory of this reach.
    const fn access(self, mode: u32) -> Access {
        if self.others && mode & 0o004 != 0 {
            Access::World
        } else if self.group && mode & 0o040 != 0 {
            Access::Group
        } else {
            Access::OwnerOnly
        }
    }
}

/// Searches under `root`, the processes `scan` listed, and the identity
/// files running validators were given, at `identities`.
#[cfg(unix)]
pub(super) fn search(
    root: &Path,
    budget: Budget,
    scan: &super::procs::Scan,
    identities: &[PathBuf],
) -> (Keys, Places) {
    let mut search = walk::Search::new(root, budget);
    search.identities(identities);
    search.environs(scan);
    for start in STARTS {
        if search.cut() {
            break;
        }
        search.walk(start);
    }
    search.finish()
}

/// Elsewhere the modes and devices this reads do not exist.
#[cfg(not(unix))]
pub(super) fn search(
    _root: &Path,
    _budget: Budget,
    _scan: &super::procs::Scan,
    _identities: &[PathBuf],
) -> (Keys, Places) {
    (Keys::unreadable(), Places::default())
}

#[cfg(unix)]
mod walk {
    use std::collections::BTreeSet;
    use std::ffi::{CStr, OsStr};
    use std::fs::{File, Metadata};
    use std::os::fd::OwnedFd;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::MetadataExt as _;
    use std::path::{Path, PathBuf};
    use std::time::Instant;

    use erpc_api::security_check::{Access, Coverage, KeyKind, KeyLocation, KeyRole, Keys};
    use rustix::fs::{Dir, FileType, Mode, OFlags};

    use super::{
        Budget, Buffer, CHAIN_DATA, FILE_LIMIT, Found, MAX_DEPTH, Places, Reach, SKIPPED_PATHS,
        Start, TAIL_LIMIT, descend, place,
    };
    use crate::node::security::secrets;

    /// Whether an error says the file or process went away, which is no
    /// loss of view.
    fn gone(error: &std::io::Error) -> bool {
        error.kind() == std::io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH)
    }

    /// An entry of a directory, opened without starting a device's driver.
    pub(super) enum Opened {
        Dir(OwnedFd, Metadata),
        File(File, Metadata),
        /// A link (when links are not followed), a pipe, a socket or a
        /// device: never read.
        Other,
    }

    /// Opens `name` in the directory `dir` (or a path, with
    /// [`rustix::fs::CWD`]): a directory to list, or a regular file to read.
    /// On Linux the entry is first opened as a path only, which opens no
    /// device and waits on no pipe; only a directory or a regular file is
    /// then opened for reading, through that same descriptor.
    #[cfg(target_os = "linux")]
    pub(super) fn open_entry(
        dir: impl rustix::fd::AsFd,
        name: &CStr,
        follow: bool,
    ) -> std::io::Result<Opened> {
        let mut flags = OFlags::PATH | OFlags::CLOEXEC;
        if !follow {
            flags |= OFlags::NOFOLLOW;
        }
        let path = File::from(rustix::fs::openat(dir, name, flags, Mode::empty())?);
        let meta = path.metadata()?;
        // An error from here on is a loss of view, never a file gone.
        let reopen = |e: std::io::Error| std::io::Error::other(e.to_string());
        if meta.is_dir() {
            let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
            let fd = rustix::fs::openat(&path, c".", flags, Mode::empty())
                .map_err(|e| reopen(e.into()))?;
            Ok(Opened::Dir(fd, meta))
        } else if meta.is_file() {
            // The descriptor's own link in /proc names this very file.
            use std::os::fd::AsRawFd as _;
            let file = File::open(format!("/proc/self/fd/{}", path.as_raw_fd())).map_err(reopen)?;
            Ok(Opened::File(file, meta))
        } else {
            Ok(Opened::Other)
        }
    }

    /// Elsewhere there is no path-only open; the check itself runs on Linux
    /// only, and this serves the tests.
    #[cfg(not(target_os = "linux"))]
    pub(super) fn open_entry(
        dir: impl rustix::fd::AsFd,
        name: &CStr,
        follow: bool,
    ) -> std::io::Result<Opened> {
        let nofollow = if follow {
            OFlags::empty()
        } else {
            OFlags::NOFOLLOW
        };
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | nofollow;
        match rustix::fs::openat(&dir, name, flags, Mode::empty()) {
            Ok(fd) => {
                let file = File::from(fd);
                let meta = file.metadata()?;
                return Ok(Opened::Dir(file.into(), meta));
            }
            Err(rustix::io::Errno::NOTDIR) => {}
            Err(e) => return Err(e.into()),
        }
        let flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC | nofollow;
        let file = File::from(rustix::fs::openat(&dir, name, flags, Mode::empty())?);
        let meta = file.metadata()?;
        Ok(if meta.is_file() {
            Opened::File(file, meta)
        } else {
            Opened::Other
        })
    }

    /// Whether an error says the entry is a link that was not followed.
    pub(super) fn link(error: &std::io::Error) -> bool {
        error.raw_os_error() == Some(libc::ELOOP)
    }

    pub(super) struct Search<'a> {
        root: &'a Path,
        budget: Budget,
        started: Instant,
        seen: usize,
        cut: bool,
        partial: bool,
        opened: usize,
        buffer: Buffer,
        identities: BTreeSet<String>,
        found: Found,
    }

    /// A directory being listed.
    struct Frame {
        dir: Dir,
        path: PathBuf,
        dev: u64,
        reach: Reach,
        depth: usize,
    }

    impl<'a> Search<'a> {
        pub(super) fn new(root: &'a Path, budget: Budget) -> Self {
            Self {
                root,
                budget,
                started: Instant::now(),
                seen: 0,
                cut: false,
                partial: false,
                opened: 0,
                buffer: Buffer::new(),
                identities: BTreeSet::new(),
                found: Found::default(),
            }
        }

        pub(super) const fn cut(&self) -> bool {
            self.cut
        }

        /// Counts one entry; whether the budget is spent.
        fn spend(&mut self) -> bool {
            self.seen += 1;
            if self.seen > self.budget.entries || self.started.elapsed() > self.budget.time {
                self.cut = true;
                self.partial = true;
            }
            self.cut
        }

        /// The public keys of the identity files at `paths`, which running
        /// validators were given. Unlike the walk, this reads a file where
        /// the validator does: through links, and on any filesystem. Only a
        /// regular file is read.
        pub(super) fn identities(&mut self, paths: &[PathBuf]) {
            for path in paths {
                let pubkey = rustix::ffi::CString::new(path.as_os_str().as_bytes())
                    .map_err(std::io::Error::other)
                    .and_then(|path| open_entry(rustix::fs::CWD, &path, true))
                    .and_then(|opened| match opened {
                        Opened::File(mut file, _) => self
                            .buffer
                            .read(&mut file, FILE_LIMIT, true, secrets::solana_pubkey)
                            .map(Option::flatten),
                        Opened::Dir(..) | Opened::Other => Ok(None),
                    });
                match pubkey {
                    Ok(Some(pubkey)) => {
                        self.identities.insert(pubkey);
                    }
                    Ok(None) => {}
                    Err(e) if gone(&e) => {}
                    // A key that cannot be told to be the identity would
                    // read as a wallet's.
                    Err(_) => self.partial = true,
                }
            }
        }

        /// Every listed process's environment, read whole up to its limit.
        pub(super) fn environs(&mut self, scan: &crate::node::security::procs::Scan) {
            if !scan.listed {
                self.partial = true;
            }
            let mut pids: Vec<u32> = scan.apps.keys().copied().collect();
            pids.sort_unstable();
            for pid in pids {
                if self.spend() {
                    return;
                }
                let path = self.root.join("proc").join(pid.to_string()).join("environ");
                let count = File::open(&path).and_then(|mut file| {
                    self.buffer
                        .read(&mut file, TAIL_LIMIT, true, secrets::environ_secrets)
                });
                match count {
                    Ok(Some(count)) => self.found.add(
                        (
                            KeyKind::ProcessEnvSecret,
                            KeyRole::Unknown,
                            KeyLocation::ProcessEnv,
                            Access::OwnerOnly,
                        ),
                        count,
                        place(self.root, &path),
                    ),
                    Err(e) if gone(&e) => {}
                    // Too large to read whole, or not this account's.
                    Ok(None) | Err(_) => self.partial = true,
                }
            }
        }

        /// The reach of the directory at `path` under the root, from the
        /// modes of the root and the directories between. `None` when one
        /// cannot be read or is a link.
        fn reach_of(&self, path: &str) -> Option<Reach> {
            let mut at = self.root.to_path_buf();
            let mut reach = Reach::ALL;
            let parts: Vec<_> = Path::new(path).components().collect();
            for part in std::iter::once(None).chain(parts.iter().map(Some)) {
                if let Some(part) = part {
                    at.push(part);
                }
                let meta = std::fs::symlink_metadata(&at).ok()?;
                if meta.file_type().is_symlink() {
                    return None;
                }
                reach = reach.through(meta.mode());
            }
            Some(reach)
        }

        /// The start directory, opened without following a link.
        fn open_start(&mut self, start: &Start) -> Option<Frame> {
            let path = self.root.join(start.path);
            match std::fs::symlink_metadata(&path) {
                Ok(meta) if meta.is_dir() => {}
                Ok(meta) => {
                    // A start that is a link leads where this search does
                    // not go.
                    self.partial |= meta.file_type().is_symlink();
                    return None;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
                Err(_) => {
                    self.partial = true;
                    return None;
                }
            }
            let reach = self.reach_of(start.path);
            let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            let opened = rustix::fs::open(&path, flags, Mode::empty())
                .map_err(std::io::Error::from)
                .and_then(|fd| {
                    let file = File::from(fd);
                    let meta = file.metadata()?;
                    Ok((Dir::new(OwnedFd::from(file))?, meta))
                });
            let (Ok((dir, meta)), Some(reach)) = (opened, reach) else {
                self.partial = true;
                return None;
            };
            self.opened += 1;
            Some(Frame {
                dir,
                path,
                dev: meta.dev(),
                reach,
                depth: 0,
            })
        }

        pub(super) fn walk(&mut self, start: &Start) {
            let Some(first) = self.open_start(start) else {
                return;
            };
            let mut frames = vec![first];
            while let Some(frame) = frames.last_mut() {
                let Some(entry) = frame.dir.read() else {
                    frames.pop();
                    continue;
                };
                let Ok(entry) = entry else {
                    self.partial = true;
                    frames.pop();
                    continue;
                };
                let name = entry.file_name();
                if name == c"." || name == c".." {
                    continue;
                }
                if self.spend() {
                    return;
                }
                // Links, pipes, sockets and devices are not opened. An entry
                // of unknown type is opened as a path to find out.
                if !matches!(
                    entry.file_type(),
                    FileType::RegularFile | FileType::Directory | FileType::Unknown
                ) {
                    continue;
                }
                let path = frame.path.join(OsStr::from_bytes(name.to_bytes()));
                if entry.file_type() == FileType::Directory && self.skipped(&path, name) {
                    continue;
                }
                let opened = frame
                    .dir
                    .fd()
                    .map_err(std::io::Error::from)
                    .and_then(|dir| open_entry(dir, name, false));
                let child = match opened {
                    Ok(Opened::Dir(fd, meta)) => {
                        if self.skipped(&path, name) {
                            continue;
                        }
                        let Some(dev) = descend(start.homes, frame.depth, frame.dev, meta.dev())
                        else {
                            continue;
                        };
                        if frame.depth + 1 > MAX_DEPTH {
                            self.partial = true;
                            continue;
                        }
                        let Ok(dir) = Dir::new(fd) else {
                            self.partial = true;
                            continue;
                        };
                        Frame {
                            dir,
                            path,
                            dev,
                            reach: frame.reach.through(meta.mode()),
                            depth: frame.depth + 1,
                        }
                    }
                    Ok(Opened::File(file, meta)) => {
                        let reach = frame.reach;
                        self.file(&path, name.to_bytes(), file, &meta, reach, start.location);
                        continue;
                    }
                    Ok(Opened::Other) => continue,
                    Err(e) if gone(&e) || link(&e) => continue,
                    Err(_) => {
                        self.partial = true;
                        continue;
                    }
                };
                frames.push(child);
            }
        }

        fn skipped(&self, path: &Path, name: &CStr) -> bool {
            CHAIN_DATA
                .iter()
                .any(|skip| name.to_bytes() == skip.as_bytes())
                || path
                    .strip_prefix(self.root)
                    .is_ok_and(|inside| SKIPPED_PATHS.iter().any(|skip| inside == Path::new(skip)))
        }

        fn file(
            &mut self,
            path: &Path,
            name: &[u8],
            mut file: File,
            meta: &Metadata,
            reach: Reach,
            location: KeyLocation,
        ) {
            let history = is_history(path, name);
            if meta.len() == 0 || (!history && meta.len() > FILE_LIMIT as u64) {
                return;
            }
            let access = reach.access(meta.mode());
            let found = if history {
                let skip = meta.len().saturating_sub(TAIL_LIMIT as u64);
                if skip > 0 {
                    use std::io::Seek as _;
                    if file.seek(std::io::SeekFrom::Start(skip)).is_err() {
                        self.partial = true;
                        return;
                    }
                }
                self.buffer
                    .read(&mut file, TAIL_LIMIT, false, |tail| {
                        // The first line of a tail may be the end of one
                        // cut in two.
                        let lines = if skip > 0 {
                            tail.iter()
                                .position(|&b| b == b'\n')
                                .map_or(&[][..], |at| &tail[at + 1..])
                        } else {
                            tail
                        };
                        secrets::history_secret_lines(lines)
                    })
                    .map(|count| {
                        count.map(|count| {
                            (
                                KeyKind::HistorySecret,
                                count,
                                KeyRole::Unknown,
                                KeyLocation::ShellHistory,
                            )
                        })
                    })
            } else {
                self.buffer
                    .read(&mut file, FILE_LIMIT, true, |contents| {
                        secrets::classify(name, contents)
                    })
                    .map(|hit| {
                        hit.flatten().map(|hit| {
                            let identity = hit
                                .pubkey
                                .as_ref()
                                .is_some_and(|pubkey| self.identities.contains(pubkey));
                            let role = if identity {
                                KeyRole::ValidatorIdentity
                            } else {
                                KeyRole::Unknown
                            };
                            (hit.kind, hit.count, role, location)
                        })
                    })
            };
            match found {
                Ok(Some((kind, count, role, location))) => {
                    self.found.add(
                        (kind, role, location, access),
                        count,
                        place(self.root, path),
                    );
                }
                // A file that grew past the limit since it was listed.
                Ok(None) => {}
                Err(_) => self.partial = true,
            }
        }

        pub(super) fn finish(self) -> (Keys, Places) {
            if self.opened == 0 && self.found.groups.is_empty() {
                return (Keys::unreadable(), Places::default());
            }
            let coverage = if self.partial || self.opened == 0 {
                Coverage::Partial
            } else {
                Coverage::Complete
            };
            self.found.finish(coverage)
        }
    }

    /// Whether the file at `path`, named `name`, is a shell's history.
    fn is_history(path: &Path, name: &[u8]) -> bool {
        matches!(name, b".bash_history" | b".zsh_history")
            || (name == b"fish_history"
                && path
                    .parent()
                    .is_some_and(|dir| dir.ends_with(".local/share/fish")))
    }
}

#[cfg(test)]
impl Places {
    /// Places made by hand, for the report's tests.
    pub(crate) fn of_groups(groups: Vec<Shown>) -> Self {
        Self(groups)
    }
}

#[cfg(all(test, unix))]
pub(super) mod tests {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use erpc_api::security_check::{
        Access, App, Coverage, KeyGroup, KeyKind, KeyLocation, KeyRole, Keys,
    };
    use erpc_chain_solana::identity::{Keypair, base58};

    use super::super::procs::{Budget, Scan};
    use super::super::secrets::tests::{array_with, hex_key, phrase};
    use super::walk::{Opened, link, open_entry};
    use super::{BUDGET, Found, MAX_DEPTH, Reach, descend, printable, search};

    fn write(root: &Path, path: &str, contents: &[u8], mode: u32) {
        let path = root.join(path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap_or_else(|e| panic!("{e}"));
        }
        std::fs::write(&path, contents).unwrap_or_else(|e| panic!("{e}"));
        chmod(&path, mode);
    }

    fn chmod(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .unwrap_or_else(|e| panic!("{e}"));
    }

    fn keypair() -> Keypair {
        Keypair::generate().unwrap_or_else(|e| panic!("{e}"))
    }

    /// A server with a key of every kind in every place, and what must not
    /// be counted beside them.
    pub(in crate::node::security) struct KeyHost {
        pub(in crate::node::security) root: PathBuf,
        /// Every secret written, as text.
        pub(in crate::node::security) secrets: Vec<String>,
    }

    /// The modes of the fixture's directories, set whatever the umask.
    fn set_modes(root: &Path) {
        for (dir, mode) in [
            ("", 0o755),
            ("home", 0o755),
            ("home/sol", 0o750),
            ("home/sol/private", 0o700),
            ("root", 0o700),
            ("etc", 0o755),
            ("etc/bot", 0o755),
            ("var/lib/docker", 0o710),
            ("var/lib/docker/volumes", 0o701),
            ("tmp", 0o1777),
        ] {
            chmod(&root.join(dir), mode);
        }
    }

    pub(in crate::node::security) fn key_host(name: &str) -> KeyHost {
        let root = crate::node::security::fixture(name);
        let [identity, wallet, hidden, docker, outside] = std::array::from_fn(|_| keypair());
        let hex = hex_key();
        let words = phrase(24);
        let typed = base58(keypair().bytes());
        let json = |k: &Keypair| k.to_json().as_bytes().to_vec();
        let found: [(&str, Vec<u8>, u32); 15] = [
            ("home/sol/validator-keypair.json", json(&identity), 0o644),
            ("home/sol/wallet/id.json", json(&wallet), 0o600),
            ("home/sol/private/k.json", json(&hidden), 0o644),
            ("home/sol/.config/deployer.key", format!("0x{hex}\n").into(), 0o600),
            ("var/lib/docker/volumes/v1/_data/id.json", json(&docker), 0o644),
            ("var/lib/app/key.hex", hex.clone().into(), 0o644),
            ("tmp/x/wallet.key", hex.clone().into(), 0o644),
            ("opt/bot/seed.txt", format!("{words}\n").into(), 0o644),
            (
                "etc/bot/keystore.json",
                format!(r#"{{"address": "ab", "privateKey": "0x{hex}"}}"#).into(),
                0o640,
            ),
            (
                "srv/app/.env",
                format!("LOG_LEVEL=info\nPRIVATE_KEY=0x{hex}\nBOT_MNEMONIC=\"{words}\"\n").into(),
                0o644,
            ),
            (
                "root/.bash_history",
                format!("ls\nimport {typed}\nexport WALLET_KEY={hex}\n").into(),
                0o600,
            ),
            (
                "home/sol/.local/share/fish/fish_history",
                format!("- cmd: env PRIVATE_KEY={hex} ./bot\n- cmd: cast wallet import --private-key {hex}\n").into(),
                0o600,
            ),
            (
                "proc/41/cmdline",
                b"agave-validator\0--identity\0/home/sol/validator-keypair.json\0".to_vec(),
                0o644,
            ),
            ("proc/41/comm", b"agave-validator\n".to_vec(), 0o644),
            (
                "proc/41/environ",
                format!("HOME=/home/sol\0PRIVATE_KEY={hex}\0SEED_PHRASE=op://v/i/f\0").into(),
                0o644,
            ),
        ];
        let mut big = hex.clone().into_bytes();
        big.resize(super::FILE_LIMIT + 1, b' ');
        let not_found: [(&str, Vec<u8>, u32); 10] = [
            ("home/sol/ledger/id.json", json(&keypair()), 0o644),
            ("mnt/keys/real.json", json(&outside), 0o644),
            (
                "home/sol/notes/UTC--2024",
                br#"{"version": 3, "address": "ab", "crypto": {"cipher": "aes-128-ctr"}}"#.to_vec(),
                0o600,
            ),
            (
                "home/sol/app/.env",
                b"PRIVATE_KEY=op://vault/item/key\nMNEMONIC=${MNEMONIC_FILE}\n".to_vec(),
                0o644,
            ),
            ("home/sol/bad.json", array_with(256).into(), 0o644),
            ("home/sol/short.key", hex.as_bytes()[1..].to_vec(), 0o644),
            ("home/sol/server.pem", format!("{hex}\n").into(), 0o644),
            (
                "var/lib/docker/overlay2/l1/diff/id.json",
                json(&keypair()),
                0o644,
            ),
            ("home/sol/big.key", big, 0o644),
            ("opt/bot/README", b"no keys here\n".to_vec(), 0o644),
        ];
        for (path, contents, mode) in found.iter().chain(&not_found) {
            write(&root, path, contents, *mode);
        }
        symlink("../../mnt/keys/real.json", root.join("home/sol/link.json"))
            .unwrap_or_else(|e| panic!("{e}"));
        symlink("../mnt/keys", root.join("opt/keys")).unwrap_or_else(|e| panic!("{e}"));
        // A pipe is neither opened nor waited on, where mkfifo exists.
        let _ = std::process::Command::new("mkfifo")
            .arg(root.join("tmp/x/pipe.key"))
            .status();
        set_modes(&root);
        let mut secrets = vec![hex, words, typed];
        for keypair in [identity, wallet, hidden, docker, outside] {
            secrets.push(keypair.to_json().to_string());
            secrets.push(keypair.pubkey());
        }
        KeyHost { root, secrets }
    }

    fn groups(keys: &Keys) -> Vec<(KeyKind, KeyRole, KeyLocation, Access, u32)> {
        keys.items()
            .iter()
            .map(|g| (g.kind, g.role, g.location, g.access, g.count))
            .collect()
    }

    fn scan(pids: &[u32]) -> Scan {
        Scan {
            apps: pids.iter().map(|&pid| (pid, App::Other)).collect(),
            listed: true,
            complete: true,
            ..Scan::default()
        }
    }

    #[test]
    fn keys_are_counted_by_kind_role_place_and_access() {
        use Access as A;
        use KeyKind as K;
        use KeyLocation as L;
        use KeyRole as R;

        let host = key_host("keys-found");
        let identity = host.root.join("home/sol/validator-keypair.json");
        let (keys, places) = search(&host.root, BUDGET, &scan(&[41]), &[identity]);
        assert_eq!(
            groups(&keys),
            [
                (K::SolanaKeypair, R::ValidatorIdentity, L::Home, A::Group, 1),
                (K::SolanaKeypair, R::Unknown, L::Home, A::OwnerOnly, 2),
                (K::SolanaKeypair, R::Unknown, L::Docker, A::Group, 1),
                (K::EvmPrivateKey, R::Unknown, L::Home, A::OwnerOnly, 1),
                (K::EvmPrivateKey, R::Unknown, L::Var, A::World, 1),
                (K::EvmPrivateKey, R::Unknown, L::Tmp, A::World, 1),
                (K::Mnemonic, R::Unknown, L::Opt, A::World, 1),
                (K::UnencryptedKeystore, R::Unknown, L::Etc, A::Group, 1),
                (K::EnvSecret, R::Unknown, L::Srv, A::World, 2),
                (
                    K::ProcessEnvSecret,
                    R::Unknown,
                    L::ProcessEnv,
                    A::OwnerOnly,
                    1
                ),
                (
                    K::HistorySecret,
                    R::Unknown,
                    L::ShellHistory,
                    A::OwnerOnly,
                    4
                ),
            ]
        );
        assert_eq!(keys.coverage(), Coverage::Complete);

        let shown = |index: usize| {
            let mut paths = places
                .of(index)
                .unwrap_or_else(|| panic!("no places for {index}"))
                .paths
                .clone();
            paths.sort();
            paths
        };
        assert_eq!(shown(0), ["/home/sol/validator-keypair.json"]);
        assert_eq!(
            shown(1),
            ["/home/sol/private/k.json", "/home/sol/wallet/id.json"]
        );
        assert_eq!(shown(2), ["/var/lib/docker/volumes/v1/_data/id.json"]);
        assert_eq!(shown(9), ["/proc/41/environ"]);
        assert_eq!(
            shown(10),
            [
                "/home/sol/.local/share/fish/fish_history",
                "/root/.bash_history"
            ]
        );
        assert!(places.of(11).is_none());
        let _ = std::fs::remove_dir_all(&host.root);
    }

    #[test]
    fn without_the_identity_its_keypair_is_a_wallet_key() {
        let host = key_host("keys-no-identity");
        let (keys, _) = search(&host.root, BUDGET, &scan(&[]), &[]);
        let groups = groups(&keys);
        assert!(groups.contains(&(
            KeyKind::SolanaKeypair,
            KeyRole::Unknown,
            KeyLocation::Home,
            Access::Group,
            1
        )));
        assert!(groups.iter().all(|g| g.1 == KeyRole::Unknown));
        let _ = std::fs::remove_dir_all(&host.root);
    }

    #[test]
    fn a_spent_budget_or_an_unread_directory_makes_the_search_partial() {
        let host = key_host("keys-budget");
        let small = Budget {
            entries: 5,
            time: Duration::from_secs(20),
        };
        let (keys, _) = search(&host.root, small, &scan(&[41]), &[]);
        assert_eq!(keys.coverage(), Coverage::Partial);

        let unlisted = Scan {
            listed: false,
            ..scan(&[])
        };
        let (keys, _) = search(&host.root, BUDGET, &unlisted, &[]);
        assert_eq!(keys.coverage(), Coverage::Partial);

        // A process whose environment cannot be read.
        std::fs::create_dir_all(host.root.join("proc/42/environ"))
            .unwrap_or_else(|e| panic!("{e}"));
        let (keys, _) = search(&host.root, BUDGET, &scan(&[42]), &[]);
        assert_eq!(keys.coverage(), Coverage::Partial);
        let _ = std::fs::remove_dir_all(&host.root);
    }

    #[test]
    fn a_start_that_is_a_link_is_not_followed_and_says_so() {
        let root = crate::node::security::fixture("keys-linked-start");
        chmod(&root, 0o755);
        write(
            &root,
            "elsewhere/id.json",
            keypair().to_json().as_bytes(),
            0o644,
        );
        write(&root, "etc/hostname", b"node\n", 0o644);
        symlink("elsewhere", root.join("home")).unwrap_or_else(|e| panic!("{e}"));
        let (keys, _) = search(&root, BUDGET, &scan(&[]), &[]);
        assert!(keys.items().is_empty());
        assert_eq!(keys.coverage(), Coverage::Partial);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn nothing_to_read_is_unreadable_and_nothing_found_is_complete() {
        let root = crate::node::security::fixture("keys-empty");
        let (keys, _) = search(&root, BUDGET, &scan(&[]), &[]);
        assert_eq!(keys.coverage(), Coverage::Unreadable);
        write(&root, "etc/hostname", b"node\n", 0o644);
        chmod(&root, 0o755);
        let (keys, places) = search(&root, BUDGET, &scan(&[]), &[]);
        assert_eq!(keys.coverage(), Coverage::Complete);
        assert!(keys.items().is_empty() && places.of(0).is_none());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn access_is_the_narrowest_the_modes_allow() {
        let open = Reach::ALL.through(0o755);
        assert_eq!(open.access(0o644), Access::World);
        assert_eq!(open.access(0o640), Access::Group);
        assert_eq!(open.access(0o600), Access::OwnerOnly);
        let group = open.through(0o750);
        assert_eq!(group.access(0o644), Access::Group);
        assert_eq!(group.access(0o604), Access::OwnerOnly);
        let closed = open.through(0o700);
        assert_eq!(closed.access(0o666), Access::OwnerOnly);
        // Docker's directories let only their group, or others, pass.
        let docker = open.through(0o710).through(0o701);
        assert_eq!(docker.access(0o644), Access::Group);
    }

    #[test]
    fn the_walk_stays_on_its_filesystem_except_into_homes() {
        assert_eq!(descend(false, 0, 1, 1), Some(1));
        assert_eq!(descend(false, 0, 1, 2), None);
        assert_eq!(descend(false, 3, 1, 2), None);
        // /home/<name> may be mounted on its own; below it, the walk stays.
        assert_eq!(descend(true, 0, 1, 2), Some(2));
        assert_eq!(descend(true, 1, 2, 3), None);
    }

    #[test]
    fn counts_are_capped_and_groups_bounded_with_their_places() {
        let mut found = Found::default();
        let key = (
            KeyKind::HistorySecret,
            KeyRole::Unknown,
            KeyLocation::ShellHistory,
            Access::World,
        );
        found.add(
            key,
            usize::try_from(KeyGroup::MAX_COUNT).unwrap_or(0) + 1,
            "/a".to_owned(),
        );
        let (keys, places) = found.finish(Coverage::Complete);
        assert_eq!(keys.items()[0].count, KeyGroup::MAX_COUNT);
        assert_eq!(keys.coverage(), Coverage::Partial);
        assert_eq!(places.of(0).map(|s| s.paths.len()), Some(1));

        let mut found = Found::default();
        let mut all = Vec::new();
        for &kind in KeyKind::ALL {
            for &role in KeyRole::ALL {
                for &location in KeyLocation::ALL {
                    for &access in Access::ALL {
                        all.push((kind, role, location, access));
                    }
                }
            }
        }
        for (index, &key) in all.iter().take(130).enumerate() {
            for n in 0..12 {
                found.add(key, 1, format!("/k/{index}/{n}"));
            }
        }
        let (keys, places) = found.finish(Coverage::Complete);
        assert_eq!(keys.items().len(), 128);
        assert_eq!(keys.coverage(), Coverage::Partial);
        let last = places.of(127).unwrap_or_else(|| panic!("no places"));
        assert_eq!((last.paths.len(), last.more), (10, 2));
        assert_eq!(keys.items()[127].count, 12);
        assert!(places.of(128).is_none());
    }

    #[test]
    fn places_cannot_drive_the_terminal() {
        assert_eq!(
            printable("/tmp/\u{1b}[2Jkey\u{202e}txt.json\n"),
            "/tmp/\\u{1b}[2Jkey\\u{202e}txt.json\\u{a}"
        );
        assert_eq!(printable("a\u{61c}b\u{2028}c"), "a\\u{61c}b\\u{2028}c");
    }

    #[test]
    fn an_identity_given_through_a_link_elsewhere_is_still_the_identity() {
        let root = crate::node::security::fixture("keys-identity-link");
        let identity = keypair();
        // The validator was given a link to a key outside every start, as
        // a setup that switches identities does.
        write(
            &root,
            "mnt/ramdisk/staked.json",
            identity.to_json().as_bytes(),
            0o600,
        );
        write(
            &root,
            "home/sol/backup/staked.json",
            identity.to_json().as_bytes(),
            0o600,
        );
        symlink(
            "../../mnt/ramdisk/staked.json",
            root.join("home/sol/identity.json"),
        )
        .unwrap_or_else(|e| panic!("{e}"));
        for (dir, mode) in [("", 0o755), ("home", 0o755), ("home/sol", 0o750)] {
            chmod(&root.join(dir), mode);
        }
        let given = root.join("home/sol/identity.json");
        let (keys, places) = search(&root, BUDGET, &scan(&[]), &[given]);
        assert_eq!(
            groups(&keys),
            [(
                KeyKind::SolanaKeypair,
                KeyRole::ValidatorIdentity,
                KeyLocation::Home,
                Access::OwnerOnly,
                1
            )]
        );
        // The walk itself followed no link: only the copy it reached counts.
        assert_eq!(
            places.of(0).map(|shown| shown.paths.clone()),
            Some(vec!["/home/sol/backup/staked.json".to_owned()])
        );
        assert_eq!(keys.coverage(), Coverage::Complete);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn unreadable_identities_directories_and_files_make_the_search_partial() {
        let root = crate::node::security::fixture("keys-unreadable");
        chmod(&root, 0o755);
        write(&root, "etc/hostname", b"node\n", 0o644);
        let complete = search(&root, BUDGET, &scan(&[]), &[]).0;
        assert_eq!(complete.coverage(), Coverage::Complete);

        let hidden = root.join("mnt/id.json");
        write(&root, "mnt/id.json", keypair().to_json().as_bytes(), 0o000);
        write(&root, "etc/secret.key", hex_key().as_bytes(), 0o000);
        std::fs::create_dir_all(root.join("etc/private")).unwrap_or_else(|e| panic!("{e}"));
        chmod(&root.join("etc/private"), 0o000);
        // The superuser reads through modes; there is nothing to show then.
        if std::fs::read(&hidden).is_ok() {
            chmod(&root.join("etc/private"), 0o755);
            let _ = std::fs::remove_dir_all(&root);
            return;
        }
        let identity = search(&root, BUDGET, &scan(&[]), std::slice::from_ref(&hidden)).0;
        assert_eq!(identity.coverage(), Coverage::Partial);
        let unread = |root: &Path| search(root, BUDGET, &scan(&[]), &[]).0.coverage();
        assert_eq!(unread(&root), Coverage::Partial);
        chmod(&root.join("etc/private"), 0o755);
        assert_eq!(unread(&root), Coverage::Partial, "the file alone");
        chmod(&root.join("etc/secret.key"), 0o644);
        chmod(&root.join("etc/private"), 0o000);
        assert_eq!(unread(&root), Coverage::Partial, "the directory alone");
        chmod(&root.join("etc/private"), 0o755);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_tree_deeper_than_the_walk_goes_is_partial() {
        let root = crate::node::security::fixture("keys-deep");
        chmod(&root, 0o755);
        let deepest = (0..=MAX_DEPTH).fold(root.join("opt"), |path, _| path.join("d"));
        std::fs::create_dir_all(&deepest).unwrap_or_else(|e| panic!("{e}"));
        let coverage = |root: &Path| search(root, BUDGET, &scan(&[]), &[]).0.coverage();
        assert_eq!(coverage(&root), Coverage::Partial);
        std::fs::remove_dir(&deepest).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(coverage(&root), Coverage::Complete);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn only_directories_and_regular_files_are_opened_to_read() {
        let path = |p: &Path| {
            std::ffi::CString::new(p.as_os_str().as_encoded_bytes())
                .unwrap_or_else(|e| panic!("{e}"))
        };
        // A device, even when a link leads to it.
        let device = open_entry(rustix::fs::CWD, c"/dev/null", true);
        assert!(matches!(device, Ok(Opened::Other)));
        let root = crate::node::security::fixture("keys-open");
        symlink("/dev/null", root.join("null")).unwrap_or_else(|e| panic!("{e}"));
        let followed = open_entry(rustix::fs::CWD, &path(&root.join("null")), true);
        assert!(matches!(followed, Ok(Opened::Other)));
        // A link, when links are not followed.
        write(&root, "real.json", b"[]", 0o644);
        symlink("real.json", root.join("link.json")).unwrap_or_else(|e| panic!("{e}"));
        let link_entry = open_entry(rustix::fs::CWD, &path(&root.join("link.json")), false);
        assert!(match link_entry {
            Ok(Opened::Other) => true,
            Err(e) => link(&e),
            Ok(_) => false,
        });
        let real = open_entry(rustix::fs::CWD, &path(&root.join("real.json")), false);
        assert!(matches!(real, Ok(Opened::File(..))));
        // A pipe is neither opened to read nor waited on, where mkfifo exists.
        let pipe = root.join("pipe");
        if std::process::Command::new("mkfifo")
            .arg(&pipe)
            .status()
            .is_ok_and(|s| s.success())
        {
            assert!(matches!(
                open_entry(rustix::fs::CWD, &path(&pipe), true),
                Ok(Opened::Other)
            ));
        }
        let _ = std::fs::remove_dir_all(&root);
    }
}
