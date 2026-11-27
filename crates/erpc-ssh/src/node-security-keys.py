# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0

# Private keys and secrets left in plain text: key files, seed phrases,
# keystores without encryption, and secrets in environment files, process
# environments and shell histories. The search runs in a child process
# beside the other reads, with its own budget, so an error or a stalled read
# costs only this section. Contents are read into bounded buffers; only
# kinds, classes, counts and the places' paths leave the child. Python
# cannot wipe what it read: it stays in the child's memory until the child
# exits, right after writing its result. BIP39_ENGLISH, the BIP-39 English
# word list, comes before this code in the delivered script.

import errno
import hashlib
import json
import os
import re
import select
import signal
import stat
import threading
import time

KEY_ENTRIES = 200000
KEY_SECONDS = 20
FILE_LIMIT = 64 * 1024
TAIL_LIMIT = 1024 * 1024
CMDLINE_LIMIT = 256 * 1024
MAX_DEPTH = 48
MAX_COUNT = 100000
# Places shown per group, the longest one shown and all of them together,
# in characters, each counted with 3 for its quotes and comma. The encoding
# below is one that JSON never escapes.
PLACES_SHOWN = 10
PLACE_LIMIT = 1024
PLACES_BUDGET = 6144
RESULT_LIMIT = 65536

KINDS = ("solana_keypair", "evm_private_key", "mnemonic", "unencrypted_keystore",
         "env_secret", "process_env_secret", "history_secret")
ROLES = ("validator_identity", "unknown")
LOCATIONS = ("home", "root_home", "etc", "opt", "srv", "var", "tmp", "docker",
             "process_env", "shell_history")
ACCESS = ("owner_only", "group", "world")
# Where the walk starts, the class of place, and whether each directory in
# it is a home that may be a filesystem of its own.
STARTS = ((b"root", "root_home", False), (b"home", "home", True), (b"etc", "etc", False),
          (b"opt", "opt", False), (b"srv", "srv", False),
          (b"var/lib/docker/volumes", "docker", False), (b"var/lib", "var", False),
          (b"tmp", "tmp", False), (b"var/tmp", "tmp", False))
# Docker's image layers, and its volumes, a start of their own.
SKIPPED_PATHS = (b"/var/lib/docker/overlay2", b"/var/lib/docker/volumes")
# Where chains keep their ledgers, snapshots and databases.
CHAIN_DATA = frozenset((b"ledger", b"accounts", b"snapshots", b"rocksdb", b"chaindata",
                        b"geth", b"nodes", b"data"))
SECRET_NAMES = (b"PRIVATE_KEY", b"SECRET_KEY", b"MNEMONIC", b"SEED_PHRASE", b"KEYPAIR",
                b"WALLET_KEY")
# A value that points to a secret kept elsewhere rather than holding it.
REFERENCES = (b"op://", b"keychain:", b"keystore:", b"$", b"/", b"~/", b"./", b"../")
LOCATION_NAMES = (b"_PATH", b"_FILE", b"_DIR")
# ASCII whitespace as Rust's is_ascii_whitespace has it: no vertical tab,
# which bytes.split() and bytes.strip() would also take.
WHITESPACE = b" \t\n\x0c\r"
WORD = re.compile(rb"[^ \t\n\x0c\r]+")
NAME = re.compile(rb"[A-Za-z_][A-Za-z0-9_]*")
NUMBER = re.compile(rb"[0-9]{1,3}")
HEX = re.compile(rb"[0-9A-Fa-f]{64}")
# Each runs in time linear in the line: a run is tried only where it starts.
HEX_RUN = re.compile(rb"(?<![0-9A-Fa-f])[0-9A-Fa-f]{64}(?![0-9A-Fa-f])")
BASE58_RUN = re.compile(
    rb"(?<![1-9A-HJ-NP-Za-km-z])[1-9A-HJ-NP-Za-km-z]{87,88}(?![1-9A-HJ-NP-Za-km-z])")
ASSIGNMENT = re.compile(rb"(?<![A-Za-z0-9_])([A-Za-z0-9_]+)=")
WORDS = frozenset(BIP39_ENGLISH.encode("ascii").split())  # noqa: F821
SAFE = frozenset(range(0x20, 0x7f)) - {0x22, 0x25, 0x5c}
# procfs, sysfs, debugfs, tracefs, securityfs, configfs, pstore, cgroup,
# cgroup2, devpts, fusectl, binfmt_misc and mqueue, by their magic numbers.
KERNEL_FILESYSTEMS = frozenset((0x9fa0, 0x62656572, 0x64626720, 0x74726163, 0x73636673,
                                0x62656570, 0x6165676c, 0x27e0eb, 0x63677270, 0x1cd1,
                                0x65735543, 0x42494e4d, 0x19800202))
VALIDATORS = (b"agave-validator", b"solana-validator")
FIREDANCER = (b"fdctl", b"fddev", b"firedancer")
GONE = (errno.ENOENT, errno.ESRCH)


def keypair(contents):
    """The 64 bytes of a Solana CLI keypair: a JSON array of exactly 64
    integers from 0 to 255, and nothing else."""
    text = contents.strip(WHITESPACE)
    if len(text) < 2 or text[:1] != b"[" or text[-1:] != b"]":
        return None
    parts = text[1:-1].split(b",", 64)
    if len(parts) != 64:
        return None
    values = []
    for part in parts:
        part = part.strip(WHITESPACE)
        if not NUMBER.fullmatch(part) or int(part) > 255:
            return None
        values.append(int(part))
    return bytes(values)


def hex_key(contents):
    text = contents.strip(WHITESPACE)
    if text[:2] in (b"0x", b"0X"):
        text = text[2:]
    return HEX.fullmatch(text) is not None


def key_file_name(name):
    lower = name.lower()
    return not lower.endswith(b".pem") and any(word in lower for word in (b"key", b"private", b"wallet"))


def mnemonic(contents):
    count = 0
    for word in WORD.finditer(contents):
        count += 1
        if count > 24 or word.group() not in WORDS:
            return False
    return count in (12, 15, 18, 21, 24)


def refuse(constant):
    raise ValueError(constant)


def folded(name):
    return name.encode("utf-8").replace(b"_", b"").replace(b"-", b"").lower()


def keystore(contents):
    """A JSON object with a private key field and no crypto object. Python's
    parser builds the values too; only the field names are kept."""
    try:
        names = json.loads(contents.decode("utf-8"), parse_constant=refuse,
                           object_pairs_hook=lambda pairs: [name for name, _ in pairs])
        fields = [folded(name) for name in names]
    except (ValueError, RecursionError, UnicodeError):
        return False
    return b"crypto" not in fields and any(
        field in (b"privatekey", b"privkey", b"secretkey") for field in fields)


def secret_name(name):
    if len(name) < 7:
        return False
    upper = name.upper()
    return not upper.endswith(LOCATION_NAMES) and any(secret in upper for secret in SECRET_NAMES)


def written_out(data, start, end=None):
    """Whether data[start:end] is a secret's value itself: not empty, and not
    a reference to where it is kept. Looked at in place, never copied."""
    end = len(data) if end is None else end
    while start < end and data[start] in WHITESPACE:
        start += 1
    while end > start and data[end - 1] in WHITESPACE:
        end -= 1
    if start < end and data[start] in b"\"'":
        start += 1
    if end > start and data[end - 1] in b"\"'":
        end -= 1
    return start < end and not any(data.startswith(prefix, start, end) for prefix in REFERENCES)


def assigned(data, eq):
    return NAME.fullmatch(data, 0, eq) is not None and secret_name(data[:eq]) and written_out(data, eq + 1)


def env_lines(contents):
    count = 0
    for line in contents.split(b"\n"):
        line = line.strip(WHITESPACE)
        if line.startswith(b"export "):
            line = line[7:].lstrip(WHITESPACE)
        eq = line.find(b"=")
        if eq >= 0:
            name = line[:eq].rstrip(WHITESPACE)
            count += assigned(name + line[eq:], len(name))
    return count


def environ_secrets(environ):
    return sum(assigned(entry, entry.find(b"=")) for entry in environ.split(b"\0") if b"=" in entry)


def assigns_secret(line):
    upper = line.upper()
    if not any(secret in upper for secret in SECRET_NAMES):
        return False
    for word in WORD.finditer(line):
        for name in ASSIGNMENT.finditer(line, word.start(), word.end()):
            if secret_name(name.group(1)) and written_out(line, name.end(), word.end()):
                return True
    return False


def history_lines(history):
    return sum(1 for line in history.split(b"\n")
               if HEX_RUN.search(line) or BASE58_RUN.search(line) or assigns_secret(line))


def classify(name, contents):
    """(kind, count, digest of a keypair) for the file `name` holding
    `contents`, or None."""
    if name.endswith(b".env") or name == b"environment":
        count = env_lines(contents)
        return ("env_secret", count, None) if count else None
    first = contents.lstrip(WHITESPACE)[:1]
    pair = keypair(contents) if first == b"[" else None
    if pair is not None:
        return "solana_keypair", 1, hashlib.sha256(pair).digest()
    if first == b"{" and keystore(contents):
        return "unencrypted_keystore", 1, None
    if key_file_name(name) and hex_key(contents):
        return "evm_private_key", 1, None
    if mnemonic(contents):
        return "mnemonic", 1, None
    return None


def place(path):
    """A path as printable ASCII that JSON leaves as it is: every other byte,
    and %, " and backslash, as %HH."""
    return "".join(chr(byte) if byte in SAFE else "%%%02X" % byte for byte in path)


def access_of(reach, gid, mode):
    """Who can read a file from permission bits and groups alone, through the
    directories above it: an account that owns one of them, and access
    control lists, are not considered."""
    if mode & 0o004 and all(dir_mode & 0o001 for _, dir_mode in reach):
        return "world"
    if mode & 0o040 and all(dir_mode & (0o010 if dir_gid == gid else 0o001)
                            for dir_gid, dir_mode in reach):
        return "group"
    return "owner_only"


def descend(homes, depth, start_dev, dev):
    """The device a directory below is held to, or None on another
    filesystem. A home directly in /home may be one of its own."""
    if homes and depth == 0:
        return dev
    return start_dev if dev == start_dev else None


def hold(name, dir_fd=None, follow=False):
    """A path-only descriptor and its status: no device is opened and no pipe
    waited on, so the entry's kind, owner and size are known first."""
    fd = os.open(name, os.O_PATH | os.O_CLOEXEC | (0 if follow else os.O_NOFOLLOW), dir_fd=dir_fd)
    try:
        return fd, os.fstat(fd)
    except BaseException:
        os.close(fd)
        raise


def reopen(fd, directory):
    """The entry held, opened to read through its own link in /proc, which
    names this very file, without updating its access time where allowed."""
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOCTTY | (os.O_DIRECTORY if directory else os.O_NONBLOCK)
    link = "/proc/self/fd/%d" % fd
    try:
        return os.open(link, flags | os.O_NOATIME)
    except PermissionError as error:
        if error.errno != errno.EPERM:
            raise
        return os.open(link, flags)


def read(fd, limit):
    chunks = []
    left = limit
    while left > 0:
        chunk = os.read(fd, min(left, 1 << 20))
        if not chunk:
            break
        chunks.append(chunk)
        left -= len(chunk)
    return b"".join(chunks)


def read_file(path, limit):
    with open(path, "rb", buffering=0) as file:
        return read(file.fileno(), limit)


def kernel_file(fd):
    """Whether the held entry is on a kernel filesystem, or that cannot be
    told: fstatfs's f_type, through ctypes, where its first 32 bits are the
    low ones."""
    try:
        import ctypes
        import sys
        status = ctypes.create_string_buffer(512)
        if sys.byteorder != "little" or ctypes.CDLL(None, use_errno=True).fstatfs(fd, status):
            return True
        return ctypes.c_uint32.from_buffer(status).value in KERNEL_FILESYSTEMS
    except Exception:
        return True


def program_of(process):
    """The program of a process: its executable's name, or the kernel's
    short name for it when the executable cannot be read."""
    try:
        name = os.path.basename(os.readlink(process + b"/exe"))
        return name[:-10] if name.endswith(b" (deleted)") else name
    except OSError:
        try:
            return read_file(process + b"/comm", 4096).rstrip(b"\n")
        except OSError:
            return None


def known(name, programs):
    # The kernel keeps the first 15 bytes of a program's name.
    return name is not None and any(
        name == program or (len(name) == 15 and program.startswith(name)) for program in programs)


def identity_argument(cmdline):
    """The --identity a validator was given, as its last one says."""
    arguments = [argument for argument in cmdline.split(b"\0")[1:] if argument]
    identity = None
    index = 0
    while index < len(arguments):
        flag, inline = arguments[index], None
        index += 1
        if flag.startswith(b"--") and b"=" in flag:
            flag, inline = flag.split(b"=", 1)
        if flag in (b"--identity", b"-i"):
            if inline is None and index < len(arguments):
                inline = arguments[index]
                index += 1
            identity = inline
    return identity


def process_uid(process):
    """The effective user id from a process's status."""
    try:
        for line in read_file(process + b"/status", 64 * 1024).split(b"\n"):
            if line.startswith(b"Uid:"):
                return int(line.split()[2])
    except (OSError, ValueError, IndexError):
        pass
    return None


class KeySearch:
    def __init__(self, root, deadline, entries=KEY_ENTRIES):
        self.root = os.fsencode(root).rstrip(b"/")
        self.deadline = deadline
        self.entries = entries
        self.seen = 0
        self.cut = False
        self.partial = False
        self.opened = 0
        self.identities = set()
        self.groups = {}
        self.budget = PLACES_BUDGET
        self.lock = threading.Lock()

    def spend(self):
        """Counts one entry; whether the budget is spent."""
        self.seen += 1
        if self.seen > self.entries or time.monotonic() > self.deadline:
            self.cut = self.partial = True
        return self.cut

    def add(self, key, count, path):
        if not count:
            return
        shown = place(path)
        with self.lock:
            group = self.groups.setdefault(key, [0, [], 0])
            group[0] += count
            cost = len(shown) + 3
            if len(group[1]) < PLACES_SHOWN and len(shown) <= PLACE_LIMIT and cost <= self.budget:
                group[1].append(shown)
                self.budget -= cost
            else:
                group[2] += 1

    def result(self, failed=False):
        with self.lock:
            partial = self.partial or failed or not self.opened
            if not self.opened and not self.groups:
                return {"coverage": "unreadable", "groups": []}
            groups = []
            order = lambda item: (KINDS.index(item[0][0]), ROLES.index(item[0][1]),
                                  LOCATIONS.index(item[0][2]), ACCESS.index(item[0][3]))
            for (kind, role, location, access), (total, places, more) in sorted(self.groups.items(), key=order):
                count = min(total, MAX_COUNT)
                partial |= total > MAX_COUNT
                groups.append({"kind": kind, "role": role, "location": location, "access": access,
                               "count": count, "places": list(places),
                               "more": min(more, count - len(places))})
            return {"coverage": "partial" if partial else "complete", "groups": groups}

    def run(self):
        processes = self.processes()
        self.find_identities(processes)
        self.environs(processes)
        for start, location, homes in STARTS:
            if self.cut:
                break
            self.walk(start, location, homes)

    def processes(self):
        try:
            return sorted(int(name) for name in os.listdir(self.root + b"/proc")
                          if name.isdigit() and name.isascii())
        except OSError:
            self.partial = True
            return []

    def find_identities(self, processes):
        """The identity files running validators were given. Unlike the walk,
        this reads a file where the validator does, through links and on any
        filesystem, and only a regular file of 1 byte to FILE_LIMIT, not on a
        kernel filesystem, owned by the validator's user unless it runs as
        root. A validator whose identity file cannot be told, Firedancer
        among them, makes the search partial."""
        for pid in processes:
            process = self.root + b"/proc/%d" % pid
            program = program_of(process)
            if known(program, FIREDANCER):
                self.partial = True
                continue
            if not known(program, VALIDATORS):
                continue
            try:
                identity = identity_argument(read_file(process + b"/cmdline", CMDLINE_LIMIT))
            except OSError:
                identity = None
            if identity is not None and not identity.startswith(b"/"):
                try:
                    identity = os.readlink(process + b"/cwd").rstrip(b"/") + b"/" + identity
                except OSError:
                    identity = None
            if identity is None:
                self.partial = True
                continue
            try:
                if stat.S_ISREG(os.stat(self.root + identity).st_mode):
                    self.read_identity(process, self.root + identity)
            except FileNotFoundError:
                pass
            except OSError:
                self.partial = True

    def read_identity(self, process, path):
        uid = process_uid(process)
        if uid is None:
            # The process ended, or its status cannot be read.
            self.partial |= os.path.exists(process)
            return
        try:
            fd, status = hold(path, follow=True)
        except OSError as error:
            self.partial |= error.errno not in GONE
            return
        try:
            if (not stat.S_ISREG(status.st_mode) or not (uid == 0 or status.st_uid == uid)
                    or not 1 <= status.st_size <= FILE_LIMIT or kernel_file(fd)):
                self.partial = True
                return
            opened = reopen(fd, False)
            try:
                contents = read(opened, status.st_size)
            finally:
                os.close(opened)
        except OSError as error:
            self.partial |= error.errno not in GONE
            return
        finally:
            os.close(fd)
        pair = keypair(contents)
        if pair is not None:
            self.identities.add(hashlib.sha256(pair).digest())

    def environs(self, processes):
        for pid in processes:
            if self.spend():
                return
            path = b"/proc/%d/environ" % pid
            try:
                environ = read_file(self.root + path, TAIL_LIMIT + 1)
            except OSError as error:
                self.partial |= error.errno not in GONE
                continue
            if len(environ) > TAIL_LIMIT:
                self.partial = True
                continue
            self.add(("process_env_secret", "unknown", "process_env", "owner_only"),
                     environ_secrets(environ), path)

    def open_start(self, start):
        """The start directory, reached from the root one name at a time
        without following a link, and the groups and modes on the way."""
        try:
            fd, status = hold(self.root or b"/", follow=True)
        except OSError:
            self.partial = True
            return None
        reach = [(status.st_gid, status.st_mode)]
        names = start.split(b"/")
        try:
            for depth, name in enumerate(names, 1):
                child, status = hold(name, fd)
                os.close(fd)
                fd = child
                if stat.S_ISLNK(status.st_mode):
                    # A start that is a link leads where this search does not go.
                    self.partial = True
                    return None
                if not stat.S_ISDIR(status.st_mode):
                    # No start, unless something else stands on its way.
                    self.partial |= depth < len(names)
                    return None
                reach.append((status.st_gid, status.st_mode))
            directory = reopen(fd, True)
        except OSError as error:
            self.partial |= error.errno != errno.ENOENT
            return None
        finally:
            os.close(fd)
        try:
            entries = os.scandir(directory)
        except OSError:
            os.close(directory)
            self.partial = True
            return None
        self.opened += 1
        return [directory, entries, b"/" + start, status.st_dev, reach, 0]

    def walk(self, start, location, homes):
        first = self.open_start(start)
        frames = [first] if first else []
        try:
            while frames:
                directory, entries, path, dev, reach, depth = frames[-1]
                try:
                    entry = next(entries, None)
                except OSError:
                    entry = None
                    self.partial = True
                if entry is None:
                    entries.close()
                    os.close(directory)
                    frames.pop()
                    continue
                if self.spend():
                    return
                name = os.fsencode(entry.name)
                child = path + b"/" + name
                try:
                    is_dir = entry.is_dir(follow_symlinks=False)
                    if not is_dir and not entry.is_file(follow_symlinks=False):
                        # A link, pipe, socket or device: never opened.
                        continue
                except OSError:
                    is_dir = False
                if is_dir and self.skipped(child, name):
                    continue
                try:
                    fd, status = hold(name, directory)
                except OSError as error:
                    self.partial |= error.errno not in GONE
                    continue
                try:
                    if stat.S_ISREG(status.st_mode):
                        self.file(child, name, fd, status, reach, location)
                    elif stat.S_ISDIR(status.st_mode) and not self.skipped(child, name):
                        # The filesystem and the depth are checked before
                        # the directory is opened to read.
                        below = descend(homes, depth, dev, status.st_dev)
                        if below is None:
                            continue
                        if depth + 1 > MAX_DEPTH:
                            self.partial = True
                            continue
                        opened = reopen(fd, True)
                        try:
                            listing = os.scandir(opened)
                        except BaseException:
                            os.close(opened)
                            raise
                        frames.append([opened, listing, child, below,
                                       reach + [(status.st_gid, status.st_mode)], depth + 1])
                except OSError:
                    self.partial = True
                finally:
                    os.close(fd)
        finally:
            for directory, entries, _, _, _, _ in frames:
                entries.close()
                os.close(directory)

    def skipped(self, path, name):
        return name in CHAIN_DATA or path in SKIPPED_PATHS

    def file(self, path, name, fd, status, reach, location):
        history = name in (b".bash_history", b".zsh_history") or (
            name == b"fish_history" and path.endswith(b"/.local/share/fish/fish_history"))
        size = status.st_size
        if size == 0 or (not history and size > FILE_LIMIT):
            return
        access = access_of(reach, status.st_gid, status.st_mode)
        opened = reopen(fd, False)
        try:
            if history:
                skip = max(0, size - TAIL_LIMIT)
                if skip:
                    os.lseek(opened, skip, os.SEEK_SET)
                tail = read(opened, TAIL_LIMIT)
                if skip:
                    # The first line of a tail may be the end of one cut in two.
                    tail = tail[tail.find(b"\n") + 1:] if b"\n" in tail else b""
                found = "history_secret", history_lines(tail), None
                location = "shell_history"
            else:
                contents = read(opened, FILE_LIMIT + 1)
                # A file that grew past the limit since it was listed is skipped.
                found = classify(name, contents) if len(contents) <= FILE_LIMIT else None
        finally:
            os.close(opened)
        if found:
            kind, count, digest = found
            role = "validator_identity" if digest in self.identities else "unknown"
            self.add((kind, role, location, access), count, path)


UNREADABLE_KEYS = {"coverage": "unreadable", "groups": []}


def search_child(write_end, search):
    """Runs in the child: writes one line of JSON, from the search when it
    ends or, past its deadline, from what it found so far, then exits."""
    sent = threading.Lock()

    def send(failed):
        sent.acquire()
        data = json.dumps(search.result(failed), separators=(",", ":")).encode("ascii") + b"\n"
        while data:
            data = data[os.write(write_end, data):]
        os._exit(0)

    def watch():
        time.sleep(max(0, search.deadline - time.monotonic()) + 1)
        send(True)

    threading.Thread(target=watch, daemon=True).start()
    try:
        search.run()
    except Exception:
        send(True)
    send(False)


def start_key_search(root="/", seconds=KEY_SECONDS):
    deadline = time.monotonic() + seconds
    read_end, write_end = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(read_end)
            # Nothing the child prints can reach the SSH channel, and a child
            # that never ends does not hold it open.
            null = os.open(os.devnull, os.O_RDWR)
            for target in (0, 1, 2):
                os.dup2(null, target)
            search_child(write_end, KeySearch(root, deadline))
        finally:
            os._exit(0)
    os.close(write_end)
    return pid, read_end, deadline


def finish_key_search(pending):
    """The child's result, or unreadable keys when it gives none in time."""
    pid, read_end, deadline = pending
    data = b""
    until = max(deadline + 2, time.monotonic() + 1)
    try:
        while not data.endswith(b"\n") and len(data) <= RESULT_LIMIT:
            if not select.select([read_end], [], [], max(0, until - time.monotonic()))[0]:
                break
            chunk = os.read(read_end, RESULT_LIMIT)
            if not chunk:
                break
            data += chunk
    finally:
        os.close(read_end)
        try:
            if os.waitpid(pid, os.WNOHANG) == (0, 0):
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, os.WNOHANG)
        except OSError:
            pass
    try:
        result = json.loads(data.decode("ascii"))
    except ValueError:
        return UNREADABLE_KEYS
    if (len(data) > RESULT_LIMIT or not isinstance(result, dict) or not isinstance(result.get("groups"), list)
            or result.get("coverage") not in ("complete", "partial", "unreadable")):
        return UNREADABLE_KEYS
    return result
