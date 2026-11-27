# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0

import ipaddress
import json
import os
import re
import selectors
import shlex
import stat
import subprocess
import sys
import time

TABLE_LIMIT = 8 * 1024 * 1024


def binding(path, width):
    with open(path, "rb") as table:
        data = table.read(TABLE_LIMIT + 1)
    if len(data) > TABLE_LIMIT or not data.endswith(b"\n"):
        raise ValueError()

    rows = iter(data.splitlines())
    header = next(rows).split()
    if len(header) != 12 or header[:2] != [b"sl", b"local_address"]:
        raise ValueError()
    if header[2] not in (b"rem_address", b"remote_address") or header[3:] != (
        b"st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode".split()
    ):
        raise ValueError()

    observed = 0
    for row in rows:
        fields = row.split()
        if len(fields) < 10 or not fields[0].endswith(b":"):
            raise ValueError()
        address, port = fields[1].split(b":")
        state = fields[3]
        if len(address) != width or len(port) != 4 or len(state) != 2:
            raise ValueError()
        octets = b"".join(
            int(address[start : start + 8], 16).to_bytes(4, sys.byteorder)
            for start in range(0, width, 8)
        )
        ip = ipaddress.ip_address(octets)
        if int(fields[0][:-1]) < 0 or int(fields[9]) < 0:
            raise ValueError()
        if int(port, 16) != 8899 or int(state, 16) != 10:
            continue
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        observed = max(observed, 1 if ip.is_loopback else 2)
    return observed


def listeners():
    try:
        observed = max(binding("/proc/net/tcp", 8), binding("/proc/net/tcp6", 32))
        return ("no_listener", "loopback_binding", "review_binding")[observed]
    except (OSError, StopIteration, ValueError, OverflowError):
        return "inconclusive"


PORT_LIMIT = 128
PID_LIMIT = 64
UNIT_LIMIT = 16
PATH_LIMIT = 64
SCOPES = ("wildcard", "interface", "loopback")
PROTOCOLS = ("tcp", "udp")
PROCESS_CATEGORY = {
    "sshd": "ssh", "sshd-session": "ssh",
    "nginx": "web", "apache2": "web", "httpd": "web", "caddy": "web",
    "redis-server": "redis", "redis": "redis",
    "valkey-server": "valkey",
    "postgres": "postgresql", "postmaster": "postgresql",
    "mysqld": "mysql", "mariadbd": "mysql",
    "systemd-resolve": "dns", "dnsmasq": "dns", "named": "dns", "unbound": "dns",
    "chronyd": "time_sync", "ntpd": "time_sync",
    "dockerd": "container", "docker-proxy": "container", "containerd": "container",
    "agave-validator": "solana", "solana-validato": "solana", "firedancer": "solana",
    "erpc-worker": "erpc_worker", "erpc-worker-age": "erpc_worker",
}
FIXED_UNITS = (
    "ssh.service", "sshd.service", "redis-server.service", "valkey-server.service",
    "postgresql.service", "mariadb.service", "nginx.service", "apache2.service",
    "caddy.service", "docker.service", "fail2ban.service",
)
ERPC_UNIT = re.compile(r"erpc-(?:worker|waf|backup)-[a-z0-9-]{1,64}\.service\Z")
PROCESS = re.compile(rb'\("([^"\\]{1,40})",pid=([0-9]{1,10}),fd=[0-9]{1,10}\)')


DENIED = object()
NFT_DENIED = (b"Operation not permitted (you must be root)",
              b"cache initialization failed: Operation not permitted",
              b"Could not receive more data: Operation not permitted")
FAIL2BAN_DENIED = (b"Permission denied to socket:",)
CONTROL_READS = {
    "ruleset": (["/usr/sbin/nft", "-j", "list", "ruleset"], NFT_DENIED, 1 << 19),
    "sshd_jail": (["/usr/bin/fail2ban-client", "status", "sshd"], FAIL2BAN_DENIED, 8192),
    "jail_list": (["/usr/bin/fail2ban-client", "status"], FAIL2BAN_DENIED, 8192),
}


def capture(argv, limit=65536, seconds=3, denial_markers=()):
    """Run a fixed local read with bounded time and output."""
    try:
        process = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE if denial_markers else subprocess.DEVNULL,
            env={"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin", "SYSTEMD_PAGER": "cat"},
        )
    except OSError:
        return None, False
    deadline = time.monotonic() + seconds
    data = bytearray()
    diagnostics = bytearray()
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, (data, limit))
            if process.stderr is not None:
                selector.register(process.stderr, selectors.EVENT_READ, (diagnostics, 4096))
            while selector.get_map():
                events = selector.select(max(0, deadline - time.monotonic()))
                if not events:
                    return bytes(data), True
                for stream, _ in events:
                    buffer, maximum = stream.data
                    block = os.read(stream.fd, min(65536, maximum + 1 - len(buffer)))
                    if not block:
                        selector.unregister(stream.fd)
                        continue
                    buffer.extend(block)
                    if len(buffer) > maximum or time.monotonic() >= deadline:
                        return bytes(data[:limit]), True
        try:
            status = process.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            return bytes(data), True
        if status == 0:
            return bytes(data), False
        if any(marker in diagnostics or marker in data for marker in denial_markers):
            return DENIED, False
        return None, False
    except OSError:
        return None, False
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()


def control_read(operation):
    # The complete sudo allowlist. No shell, probes, passwords, or caller arguments.
    argv, denial_markers, limit = CONTROL_READS[operation]
    data, truncated = capture(argv, limit=limit, denial_markers=denial_markers)
    if data is DENIED and not truncated:
        return capture(["/usr/bin/sudo", "-n", "--"] + argv, limit=limit)
    return data, truncated


def local_socket(value):
    host, port = value.decode("ascii").rsplit(":", 1)
    if not port.isascii() or not port.isdecimal() or not 0 <= int(port) <= 65535:
        if port == "*":
            return None
        raise ValueError()
    number = int(port)
    if number == 0:
        return None
    host = host.strip("[]").split("%", 1)[0]
    if host == "*":
        return "wildcard", number
    ip = ipaddress.ip_address(host)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ("wildcard" if ip.is_unspecified else "loopback" if ip.is_loopback else "interface"), number


def socket_report(data, input_truncated):
    observed = {protocol: {scope: {} for scope in SCOPES} for protocol in PROTOCOLS}
    pids = set()
    incomplete = input_truncated
    if data is not None:
        if data and not data.endswith(b"\n"):
            incomplete = True
            data = data[:data.rfind(b"\n") + 1]
        for line in data.splitlines():
            fields = line.split(maxsplit=6)
            if len(fields) < 6 or fields[0] not in (b"tcp", b"udp"):
                incomplete = True
                continue
            if fields[0] == b"tcp" and fields[1] != b"LISTEN":
                continue
            try:
                endpoint = local_socket(fields[4])
            except (UnicodeError, ValueError):
                incomplete = True
                continue
            if endpoint is None:
                continue
            scope, port = endpoint
            processes = PROCESS.findall(fields[6]) if len(fields) == 7 else []
            categories = {
                PROCESS_CATEGORY.get(name.decode("ascii", "replace"), "unclassified")
                for name, _ in processes
            } or {"unknown"}
            by_port = observed[fields[0].decode("ascii")][scope]
            by_port.setdefault(port, set()).update(categories)
            for _, pid in processes:
                if len(pids) <= PID_LIMIT:
                    pids.add(int(pid))
    total = sum(len(ports) for scopes in observed.values() for ports in scopes.values())
    left = PORT_LIMIT
    report = {"truncated": input_truncated or total > PORT_LIMIT}
    for protocol, scopes in observed.items():
        groups = {"coverage": "unknown" if data is None else "partial" if incomplete else "complete"}
        for scope, ports in scopes.items():
            group = [{"port": port, "services": sorted(categories)}
                     for port, categories in sorted(ports.items())[:left]]
            left -= len(group)
            groups[scope] = group
        report[protocol] = groups
    return report, pids


def filter_evidence(data, truncated):
    evidence = {"ipv4": "unknown", "ipv6": "unknown", "truncated": truncated}
    if data is None or truncated:
        return "not_observed", evidence
    try:
        entries = json.loads(data)["nftables"]
        if not isinstance(entries, list) or any(not isinstance(entry, dict) for entry in entries):
            raise ValueError()
        tables = any("table" in entry for entry in entries)
        hooks = {}
        for entry in entries:
            chain = entry.get("chain")
            if (
                isinstance(chain, dict) and chain.get("type") == "filter" and chain.get("hook") == "input"
                and chain.get("family") in ("inet", "ip", "ip6")
                and all(isinstance(chain.get(name), str) for name in ("name", "table"))
            ):
                hooks[(chain["family"], chain["table"], chain["name"])] = (
                    3 if chain.get("policy") == "drop" else 1
                )
        for entry in entries:
            rule = entry.get("rule")
            if isinstance(rule, dict) and all(isinstance(rule.get(name), str) for name in ("family", "table", "chain")):
                identity = (rule["family"], rule["table"], rule["chain"])
                expressions = rule.get("expr")
                if identity in hooks and isinstance(expressions, list) and any(
                    isinstance(expr, dict) and ("drop" in expr or "reject" in expr)
                    for expr in expressions
                ):
                    hooks[identity] = max(hooks[identity], 2)
        states = ("no_input_filter_hook", "input_filter_hook", "configured_drop_or_reject_rule", "input_default_drop")
        for family, native in (("ipv4", "ip"), ("ipv6", "ip6")):
            evidence[family] = states[max((value for key, value in hooks.items() if key[0] in (native, "inet")), default=0)]
        return ("tables_present" if tables else "no_tables_observed"), evidence
    except (ValueError, TypeError, KeyError, RecursionError):
        return "not_observed", evidence


def ssh_settings(data):
    report = {"password": "unknown", "keyboard_interactive": "unknown"}
    if data is None:
        return report
    wanted = {b"passwordauthentication": "password", b"kbdinteractiveauthentication": "keyboard_interactive"}
    values = {key: [] for key in wanted}
    for line in data.splitlines():
        pair = line.split()
        if len(pair) == 2 and pair[0] in values:
            values[pair[0]].append(pair[1])
    for key, seen in values.items():
        if seen in ([b"yes"], [b"no"]):
            report[wanted[key]] = "enabled" if seen == [b"yes"] else "disabled"
    return report


def effective_ssh_settings():
    user = os.environ.get("USER", "")
    connection = os.environ.get("SSH_CONNECTION", "").split()
    if len(connection) != 4 or not re.fullmatch("[a-zA-Z0-9_.-]{1,32}", user):
        return ssh_settings(None)
    try:
        source, local = (ipaddress.ip_address(connection[index]) for index in (0, 2))
        port = int(connection[3])
        if not 1 <= port <= 65535:
            return ssh_settings(None)
    except ValueError:
        return ssh_settings(None)
    # Older OpenSSH needs -T to accept -C. The accompanying -G takes the
    # config-dump exit before host keys are loaded. We never fall back to -T
    # alone. A numeric source avoids name lookups.
    data, truncated = capture(["/usr/sbin/sshd", "-T", "-G", "-C",
                               f"user={user},addr={source},host={source},laddr={local},lport={port}"])
    if truncated or data is None or b"usedns no" not in data.splitlines():
        return ssh_settings(None)
    return ssh_settings(data)


def sshd_jail():
    data, truncated = control_read("sshd_jail")
    if not truncated and data is not None and b"Status for the jail: sshd" in data.splitlines():
        return "sshd_jail_observed"
    data, truncated = control_read("jail_list")
    if not truncated and data is not None:
        counts = re.findall(rb"Number of jail:[ \t]*([0-9]{1,5})(?:\r?\n|$)", data)
        matches = re.findall(rb"Jail list:[ \t]*([^\r\n]*)", data)
        if len(matches) == len(counts) == 1:
            names = [name.strip() for name in matches[0].split(b",") if name.strip()]
            if len(names) == int(counts[0]) and b"sshd" not in names:
                return "sshd_jail_not_listed"
    return "unknown"


def unit_names(pids):
    units = set(FIXED_UNITS)
    for pid in sorted(pids)[:PID_LIMIT]:
        try:
            with open(f"/proc/{pid}/cgroup", "rb") as cgroup:
                data = cgroup.read(4097)
            if len(data) > 4096:
                continue
            for line in data.decode("ascii").splitlines():
                unit = line.rsplit("/", 1)[-1]
                if ERPC_UNIT.fullmatch(unit):
                    units.add(unit)
        except (OSError, UnicodeError):
            continue
    return sorted(units)[:UNIT_LIMIT], len(units) > UNIT_LIMIT or len(pids) > PID_LIMIT


def property_references():
    return {"environment_files": set(), "service_env": set(),
            "as_is_credentials": set(), "encrypted_credentials": set()}


def parse_properties(data):
    """Only the three requested path-valued service properties."""
    rows = data.decode("utf-8").splitlines()
    if len(rows) != 3:
        raise ValueError()
    result = property_references()
    for index, (line, signature) in enumerate(zip(rows, ("a(sb)", "a(ss)", "a(ss)"))):
        fields = shlex.split(line)
        if len(fields) < 2 or fields[0] != signature or int(fields[1]) * 2 != len(fields) - 2:
            raise ValueError()
        for left, right in zip(fields[2::2], fields[3::2]):
            if index == 0 and right not in ("true", "false"):
                raise ValueError()
            if index == 0:
                result["environment_files"].add(left)
                if os.path.basename(left) == ".env":
                    result["service_env"].add(left)
            else:
                kind = "as_is_credentials" if index == 1 else "encrypted_credentials"
                result[kind].add(right)
    return result


def file_modes(paths):
    counts = {"owner_only": 0, "group_or_other_access": 0, "unknown": 0}
    for path in paths:
        # A credential ID, pattern, socket or symlink is not a file mode
        # observation. No dereferencing, resolution or directory listing.
        if not path.startswith("/") or any(char in path for char in ("*", "?", "\\", "[", "\0")):
            counts["unknown"] += 1
            continue
        try:
            mode = os.lstat(path).st_mode
            if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                counts["unknown"] += 1
            elif mode & 0o077:
                counts["group_or_other_access"] += 1
            else:
                counts["owner_only"] += 1
        except OSError:
            counts["unknown"] += 1
    return counts


def metadata_policy(pids):
    units, truncated = unit_names(pids)
    properties = property_references()
    service = "org.freedesktop.systemd1"
    base = ["/usr/bin/busctl", "--system", "--auto-start=no", "--allow-interactive-authorization=no"]
    units_with_evidence = 0
    for unit in units:
        obj, capped = capture(base + ["call", service, "/org/freedesktop/systemd1",
                                      service + ".Manager", "GetUnit", "s", unit], limit=4096, seconds=1)
        truncated |= capped
        if obj is None or capped:
            continue
        match = re.fullmatch(rb'o "(/org/freedesktop/systemd1/unit/[a-zA-Z0-9_]+)"\n', obj)
        if match is None:
            continue
        data, capped = capture(base + ["get-property", service, match[1].decode("ascii"),
                                       service + ".Service", "EnvironmentFiles", "LoadCredential",
                                       "LoadCredentialEncrypted"], limit=16384, seconds=1)
        truncated |= capped
        if data is None or capped:
            continue
        try:
            discovered = parse_properties(data)
        except (ValueError, UnicodeError):
            continue
        units_with_evidence += 1
        for group in properties:
            properties[group].update(discovered[group])
    report = {"coverage": "observed" if units_with_evidence else "unknown",
              "units_with_evidence": units_with_evidence, "truncated": truncated}
    as_is = properties["as_is_credentials"]
    encrypted = properties["encrypted_credentials"]
    report["credential_declarations"] = {
        "as_is": min(len(as_is), PATH_LIMIT) if units_with_evidence else None,
        "encrypted": min(len(encrypted), PATH_LIMIT) if units_with_evidence else None,
    }
    for group, paths in (
        ("environment_files", properties["environment_files"]),
        ("service_env", properties["service_env"]),
        ("credential_sources", as_is | encrypted),
    ):
        if len(paths) > PATH_LIMIT:
            report["truncated"] = True
        report[group] = file_modes(sorted(paths)[:PATH_LIMIT])
    return report


def report_linux():
    sockets, capped = capture(["/usr/bin/ss", "-H", "-O", "-a", "-t", "-u", "-n", "-p"], limit=1 << 20)
    ports, pids = socket_report(sockets, capped)
    nft, nft_capped = control_read("ruleset")
    nftables, firewall = filter_evidence(nft, nft_capped)
    if nftables == "not_observed":
        tables, tables_capped = capture(["/usr/sbin/nft", "list", "tables"])
        firewall["truncated"] |= tables_capped
        if tables is not None and not tables_capped:
            nftables = "tables_present" if tables.strip() else "no_tables_observed"
    return {
        "listeners": listeners(), "nftables": nftables, "ports": ports,
        "ssh": effective_ssh_settings(), "firewall": firewall, "fail2ban": sshd_jail(),
        "metadata": metadata_policy(pids),
    }


if __name__ == "__main__":
    if sys.platform == "linux":
        report = report_linux()
        updates = globals().get("security_update_summary")
        if updates is not None:
            report["updates"] = updates()
        print(json.dumps(report, separators=(",", ":")))
    else:
        print(json.dumps({"listeners": "inconclusive", "nftables": "not_observed"}))
