#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Read-only L1 transport. Credentials enter through systemd's credential file.

No caller-selected destinations, forwarded headers, redirects, environment
proxies, URL logs, or transport exceptions leave this process. Each connection
resolves and validates all answers, then connects to an already-checked numeric
address while retaining the configured hostname for TLS certificate validation.
"""

import concurrent.futures
import http.client
import http.server
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import socket
import ssl
import sys
import threading
import time
from urllib.parse import urlsplit

MAX_REQUEST = 4 * 1024 * 1024
MAX_RESPONSE = 128 * 1024 * 1024
TIMEOUT = 30
IDENTITY_TTL = 60
L1 = {
    # go-ethereum params/config.go and eth-clients/{mainnet,sepolia} metadata.
    "mainnet": {
        "chain": "0x1",
        "block": "0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
        "genesis_time": "1606824023",
        "genesis_validators_root": "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95",
        "genesis_fork_version": "0x00000000",
    },
    "sepolia": {
        "chain": "0xaa36a7",
        "block": "0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9",
        "genesis_time": "1655733600",
        "genesis_validators_root": "0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078",
        "genesis_fork_version": "0x90000069",
    },
}
# No engine, admin, debug or transaction-submission API is forwarded. Basic
# provider mode uses individual transaction receipts when block receipts fail.
METHODS = frozenset({
    "eth_chainId", "eth_blockNumber", "eth_getBlockByHash", "eth_getBlockByNumber",
    "eth_getTransactionReceipt", "eth_getBlockReceipts", "eth_getProof",
    "eth_getLogs", "eth_getTransactionByHash", "eth_call", "eth_getCode",
    "eth_getStorageAt", "eth_getBalance", "eth_getTransactionCount",
    # Nitro calldata lookup and historical L1 block-body completion.
    "eth_getTransactionByBlockHashAndIndex", "eth_getUncleByBlockHashAndIndex",
})


class Rejected(Exception):
    """A deliberately context-free error safe to print or return."""

    def __init__(self):
        super().__init__("L1 upstream request rejected or unavailable")


class MissingBeaconResource(Rejected):
    """A missing blob resource, without retaining any provider diagnostics."""


def fail():
    raise Rejected() from None


def strict_json(raw):
    def finite(value):
        number = float(value)
        if not math.isfinite(number):
            fail()
        return number
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                fail()
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: fail(), parse_float=finite)
    except (ValueError, TypeError, RecursionError):
        fail()


def printable(value):
    return isinstance(value, str) and all(32 <= ord(c) < 127 for c in value)


# Explicit conservative policy from the IANA special-purpose registries read
# 2026-10-26. Do not use is_global/is_private: their registry tables vary by
# Python release/backport (notably 192.0.0.8 and 192.88.99.2 on older hosts).
# All special-use assignments are excluded, including globally reachable
# service anycasts. IPv6 is additionally restricted to the 2000::/3 envelope.
SPECIAL_V4 = tuple(ipaddress.IPv4Network(value) for value in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.31.196.0/24", "192.52.193.0/24", "192.88.99.0/24", "192.168.0.0/16",
    "192.175.48.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "224.0.0.0/4", "240.0.0.0/4",
))
GLOBAL_UNICAST_V6 = ipaddress.IPv6Network("2000::/3")
SPECIAL_GLOBAL_V6 = tuple(ipaddress.IPv6Network(value) for value in (
    "2001::/23", "2001:db8::/32", "2002::/16", "2620:4f:8000::/48",
    "3ffe::/16", "3fff::/20",
))
LOOPBACK_V4 = ipaddress.IPv4Network("127.0.0.0/8")
LOOPBACK_V6 = ipaddress.IPv6Network("::1/128")


def address_allowed(value, loopback):
    if not isinstance(value, str) or type(loopback) is not bool or "%" in value:
        return False
    try:
        ip = ipaddress.ip_address(value)
        if ip.version == 4:
            return ip in LOOPBACK_V4 if loopback else not any(ip in block for block in SPECIAL_V4)
        if loopback:
            return ip in LOOPBACK_V6
        # Mapped/compatible IPv4, NAT64, Teredo, 6to4, scoped/site/link-local,
        # unique-local, multicast and unallocated non-GUA space cannot bypass
        # the selected numeric destination boundary.
        return ip in GLOBAL_UNICAST_V6 and not any(ip in block for block in SPECIAL_GLOBAL_V6)
    except ValueError:
        return False


class Endpoint:
    """Contains secrets; its representation and errors intentionally omit them."""

    def __init__(self, config):
        try:
            if not isinstance(config, dict) or set(config) - {"url", "headers", "allow_loopback"}:
                fail()
            raw = config["url"]
            if not printable(raw) or len(raw) > 8192 or "\\" in raw:
                fail()
            parsed = urlsplit(raw)
            self.loopback = config.get("allow_loopback", False)
            if type(self.loopback) is not bool:
                fail()
            if parsed.scheme not in ("http", "https") or not parsed.hostname:
                fail()
            if parsed.username is not None or parsed.password is not None or parsed.fragment:
                fail()
            self.host = parsed.hostname.lower().rstrip(".")
            if not re.fullmatch(r"[a-z0-9.-]+|[0-9a-f:]+", self.host):
                fail()
            # ERPC service URLs are compile-time constants elsewhere. This
            # separately authorized L1 transport cannot proxy those APIs.
            if self.host == "erpc.global" or self.host.endswith(".erpc.global"):
                fail()
            if self.loopback:
                # Explicit numeric loopback only, never a name that can rebind.
                if not address_allowed(self.host, True):
                    fail()
            elif parsed.scheme != "https":
                fail()
            # Reject prohibited numeric literals before any resolver call. Named
            # destinations still revalidate every answer before each connection.
            try:
                literal = ipaddress.ip_address(self.host)
            except ValueError:
                literal = None
            if literal is not None and not address_allowed(self.host, self.loopback):
                fail()
            self.tls = parsed.scheme == "https"
            self.port = parsed.port if parsed.port is not None else (443 if self.tls else 80)
            if not 1 <= self.port <= 65535:
                fail()
            self.path = parsed.path or "/"
            if not self.path.startswith("/") or self.path.startswith("//"):
                fail()
            self.query = parsed.query
            headers = config.get("headers", {})
            if not isinstance(headers, dict) or len(headers) > 2:
                fail()
            self.headers = {}
            for key, value in headers.items():
                if (not isinstance(key, str) or key.lower() not in {"authorization", "x-api-key"}
                        or not printable(value) or len(value) > 8192 or key.lower() in self.headers):
                    fail()
                self.headers[key.lower()] = value
        except (KeyError, ValueError, TypeError, AttributeError):
            fail()

    def __repr__(self):
        return "Endpoint(<concealed>)"

    def addresses(self):
        try:
            answers = socket.getaddrinfo(self.host, self.port, type=socket.SOCK_STREAM)
            if not answers or len(answers) > 32:
                fail()
            checked = []
            for family, socktype, protocol, _, address in answers:
                if family not in (socket.AF_INET, socket.AF_INET6) or not address_allowed(address[0], self.loopback):
                    fail()
                checked.append((family, socktype, protocol, address))
            return checked
        except (OSError, ValueError, TypeError):
            fail()

    def request(self, method, suffix="", body=None):
        connection = None
        raw_socket = None
        try:
            # Reject the entire answer set if even one answer is non-public.
            # Connect to the numeric sockaddr; HTTPConnection must never resolve
            # the hostname a second time after this validation.
            answers = self.addresses()
            for family, socktype, protocol, address in answers:
                raw_socket = socket.socket(family, socktype, protocol)
                raw_socket.settimeout(TIMEOUT)
                try:
                    raw_socket.connect(address)
                    break
                except OSError:
                    raw_socket.close()
                    raw_socket = None
            if raw_socket is None:
                fail()
            if self.tls:
                raw_socket = ssl.create_default_context().wrap_socket(raw_socket, server_hostname=self.host)
            connection = http.client.HTTPConnection(self.host, self.port, timeout=TIMEOUT)
            connection.sock = raw_socket
            path = self.path.rstrip("/") + suffix if suffix else self.path
            if self.query:
                path += ("&" if "?" in path else "?") + self.query
            headers = {"Content-Type": "application/json", "Accept": "application/json",
                       "Accept-Encoding": "identity", "Connection": "close", **self.headers}
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            # A redirect could disclose credentials to an attacker or metadata
            # server. It is an error, never followed, even on the same host.
            # Base distinguishes missed/orphaned beacon slots from transient
            # transport errors. Preserve only this resource-specific 404; never
            # copy a provider body, Location, authentication header or message.
            if (response.status == 404 and method == "GET"
                    and re.fullmatch(r"/eth/v1/beacon/(?:blobs|blob_sidecars)/[A-Za-z0-9_]+", suffix.partition("?")[0])):
                raise MissingBeaconResource()
            if response.status != 200 or response.getheader("Content-Encoding", "identity") != "identity":
                fail()
            size = response.getheader("Content-Length")
            if size is not None and (not size.isdecimal() or int(size) > MAX_RESPONSE):
                fail()
            data = response.read(MAX_RESPONSE + 1)
            if len(data) > MAX_RESPONSE:
                fail()
            return strict_json(data)
        except (OSError, ValueError, TypeError, http.client.HTTPException):
            fail()
        finally:
            if connection:
                connection.close()
            if raw_socket:
                raw_socket.close()


def rpc_request(body, methods=METHODS):
    parsed = strict_json(body)
    batch = isinstance(parsed, list)
    items = parsed if batch else [parsed]
    if not 1 <= len(items) <= 100:
        fail()
    seen = set()
    for item in items:
        if (not isinstance(item, dict) or set(item) - {"jsonrpc", "id", "method", "params"}
                or item.get("jsonrpc") != "2.0" or not isinstance(item.get("method"), str)
                or item.get("method") not in methods
                or not isinstance(item.get("params", []), list)):
            fail()
        identity = item.get("id")
        if type(identity) not in (str, int) or (isinstance(identity, str) and len(identity) > 128):
            fail()
        identity = (type(identity), identity)
        if identity in seen:
            fail()
        seen.add(identity)
    return parsed


def rpc_response(request, response):
    batch = isinstance(request, list)
    if batch != isinstance(response, list):
        fail()
    wanted = request if batch else [request]
    received = response if batch else [response]
    if len(wanted) != len(received):
        fail()
    ids = {(type(item["id"]), item["id"]) for item in wanted}
    sanitized = []
    for item in received:
        if not isinstance(item, dict) or item.get("jsonrpc") != "2.0":
            fail()
        key = (type(item.get("id")), item.get("id"))
        try:
            if key not in ids:
                fail()
            ids.remove(key)
        except TypeError:
            fail()
        if ("result" in item) == ("error" in item):
            fail()
        out = {"jsonrpc": "2.0", "id": item["id"]}
        if "error" in item:
            # Provider diagnostics can repeat API keys, URL paths and headers.
            error = item["error"]
            code = error.get("code") if isinstance(error, dict) else None
            # Keep standard method-not-found semantics for client fallbacks,
            # without admitting booleans, arbitrary objects or oversized ints.
            if type(code) is not int or not -(2 ** 31) <= code < 2 ** 31:
                code = -32000
            out["error"] = {"code": code, "message": "L1 upstream request failed"}
        else:
            out["result"] = item["result"]
        sanitized.append(out)
    return sanitized if batch else sanitized[0]


def beacon_path(path):
    # Only read-only beacon paths used by the derivation clients. Percent
    # escapes, relative components, authorities and alternate API roots fail.
    if not isinstance(path, str) or len(path) > 4096:
        fail()
    parsed = urlsplit(path)
    if (not re.fullmatch(r"/eth/v[12]/(?:beacon|config|node)/[A-Za-z0-9_/-]+", parsed.path)
            or "//" in path or parsed.fragment):
        fail()
    if parsed.query:
        sidecars = re.fullmatch(r"/eth/v1/beacon/blob_sidecars/[A-Za-z0-9_]+", parsed.path)
        blobs = re.fullmatch(r"/eth/v1/beacon/blobs/[A-Za-z0-9_]+", parsed.path)
        if sidecars:
            valid = re.fullmatch(r"indices=[0-9]+(?:&indices=[0-9]+)*", parsed.query)
        elif blobs:
            valid = re.fullmatch(r"versioned_hashes=0x[0-9a-fA-F]{64}(?:,0x[0-9a-fA-F]{64})*(?:&versioned_hashes=0x[0-9a-fA-F]{64}(?:,0x[0-9a-fA-F]{64})*)*", parsed.query)
        else:
            fail()
        if not valid:
            fail()
    return path


class Upstreams:
    def __init__(self, config, network):
        if (network not in L1 or not isinstance(config, dict)
                or set(config) != {"execution", "beacon"}):
            fail()
        self.network = network
        self.execution = Endpoint(config["execution"])
        self.beacon = Endpoint(config["beacon"])
        self.checked = None
        self.lock = threading.Lock()

    def verify(self):
        with self.lock:
            now = time.monotonic()
            if self.checked is not None and now - self.checked < IDENTITY_TTL:
                return
            expected = L1[self.network]
            def rpc(method, params):
                query = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
                answer = rpc_response(query, self.execution.request("POST", body=json.dumps(query).encode()))
                if "result" not in answer:
                    fail()
                return answer["result"]
            if rpc("eth_chainId", []) != expected["chain"]:
                fail()
            block = rpc("eth_getBlockByNumber", ["0x0", False])
            if not isinstance(block, dict) or block.get("hash") != expected["block"]:
                fail()
            response = self.beacon.request("GET", "/eth/v1/beacon/genesis")
            genesis = response.get("data") if isinstance(response, dict) else None
            if not isinstance(genesis, dict) or any(genesis.get(k) != expected[k] for k in
                    ("genesis_time", "genesis_validators_root", "genesis_fork_version")):
                fail()
            self.checked = now

    def execution_request(self, body):
        request = rpc_request(body)
        self.verify()
        return rpc_response(request, self.execution.request("POST", body=body))

    def beacon_request(self, path):
        path = beacon_path(path)
        self.verify()
        result = self.beacon.request("GET", path)
        if not isinstance(result, dict) or "data" not in result:
            fail()
        return {k: v for k, v in result.items() if k in
                {"data", "version", "execution_optimistic", "finalized"}}


class Server(http.server.HTTPServer):
    """Bounded workers: a loopback caller cannot create unlimited threads."""
    def __init__(self, address, handler, upstreams, role):
        super().__init__(address, handler)
        self.upstreams = upstreams
        self.role = role
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=8)
        self.slots = threading.BoundedSemaphore(8)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        self.pool.submit(self.work, request, client_address)

    def work(self, request, client_address):
        try:
            request.settimeout(TIMEOUT)
            self.finish_request(request, client_address)
        except Exception:
            # HTTP parser and transport exceptions must not leak credentials or
            # attacker-controlled request lines through BaseServer's traceback.
            pass
        finally:
            self.shutdown_request(request)
            self.slots.release()

    def server_close(self):
        super().server_close()
        self.pool.shutdown(wait=True)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "erpc-l1"
    sys_version = ""

    def log_message(self, *_):
        pass

    def send_error(self, code, message=None, explain=None):
        # BaseHTTPRequestHandler's default HTML can include request data.
        self.reply(code, {"error": "L1 upstream request rejected or unavailable"})

    def reply(self, status, value):
        data = json.dumps(value, separators=(",", ":"), allow_nan=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)
        self.close_connection = True

    def do_POST(self):
        try:
            lengths = self.headers.get_all("Content-Length", [])
            if (self.server.role != "execution" or self.path != "/" or len(lengths) != 1
                    or not lengths[0].isdecimal() or self.headers.get("Transfer-Encoding") is not None):
                fail()
            size = int(lengths[0])
            if not 0 < size <= MAX_REQUEST:
                fail()
            body = self.rfile.read(size)
            if len(body) != size:
                fail()
            self.reply(200, self.server.upstreams.execution_request(body))
        except Exception:
            self.send_error(502)

    def do_GET(self):
        try:
            if (self.server.role != "beacon" or self.headers.get("Transfer-Encoding") is not None
                    or self.headers.get("Content-Length") not in (None, "0")):
                fail()
            self.reply(200, self.server.upstreams.beacon_request(self.path))
        except MissingBeaconResource:
            self.send_error(404)
        except Exception:
            self.send_error(502)


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in L1:
        fail()
    # No credentials or provider URLs in argv or environment. The systemd
    # variable contains only the kernel-managed credential directory path.
    directory = Path(os.environ["CREDENTIALS_DIRECTORY"])
    with (directory / "l1-upstreams").open("rb") as stream:
        raw = stream.read(65537)
    if len(raw) > 65536:
        fail()
    upstreams = Upstreams(strict_json(raw), sys.argv[1])
    upstreams.verify()
    execution = Server(("127.0.0.1", 18545), Handler, upstreams, "execution")
    beacon = Server(("127.0.0.1", 15052), Handler, upstreams, "beacon")
    thread = threading.Thread(target=execution.serve_forever, daemon=True)
    thread.start()
    try:
        beacon.serve_forever()
    finally:
        execution.shutdown()
        execution.server_close()
        beacon.server_close()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # No raw Python exception, config value, URL, path or header is logged.
        print("L1 upstream service unavailable", file=sys.stderr)
        sys.exit(1)
