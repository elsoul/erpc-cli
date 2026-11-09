#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""ACL gateway: fixed local server, bounded RPC, no fileSnapshot/file output API."""
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
from pathlib import Path
import socket
import sys
import threading

MAX_REQUEST = 2 * 1024 * 1024
MAX_RESPONSE = 32 * 1024 * 1024
EVM = frozenset(('web3_clientVersion', 'net_version', 'eth_chainId', 'eth_blockNumber',
    'eth_syncing', 'eth_gasPrice', 'eth_maxPriorityFeePerGas', 'eth_feeHistory',
    'eth_getBalance', 'eth_getCode', 'eth_getStorageAt', 'eth_getTransactionCount',
    'eth_getBlockByNumber', 'eth_getBlockByHash', 'eth_getBlockTransactionCountByNumber',
    'eth_getBlockTransactionCountByHash', 'eth_getTransactionByHash',
    'eth_getTransactionByBlockNumberAndIndex', 'eth_getTransactionByBlockHashAndIndex',
    'eth_getTransactionReceipt', 'eth_getLogs', 'eth_call', 'eth_estimateGas',
    'eth_getProof', 'eth_sendRawTransaction'))
# The upstream node's documented state-only info subset. Deliberately exclude
# fileSnapshot, whose outPath writes arbitrary files under the native account.
INFO = frozenset(('meta', 'spotMeta', 'clearinghouseState', 'spotClearinghouseState',
    'openOrders', 'exchangeStatus', 'frontendOpenOrders', 'liquidatable',
    'activeAssetData', 'maxMarketOrderNtls', 'vaultSummaries', 'userVaultEquities',
    'leadingVaults', 'extraAgents', 'subAccounts', 'userFees', 'userRateLimit',
    'spotDeployState', 'perpDeployAuctionStatus', 'delegations', 'delegatorSummary',
    'maxBuilderFee', 'userToMultiSigSigners', 'userRole', 'perpsAtOpenInterestCap',
    'validatorL1Votes', 'marginTable', 'perpDexs', 'webData2'))


def unique_pairs(values):
    result = {}
    for key, value in values:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique_pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite number')))


def validated(path, raw):
    if len(raw) > MAX_REQUEST:
        raise ValueError('request too large')
    value = decode(raw)
    if path == '/evm':
        items = value if isinstance(value, list) else [value]
        if not 1 <= len(items) <= 32:
            raise ValueError('invalid RPC batch')
        for item in items:
            if (not isinstance(item, dict) or not set(item) <= {'jsonrpc', 'method', 'params', 'id'}
                    or item.get('jsonrpc') != '2.0' or item.get('method') not in EVM
                    or not isinstance(item.get('params', []), list)
                    or type(item.get('id')) not in (str, int, type(None))):
                raise ValueError('RPC method or envelope is outside the public profile')
    elif path == '/info':
        if (not isinstance(value, dict) or value.get('type') not in INFO
                or any(key in value for key in ('outPath', 'request', 'includeHeightInOutput'))):
            raise ValueError('info request is outside the public state-only profile')
    else:
        raise ValueError('unsupported endpoint')
    return json.dumps(value, separators=(',', ':'), allow_nan=False).encode()


def permitted(address, ranges):
    parsed = ipaddress.ip_address(address)
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        parsed = parsed.ipv4_mapped
    return any(parsed.version == network.version and parsed in network for network in ranges)


class Gateway(ThreadingHTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True
    def __init__(self, address, ranges):
        self.ranges = ranges
        self.capacity = threading.BoundedSemaphore(32)
        super().__init__(address, Handler)
    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()
    def process_request(self, request, address):
        if not self.capacity.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except Exception:
            self.capacity.release()
            raise
    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.capacity.release()


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(30)
    def log_message(self, *args):
        pass  # Never journal RPC bodies, user addresses, URLs or auth headers.
    def reply(self, status, body):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True
    def do_POST(self):
        try:
            if not permitted(self.client_address[0], self.server.ranges):
                self.reply(403, b'{"error":"access denied"}')
                return
            if self.headers.get('Transfer-Encoding') is not None:
                raise ValueError('chunked requests are unsupported')
            lengths = self.headers.get_all('Content-Length', [])
            if len(lengths) != 1 or not lengths[0].isdigit():
                raise ValueError('one content length is required')
            length = int(lengths[0])
            if not 0 < length <= MAX_REQUEST:
                raise ValueError('invalid request bound')
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError('incomplete request')
            raw = validated(self.path, raw)
        except Exception:
            self.reply(400, b'{"error":"request refused"}')
            return
        upstream = http.client.HTTPConnection('127.0.0.1', 3001, timeout=25)
        try:
            upstream.request('POST', self.path, body=raw,
                             headers={'Content-Type': 'application/json', 'Connection': 'close'})
            response = upstream.getresponse()
            body = response.read(MAX_RESPONSE + 1)
            if len(body) > MAX_RESPONSE or response.status != 200:
                raise ValueError('native API unavailable')
            # Do not proxy response headers or non-JSON diagnostics.
            value = decode(body)
            self.reply(200, json.dumps(value, separators=(',', ':'), allow_nan=False).encode())
        except Exception:
            self.reply(502, b'{"error":"native API unavailable"}')
        finally:
            upstream.close()


def main():
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if len(sys.argv) != 2:
        raise ValueError('fixed gateway configuration required')
    path = Path(sys.argv[1])
    data = path.read_bytes()
    if len(data) > 16384:
        raise ValueError('oversized gateway policy')
    policy = decode(data)
    if not isinstance(policy, dict) or set(policy) != {'allow'} or not isinstance(policy['allow'], list) or len(policy['allow']) > 64:
        raise ValueError('invalid gateway policy')
    ranges = [ipaddress.ip_network(value, strict=True) for value in policy['allow']]
    Gateway(('::', 8545), ranges).serve_forever()


if __name__ == '__main__':
    main()
