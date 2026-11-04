# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Offline execution of the carried proxy, with fake sockets/provider responses."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import socket
import threading
import unittest
from unittest.mock import Mock, patch
import http.client

PATH = Path(__file__).parents[1] / "templates/scripts/upstreams.py"
SPEC = importlib.util.spec_from_file_location("upstreams", PATH)
proxy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(proxy)


def endpoint(url="https://github.com/rpc?credential=unit-test-placeholder", **extra):
    return {"url": url, "headers": {"Authorization": "Bearer unit-test-placeholder"}, **extra}


def request(method="eth_chainId", identity=1):
    return {"jsonrpc": "2.0", "id": identity, "method": method, "params": []}


def answer(result, identity=1):
    return {"jsonrpc": "2.0", "id": identity, "result": result}


class ProxyTests(unittest.TestCase):
    def reject(self, operation, *args):
        with self.assertRaises(proxy.Rejected) as captured:
            operation(*args)
        self.assertEqual(str(captured.exception), "L1 upstream request rejected or unavailable")
        self.assertNotIn("unit-test-placeholder", repr(captured.exception))

    def test_url_and_header_errors_are_concealed(self):
        for url in ["http:" + "//github.com", "https://user:password@github.com", "https://github.com/#fragment",
                    "https://github.com/\nsecret", "https://github.com\\@127.0.0.1", "https://github.com:99999", "https://github.com:0",
                    "file:///tmp/upstream", "https://edge.erpc.global/rpc", "https://erpc.global/rpc", "https://edge.erpc.global./rpc"]:
            self.reject(proxy.Endpoint, endpoint(url))
        for headers in [{"Host": "github.com"}, {"Authorization": "unit-test-placeholder\r\nHost: metadata"},
                        {"authorization": "a", "Authorization": "b"}, {"X-API-Key": 1}]:
            self.reject(proxy.Endpoint, {"url": "https://github.com", "headers": headers})
        self.assertEqual(repr(proxy.Endpoint(endpoint())), "Endpoint(<concealed>)")

    def test_plaintext_only_explicit_numeric_loopback(self):
        for host in ["localhost", "127.0.0.1", "[::1]", "10.0.0.1", "169.254.169.254"]:
            self.reject(proxy.Endpoint, endpoint("http://" + host))
        for host in ["127.0.0.1", "[::1]"]:
            value = proxy.Endpoint(endpoint("http://" + host + ":8545", allow_loopback=True))
            self.assertTrue(value.loopback)
        for host in ["localhost", "10.0.0.1", "169.254.169.254", "github.com", "[::ffff:127.0.0.1]"]:
            self.reject(proxy.Endpoint, endpoint("http://" + host, allow_loopback=True))
        self.reject(proxy.Endpoint, endpoint(allow_loopback="false"))

    def test_explicit_zero_port_is_never_replaced_by_a_default(self):
        self.reject(proxy.Endpoint, endpoint("https://github.com:0"))
        self.reject(proxy.Endpoint, endpoint("http://127.0.0.1:0", allow_loopback=True))
        self.assertEqual(proxy.Endpoint(endpoint("https://github.com")).port, 443)
        self.assertEqual(proxy.Endpoint(endpoint("http://127.0.0.1", allow_loopback=True)).port, 80)
        self.assertEqual(proxy.Endpoint(endpoint("https://github.com:8443")).port, 8443)

    def test_non_public_mapped_and_transition_addresses_rejected(self):
        for value in ["127.0.0.1", "10.0.0.1", "169.254.169.254", "192.0.2.1", "0.0.0.0", "224.0.0.1",
                      "::1", "::", "fe80::1", "fc00::1", "ff02::1", "::ffff:8.8.8.8", "2002:0808:0808::1",
                      "2001:4860:4860::8888%eth0", "64:ff9b::a9fe:a9fe", "64:ff9b:1::a00:1"]:
            self.assertFalse(proxy.address_allowed(value, False), value)
        self.assertTrue(proxy.address_allowed("8.8.8.8", False))
        self.assertTrue(proxy.address_allowed("2001:4860:4860::8888", False))

    def test_dns_rebinding_and_mixed_answer_sets(self):
        public = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))
        private = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 443))
        value = proxy.Endpoint(endpoint())
        with patch.object(proxy.socket, "getaddrinfo", side_effect=[[public], [private]]):
            self.assertEqual(value.addresses()[0][-1][0], "8.8.8.8")
            self.reject(value.addresses)
        with patch.object(proxy.socket, "getaddrinfo", return_value=[public, private]):
            self.reject(value.addresses)

    def transport(self, status=200, data=b'{"result":1}', headers=None):
        sock = Mock()
        connection = Mock()
        response = Mock(status=status)
        response.getheader.side_effect = lambda key, default=None: (headers or {}).get(key, default)
        response.read.return_value = data
        connection.getresponse.return_value = response
        context = Mock()
        context.wrap_socket.return_value = sock
        stack = contextlib.ExitStack()
        stack.enter_context(patch.object(proxy.socket, "getaddrinfo", return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]))
        resolver = stack.enter_context(patch.object(proxy.socket, "socket", return_value=sock))
        stack.enter_context(patch.object(proxy.ssl, "create_default_context", return_value=context))
        stack.enter_context(patch.object(proxy.http.client, "HTTPConnection", return_value=connection))
        self.addCleanup(stack.close)
        return sock, context, connection, resolver

    def test_connects_validated_numeric_address_and_checks_tls_hostname(self):
        sock, context, connection, _ = self.transport()
        value = proxy.Endpoint(endpoint())
        value.request("POST", body=b'{}')
        sock.connect.assert_called_once_with(("8.8.8.8", 443))
        context.wrap_socket.assert_called_once_with(sock, server_hostname="github.com")
        self.assertIs(connection.sock, sock)
        _, args = connection.request.call_args
        self.assertEqual(args["headers"]["authorization"], "Bearer unit-test-placeholder")
        self.assertEqual(args["headers"]["Accept-Encoding"], "identity")

    def test_tls_authentication_failure_never_sends_provider_credentials(self):
        sock, context, connection, _ = self.transport()
        context.wrap_socket.side_effect = proxy.ssl.SSLCertVerificationError("unit-test-placeholder")
        self.reject(proxy.Endpoint(endpoint()).request, "POST", "", b'{}')
        connection.request.assert_not_called()
        sock.close.assert_called()

    def test_redirects_rejected_without_following_or_echoing_location(self):
        for status in [301, 302, 307, 308, 401, 500]:
            with self.subTest(status=status):
                _, _, connection, _ = self.transport(status=status, headers={"Location": "http:" + "//169.254.169.254"})
                self.reject(proxy.Endpoint(endpoint()).request, "GET")
                self.assertEqual(connection.request.call_count, 1)

    def test_response_limits_encoding_and_invalid_json(self):
        for headers, data in [({"Content-Length": str(proxy.MAX_RESPONSE + 1)}, b'{}'),
                              ({"Content-Encoding": "gzip"}, b'{}'),
                              ({"Content-Length": "invalid"}, b'{}'), ({}, b'NaN'), ({}, b'1e999'), ({}, b'{"a":1,"a":2}')]:
            with self.subTest(headers=headers):
                self.transport(headers=headers, data=data)
                self.reject(proxy.Endpoint(endpoint()).request, "GET")

    def test_request_method_and_batch_restrictions(self):
        for method in ["engine_newPayloadV4", "admin_nodeInfo", "debug_traceTransaction", "eth_sendRawTransaction"]:
            self.reject(proxy.rpc_request, json.dumps(request(method)))
        for item in [[], [request()] * 101, [request(), request()], {**request(), "id": None},
                     {**request(), "id": True}, {**request(), "jsonrpc": "1.0"}, {**request(), "target": "elsewhere"}]:
            self.reject(proxy.rpc_request, json.dumps(item))
        accepted = [request(identity=1), request(identity="1")]
        self.assertEqual(proxy.rpc_request(json.dumps(accepted)), accepted)

    def test_nitro_historical_reads_preserve_params_without_exposing_write_methods(self):
        block_hash = '0x' + 'a' * 64
        allowed = ('eth_getTransactionByBlockHashAndIndex', 'eth_getUncleByBlockHashAndIndex')
        upstreams = Mock()
        upstreams.execution_request.side_effect = lambda body: proxy.rpc_response(
            proxy.rpc_request(body), answer({'hash': block_hash}))
        for role in ('execution', 'beacon'):
            server = proxy.Server(('127.0.0.1', 0), proxy.Handler, upstreams, role)
            worker = threading.Thread(target=server.serve_forever)
            worker.start()
            try:
                for method in allowed:
                    query = {**request(method), 'params': [block_hash, '0x0']}
                    self.assertEqual(proxy.rpc_request(json.dumps(query))['params'], [block_hash, '0x0'])
                    upstreams.execution_request.reset_mock()
                    client = http.client.HTTPConnection('127.0.0.1', server.server_port)
                    client.request('POST', '/', json.dumps(query), {'Content-Type': 'application/json'})
                    response = client.getresponse()
                    self.assertEqual(response.status, 200 if role == 'execution' else 502)
                    response.read(); client.close()
                    if role == 'execution':
                        sent = json.loads(upstreams.execution_request.call_args.args[0])
                        self.assertEqual(sent, query)
                    else:
                        upstreams.execution_request.assert_not_called()
                for method in ('eth_sendRawTransaction', 'eth_sendTransaction', 'eth_signTransaction', 'personal_sendTransaction', 'eth_estimateGas'):
                    self.reject(proxy.rpc_request, json.dumps(request(method)))
            finally:
                server.shutdown(); server.server_close(); worker.join()

    def test_provider_errors_do_not_disclose_url_or_headers(self):
        provider = {"jsonrpc": "2.0", "id": 1, "error": {"code": 401,
                    "message": "unit-test-placeholder", "data": endpoint()}}
        result = proxy.rpc_response(request(), provider)
        self.assertEqual(result["error"], {"code": 401, "message": "L1 upstream request failed"})
        self.assertNotIn("unit-test-placeholder", json.dumps(result))

    def test_unmatched_or_duplicate_response_ids_are_rejected(self):
        for result in [answer(1, 2), {**answer(1), "error": {}}, {"jsonrpc": "2.0", "id": 1},
                       {"jsonrpc": "2.0", "id": [], "result": 1}]:
            self.reject(proxy.rpc_response, request(), result)
        self.reject(proxy.rpc_response, [request(identity=1), request(identity=2)], [answer(1), answer(2)])
        self.assertEqual(proxy.rpc_response([request(identity=1), request(identity=2)], [answer(4, 2), answer(3, 1)]),
                         [answer(4, 2), answer(3, 1)])

    def test_beacon_path_cannot_escape_configured_origin(self):
        for path in ["//github.com/", "https://github.com", "/eth/v1/beacon/../admin", "/eth/v1/beacon/%2e%2e/admin",
                     "/eth/v1/beacon//genesis", "/admin", "/eth/v1/beacon/genesis?target=x", "/eth/v1/beacon/blocks/head#x"]:
            self.reject(proxy.beacon_path, path)
        for path in ["/eth/v1/beacon/genesis", "/eth/v1/beacon/blob_sidecars/0x1234?indices=0&indices=2",
                     "/eth/v2/beacon/blocks/head", "/eth/v1/config/spec"]:
            self.assertEqual(proxy.beacon_path(path), path)

    def test_eip7594_blob_queries_are_scoped_to_blobs_and_strict_hashes(self):
        digest = "0x" + "a" * 64
        path = "/eth/v1/beacon/blobs/123?versioned_hashes=" + digest
        self.assertEqual(proxy.beacon_path(path), path)
        self.assertEqual(proxy.beacon_path(path + "," + digest), path + "," + digest)
        self.assertEqual(proxy.beacon_path(path + "&versioned_hashes=" + digest), path + "&versioned_hashes=" + digest)
        for bad in [path[:-1], path + "a", path + ",", path + ",invalid", path + "," + digest[:-1],
                    path + "&target=elsewhere", path + "&indices=1",
                    path.replace("/blobs/", "/blob_sidecars/"),
                    path.replace("blobs/123", "genesis"),
                    "/eth/v1/config/spec?indices=1", "/eth/v1/beacon/blobs/1?indices=1"]:
            self.reject(proxy.beacon_path, bad)

    def test_method_fallback_codes_survive_without_provider_diagnostics(self):
        for code in [-32601, -32602, -32005]:
            result = proxy.rpc_response(request(), {"jsonrpc": "2.0", "id": 1,
                "error": {"code": code, "message": "unit-test-placeholder", "data": endpoint()}})
            self.assertEqual(result["error"], {"code": code, "message": "L1 upstream request failed"})
            self.assertNotIn("unit-test-placeholder", json.dumps(result))
        for code in [True, False, 1.5, "-32601", {}, [], 2 ** 31, -(2 ** 31) - 1, None]:
            result = proxy.rpc_response(request(), {"jsonrpc": "2.0", "id": 1, "error": {"code": code}})
            self.assertEqual(result["error"]["code"], -32000)

    def test_missing_blob_status_is_distinct_only_for_beacon_blob_resources(self):
        for path in ["/eth/v1/beacon/blobs/123?versioned_hashes=0x" + "a" * 64,
                     "/eth/v1/beacon/blob_sidecars/head?indices=1"]:
            _, _, connection, _ = self.transport(status=404, data=b'unit-test-placeholder',
                headers={"Location": "https://github.com/elsewhere", "Authorization": "unit-test-placeholder"})
            with self.assertRaises(proxy.MissingBeaconResource):
                proxy.Endpoint(endpoint()).request("GET", path)
            connection.getresponse.return_value.read.assert_not_called()
        for method, path in [("GET", "/eth/v1/beacon/genesis"), ("GET", "/eth/v1/config/spec"),
                             ("POST", "/eth/v1/beacon/blobs/123"), ("GET", "/eth/v1/beacon/blobs/")]:
            self.transport(status=404)
            with self.assertRaises(proxy.Rejected) as result:
                proxy.Endpoint(endpoint()).request(method, path)
            self.assertNotIsInstance(result.exception, proxy.MissingBeaconResource)

    def test_http_missing_slot_reply_contains_no_provider_body_or_headers(self):
        upstreams = Mock()
        upstreams.beacon_request.side_effect = proxy.MissingBeaconResource()
        server = proxy.Server(("127.0.0.1", 0), proxy.Handler, upstreams, "beacon")
        worker = threading.Thread(target=server.serve_forever)
        worker.start()
        try:
            client = http.client.HTTPConnection("127.0.0.1", server.server_port)
            client.request("GET", "/eth/v1/beacon/blobs/123")
            response = client.getresponse()
            self.assertEqual(response.status, 404)
            self.assertEqual(json.loads(response.read()), {"error": "L1 upstream request rejected or unavailable"})
            self.assertIsNone(response.getheader("Location"))
            self.assertIsNone(response.getheader("Authorization"))
            client.close()
        finally:
            server.shutdown()
            server.server_close()
            worker.join()

    def fixture(self, network):
        value = proxy.Upstreams({"execution": endpoint(), "beacon": endpoint()}, network)
        expected = proxy.L1[network]
        value.execution = Mock()
        value.execution.request.side_effect = [answer(expected["chain"]), answer({"hash": expected["block"]})]
        value.beacon = Mock()
        value.beacon.request.return_value = {"data": {k: expected[k] for k in
            ["genesis_time", "genesis_validators_root", "genesis_fork_version"]}}
        return value

    def test_both_network_identities_and_periodic_revalidation(self):
        for network in proxy.L1:
            value = self.fixture(network)
            with patch.object(proxy.time, "monotonic", side_effect=[1, 2, 62]):
                value.verify()
                value.verify()
                self.assertEqual(value.execution.request.call_count, 2)
                value.execution.request.side_effect = [answer("0xdead")]
                self.reject(value.verify)
                self.assertEqual(value.checked, 1)

    def test_each_genesis_dimension_must_match_before_proxy_ready(self):
        value = self.fixture("mainnet")
        value.execution.request.side_effect = [answer("0xaa36a7")]
        self.reject(value.verify)
        self.assertIsNone(value.checked)
        value = self.fixture("mainnet")
        value.execution.request.side_effect = [answer("0x1"), answer({"hash": "wrong"})]
        self.reject(value.verify)
        for key in ["genesis_time", "genesis_validators_root", "genesis_fork_version"]:
            value = self.fixture("mainnet")
            value.beacon.request.return_value["data"][key] = "wrong"
            self.reject(value.verify)
            self.assertIsNone(value.checked)

    def test_real_loopback_http_framing_and_no_diagnostic_leak(self):
        upstreams = Mock()
        upstreams.execution_request.side_effect = RuntimeError("unit-test-placeholder")
        server = proxy.Server(("127.0.0.1", 0), proxy.Handler, upstreams, "execution")
        worker = threading.Thread(target=server.serve_forever)
        worker.start()
        try:
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                client = http.client.HTTPConnection("127.0.0.1", server.server_port)
                client.request("POST", "/", json.dumps(request()), {"Content-Type": "application/json"})
                response = client.getresponse()
                data = response.read()
                self.assertEqual(response.status, 502)
                self.assertNotIn(b"unit-test-placeholder", data)
                self.assertEqual(stderr.getvalue(), "")
                client.close()
            upstreams.execution_request.reset_mock()
            client = http.client.HTTPConnection("127.0.0.1", server.server_port)
            client.request("POST", "//github.com/", b'{}')
            self.assertEqual(client.getresponse().status, 502)
            upstreams.execution_request.assert_not_called()
            client.close()
        finally:
            server.shutdown()
            server.server_close()
            worker.join()


if __name__ == "__main__":
    unittest.main()
