# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Native-only BoLD submission policy over the existing authenticated transport.

The launcher supplies a send-authority context that keeps one original runtime
receipt valid while the request is in flight. A stopped/observing node cannot
acquire it. Provider diagnostics never enter logs or JSON responses.
"""
import json
import scope
import threading
import time
import admission
import bounded
import crypto
import transactions
import upstreams

EXTRA = frozenset({'eth_gasPrice', 'eth_maxPriorityFeePerGas', 'eth_estimateGas', 'eth_sendRawTransaction'})
WRITES = frozenset({'eth_estimateGas', 'eth_sendRawTransaction'})


class Transport(upstreams.Upstreams):
    def __init__(self, config, wallet, phase, authorize):
        admission.address(wallet)
        if phase not in ('observing', 'active') or not callable(authorize): upstreams.fail()
        super().__init__(config, scope.PARENT)
        self.wallet, self.phase, self.authorize = wallet, phase, authorize
        self.operation = threading.local()
        deadline = lambda: getattr(self.operation, "deadline", float("inf"))
        self.execution = bounded.Endpoint(config["execution"], deadline)
        self.beacon = bounded.Endpoint(config["beacon"], deadline)
        if not all(endpoint.tls and not endpoint.loopback for endpoint in (self.execution,self.beacon)): upstreams.fail()

    def deadline(self):
        if time.monotonic() > getattr(self.operation, "deadline", float("inf")): upstreams.fail()

    def rpc(self, method, params):
        if method not in upstreams.METHODS: upstreams.fail()
        self.deadline()
        request = {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}
        answer = upstreams.rpc_response(request, self.execution.request('POST', body=json.dumps(request).encode()))
        if 'result' not in answer: upstreams.fail()
        return answer['result']

    def known(self, digest):
        value = self.rpc('eth_getTransactionByHash', [digest])
        return (isinstance(value, dict) and value.get('hash') == digest
                and isinstance(value.get('from'), str) and value['from'].lower() == self.wallet)

    def submit(self, request, body):
        self.deadline()
        encoded = request['params'][0]
        digest = '0x' + crypto.keccak(bytes.fromhex(encoded[2:])).hex()
        try:
            answer = upstreams.rpc_response(request, self.execution.request('POST', body=body))
            if answer.get('result') == digest: return answer
        except Exception:
            pass
        # A lost reply or sanitized already-known error must not trigger another
        # signature or change of nonce. Observe THIS exact submitted transaction.
        try:
            if self.known(digest): return {'jsonrpc': '2.0', 'id': request['id'], 'result': digest}
        except Exception:
            pass
        return {'jsonrpc': '2.0', 'id': request['id'],
                'error': {'code': -32000, 'message': 'Native BoLD submission not confirmed; original transaction retained'}}

    def execution_request(self, body):
        parsed = upstreams.rpc_request(body, upstreams.METHODS | EXTRA)
        items = parsed if isinstance(parsed, list) else [parsed]
        for item in items:
            method, params = item['method'], item.get('params', [])
            if method in ('eth_gasPrice', 'eth_maxPriorityFeePerGas') and params: upstreams.fail()
        native = [item for item in items if item['method'] in WRITES]
        if not native:
            self.verify()
            return upstreams.rpc_response(parsed, self.execution.request('POST', body=body))
        # The pinned DataPoster performs one transaction operation per request.
        # Do not partially execute a caller-provided mixed batch.
        if isinstance(parsed, list) or self.phase != 'active': upstreams.fail()
        request = native[0]; params = request.get('params', [])
        if len(params) != 1: upstreams.fail()
        self.verify()  # Read-only identity checks occur before taking send authority.
        with self.authorize():
            self.operation.deadline = time.monotonic() + 45
            try:
                observation = admission.observe(self.rpc, self.wallet)
                if request['method'] == 'eth_estimateGas':
                    transactions.estimate(params[0], self.wallet, observation)
                    self.deadline()
                    return upstreams.rpc_response(request, self.execution.request('POST', body=body))
                transactions.signed(params[0], self.wallet, observation)
                return self.submit(request, body)
            finally:
                del self.operation.deadline
