#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Inert provider replies exercise the actual transport without sending a byte."""
from contextlib import contextmanager
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'templates/validator/node'))
sys.path.insert(0, str(ROOT.parent / 'erpc-chain-rollup/templates/scripts'))
import transport
import upstreams


def body(method, params): return json.dumps({'jsonrpc': '2.0', 'id': 7, 'method': method, 'params': params}).encode()


class Provider:
    tls=True
    loopback=False
    def __init__(self, wallet): self.calls = []; self.wallet = wallet; self.lost = False; self.known = False
    def request(self, method, path='', body=None):
        value = json.loads(body); self.calls.append(value['method'])
        if value['method'] == 'eth_sendRawTransaction':
            if self.lost: raise upstreams.Rejected()
            result = '0x' + 'a'*64
        elif value['method'] == 'eth_getTransactionByHash':
            result = {'hash': value['params'][0], 'from': self.wallet} if self.known else None
        else: result = '0x1'
        return {'jsonrpc': '2.0', 'id': value['id'], 'result': result}


class Transport(unittest.TestCase):
    def setUp(self):
        self.addCleanup(patch.stopall); self.wallet = '0x' + '1'*40
        self.provider = Provider(self.wallet); self.entered = 0; self.held = False
        @contextmanager
        def authorize():
            self.entered += 1; self.held = True
            try: yield
            finally: self.held = False
        # Endpoint construction is inert here; the shared suite validates its credentials.
        config = {'execution': {}, 'beacon': {}}
        with patch.object(upstreams, 'Endpoint', return_value=self.provider), patch.object(transport.bounded, 'Endpoint', return_value=self.provider):
            self.service = transport.Transport(config, self.wallet, 'active', authorize)
        patch.object(self.service, 'verify', return_value=None).start()
        def observed(_rpc, wallet):
            self.assertTrue(self.held); self.assertEqual(wallet, self.wallet); return {'inert': True}
        patch.object(transport.admission, 'observe', side_effect=observed).start()
        def checked(*args): self.assertTrue(self.held); return 'inert checked native transaction'
        self.checked = patch.object(transport.transactions, 'signed', side_effect=checked).start()
        patch.object(transport.transactions, 'estimate', side_effect=checked).start()
        patch.object(transport.crypto, 'keccak', return_value=bytes.fromhex('a'*64)).start()

    def test_ordinary_shared_proxy_stays_read_only_and_native_batches_are_never_partially_forwarded(self):
        for method in transport.EXTRA:
            with self.assertRaises(upstreams.Rejected): upstreams.rpc_request(body(method, []))
        mixed = [json.loads(body('eth_chainId', [])), dict(json.loads(body('eth_sendRawTransaction', ['0x0201'])), id=8)]
        with self.assertRaises(upstreams.Rejected): self.service.execution_request(json.dumps(mixed).encode())
        self.assertEqual(self.provider.calls, []); self.assertEqual(self.entered, 0)
        with self.assertRaises(upstreams.Rejected): self.service.execution_request(body('eth_gasPrice', ['unwanted']))

    def test_observer_or_revoked_authority_cannot_submit_or_estimate(self):
        self.service.phase = 'observing'
        for method in transport.WRITES:
            with self.assertRaises(upstreams.Rejected): self.service.execution_request(body(method, ['inert']))
        self.service.phase = 'active'
        @contextmanager
        def revoked():
            raise upstreams.Rejected()
            yield
        self.service.authorize = revoked
        with self.assertRaises(upstreams.Rejected): self.service.execution_request(body('eth_sendRawTransaction', ['0x0201']))
        self.assertEqual(self.provider.calls, []); self.assertEqual(self.checked.call_count, 0)

    def test_native_submission_stays_in_authority_scope_and_returns_only_its_exact_hash(self):
        result = self.service.execution_request(body('eth_sendRawTransaction', ['0x0201']))
        self.assertEqual(result['result'], '0x' + 'a'*64)
        self.assertEqual(self.provider.calls, ['eth_sendRawTransaction']); self.assertEqual(self.entered, 1)
        self.assertFalse(self.held); self.assertFalse(hasattr(self.service.operation, 'deadline'))

    def test_ambiguous_submission_is_recovered_by_hash_without_resubmitting_or_resigning(self):
        self.provider.lost = True; self.provider.known = True
        result = self.service.execution_request(body('eth_sendRawTransaction', ['0x0201']))
        self.assertEqual(result['result'], '0x' + 'a'*64)
        self.assertEqual(self.provider.calls, ['eth_sendRawTransaction', 'eth_getTransactionByHash'])
        self.assertEqual(self.checked.call_count, 1)
        self.provider.calls.clear(); self.provider.known = False
        result = self.service.execution_request(body('eth_sendRawTransaction', ['0x0201']))
        self.assertNotIn('result', result); self.assertIn('original transaction retained', result['error']['message'])
        self.assertEqual(self.provider.calls.count('eth_sendRawTransaction'), 1)

    def test_stale_slow_qualification_cannot_send_after_its_authority_deadline(self):
        with patch.object(transport.time, 'monotonic', side_effect=[1, 100]):
            with self.assertRaises(upstreams.Rejected): self.service.execution_request(body('eth_sendRawTransaction', ['0x0201']))
        self.assertEqual(self.provider.calls, []); self.assertFalse(self.held)
        self.assertFalse(hasattr(self.service.operation, 'deadline'))
        with self.assertRaises(upstreams.Rejected): self.service.rpc('eth_sendRawTransaction', ['inert'])


if __name__ == '__main__': unittest.main()
