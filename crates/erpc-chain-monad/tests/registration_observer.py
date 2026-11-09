#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Native ABI layout fixtures from the pinned staking precompile, without calls or signatures."""
import json
from pathlib import Path
import sys
import time
import unittest
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'templates/node'))
import erpc_monad_observe as observe


def abi_words(values):
    return b''.join(v.to_bytes(32, 'big') for v in values)


def dynamic(data):
    return abi_words([len(data)]) + data + b'\0' * ((-len(data)) % 32)


class ObservationTests(unittest.TestCase):
    def setUp(self):
        self.c = {'role': 'validator', 'network': 'testnet', 'secp': '02' + 'ab' * 32,
                  'bls': 'cd' * 48, 'auth_address': '0x' + 'ef' * 20}
        self.delay, self.member, self.wrong_key = False, True, False
        self.calls = []
        self.hash = '0x' + 'ab' * 32

    def rpc(self, method, params):
        self.calls.append((method, params))
        if method == 'eth_chainId':
            return hex(10143)
        if method == 'eth_getBlockByNumber':
            self.assertEqual(params, ['finalized', False])
            return {'number': '0x100', 'hash': self.hash, 'timestamp': hex(int(time.time()))}
        self.assertEqual(method, 'eth_call')
        self.assertEqual(params[1], {'blockHash': self.hash})
        self.assertEqual(params[0]['to'], '0x' + '0' * 36 + '1000')
        selector = params[0]['data'][2:10]
        if selector == '2b6d639a':
            # Ten static outputs and two dynamic public keys, exactly as the native encoder.
            head = [int(self.c['auth_address'], 16), 0, 10**25, 0, 5*10**16, 0, 10**25, 5*10**16, 10**25, 5*10**16, 384, 480]
            secp = bytes.fromhex(self.c['secp']) if not self.wrong_key else b'\xff' * 33
            result = abi_words(head) + dynamic(secp) + dynamic(bytes.fromhex(self.c['bls']))
        elif selector == '757991a8':
            result = abi_words([9, int(self.delay)])
        elif selector in ('fb29b729', 'de66a368'):
            self.assertEqual(selector, 'de66a368' if self.delay else 'fb29b729')
            result = abi_words([1, 1, 96, 1, 7 if self.member else 8])
        elif selector == '573c1ce0':
            self.assertEqual(params[0]['data'][10:], f'{7:064x}' + self.c['auth_address'][2:].rjust(64, '0'))
            result = abi_words([10**23, 0, 0, 0, 0, 0, 0])
        else:
            self.fail('a financial or unqualified method was attempted')
        return '0x' + result.hex()

    def test_current_epoch_selects_the_native_boundary_snapshot_and_pins_block_hash(self):
        for delay in (False, True):
            self.delay = delay
            report = observe.registration(self.c, 7, self.rpc)
            self.assertTrue(report['identity_matches'])
            self.assertEqual(report['state'], 'active in current epoch')
            self.assertEqual(report['block_hash'], self.hash)
            self.assertFalse(report['transaction_submitted'])
        self.assertTrue(all(method in ('eth_chainId', 'eth_getBlockByNumber', 'eth_call') for method, _ in self.calls))

    def test_unknown_identity_is_not_claimed_registered_or_active(self):
        self.wrong_key = True
        report = observe.registration(self.c, 7, self.rpc)
        self.assertFalse(report['identity_matches'])
        self.assertNotIn('total_stake_wei', report)
        self.wrong_key = False
        self.member = False
        self.assertEqual(observe.registration(self.c, 7, self.rpc)['state'], 'registered but not active in current epoch')

    def test_role_ids_and_abi_offsets_are_bounded(self):
        for value in (0, True, 2**64, -1):
            with self.assertRaises(ValueError):
                observe.registration(self.c, value, self.rpc)
        for offset in (1, 32, 2**256-1):
            with self.assertRaises(ValueError):
                observe.dynamic(bytes(64), offset, 48)
        with self.assertRaises(ValueError):
            observe.registration(dict(self.c, role='rpc'), 7, self.rpc)


if __name__ == '__main__':
    unittest.main()
