#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Native method/recipient/value limits with inert calldata and no signing."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'templates/validator/node'))
import abi
import admission
import crypto
import rlp
import transactions


def word(value):
    return int(value[2:], 16).to_bytes(32, 'big') if isinstance(value, str) else value.to_bytes(32, 'big')


def data(selector, values): return bytes.fromhex(selector) + b''.join(word(value) for value in values)


def assertion(wallet):
    # uint256 + BeforeStateData(7 words) + AssertionState(6)*2 + hash + address.
    values = [200, 1, 2, 3, 200, admission.CHALLENGE, 10, 20] + [0] * 12 + [4, wallet]
    return data('50f32f68', values)


class Transactions(unittest.TestCase):
    def setUp(self):
        self.wallet = '0x' + '1' * 40
        self.observation = {'wallet': self.wallet, 'rollup': admission.ROLLUP,
            'challenge_manager': admission.CHALLENGE, 'stake_token': admission.WETH, 'permissionless': True, 'rollup_paused': False,
            'assertion_bond_wei': '200', 'challenge_path_bonds_wei': ['100', '20', '5'],
            'weth_balance_wei': '325', 'rollup_allowance_wei': '200', 'challenge_allowance_wei': '125'}

    def test_exact_assertion_amount_and_original_withdrawer_are_required(self):
        call = assertion(self.wallet)
        self.assertEqual(transactions.payload(admission.ROLLUP, call, self.wallet, self.observation), 'newStakeOnNewAssertion')
        for recipient, payload in [(admission.WETH, call), (admission.CHALLENGE, call),
                                   (admission.ROLLUP, assertion('0x' + '2' * 40)),
                                   (admission.ROLLUP, call[:4] + word(201) + call[36:])]:
            with self.assertRaises(ValueError): transactions.payload(recipient, payload, self.wallet, self.observation)
        with self.assertRaises(ValueError):
            transactions.payload(admission.ROLLUP, call, self.wallet, dict(self.observation, rollup_allowance_wei='199'))

    def test_wrapping_approval_transfers_owner_and_withdrawal_methods_are_not_admitted(self):
        for selector in ('d0e30db0', '095ea7b3', 'a9059cbb', '23b872dd', 'f2fde38b', '2e1a7d4d'):
            with self.subTest(selector=selector), self.assertRaises(ValueError):
                transactions.payload(admission.ROLLUP, data(selector, [0] * 22), self.wallet, self.observation)

    def test_dynamic_edge_payload_is_contiguous_and_uses_only_allocated_level_bond(self):
        # One dynamic CreateEdgeArgs tuple: head192, two byte tails of64 each.
        call = data('05fae141', [32, 0, 1, 10, 2, 192, 256, 2]) + b'ab' + bytes(30) + word(3) + b'cde' + bytes(29)
        self.assertEqual(transactions.payload(admission.CHALLENGE, call, self.wallet, self.observation), 'createLayerZeroEdge')
        with self.assertRaises(ValueError):
            transactions.payload(admission.CHALLENGE, call, self.wallet, dict(self.observation, weth_balance_wei='99'))
        # Alias the second tail to the first, add a gap, or smuggle trailing data.
        for corrupt in (call[:4 + 6*32] + word(192) + call[4 + 7*32:],
                        call[:4] + word(64) + call[36:], call + word(0), call[:-1] + b'\x01'):
            with self.assertRaises(ValueError): abi.decode(corrupt)

    def test_one_step_struct_and_proof_arrays_have_canonical_offsets_and_no_aliases(self):
        # Main head9 words; OneStepData occupies160; arrays occupy64 and96.
        call = data('8c1b3a40', [1, 288, 2, 200, admission.CHALLENGE, 10, 20, 448, 512,
                                 3, 64, 33]) + b'x'*33 + bytes(31) + data('', [1, 4, 2, 5, 6])
        family, name, values = abi.decode(call)
        self.assertEqual((family, name), ('challenge', 'confirmEdgeByOneStepProof'))
        self.assertEqual(len(values[1][1]), 33); self.assertEqual(len(values[3]), 1); self.assertEqual(len(values[4]), 2)
        self.assertEqual(transactions.payload(admission.CHALLENGE, call, self.wallet, self.observation), name)
        with self.assertRaises(ValueError): abi.decode(call[:4 + 8*32] + word(448) + call[4 + 9*32:])

    def test_signed_path_checks_chain_sender_and_value_without_creating_a_signature(self):
        call = assertion(self.wallet)
        fields = [b'\x01', b'', b'\x01', b'\x02', b'\x01', bytes.fromhex(admission.ROLLUP[2:]),
                  b'', call, [], b'', b'\x01', b'\x01']
        def encoded(values): return '0x02' + rlp.encode(values).hex()
        with patch.object(crypto, 'keccak', return_value=bytes(32)):
            seen = []
            def recovered(digest, parity, r, s): seen.append((len(digest), parity, r, s)); return self.wallet
            self.assertEqual(transactions.signed(encoded(fields), self.wallet, self.observation, recovered), 'newStakeOnNewAssertion')
            self.assertEqual(seen, [(32, 0, 1, 1)])
            with self.assertRaisesRegex(ValueError, 'dedicated wallet'):
                transactions.signed(encoded(fields), self.wallet, self.observation, lambda *_: '0x' + '2'*40)
            for index, bad in [(0, b'\x02'), (6, b'\x01'), (8, [[bytes(20), []]]),
                               (3, (transactions.MAX_FEE_WEI + 1).to_bytes(8, 'big').lstrip(b'\0'))]:
                changed = list(fields); changed[index] = bad
                with self.assertRaises(ValueError): transactions.signed(encoded(changed), self.wallet, self.observation, recovered)
            self.assertEqual(len(seen), 1)

    def test_unsigned_gas_estimates_do_not_open_a_transfer_or_other_wallet_path(self):
        value = {'from': self.wallet, 'to': admission.ROLLUP, 'data': '0x' + assertion(self.wallet).hex()}
        self.assertEqual(transactions.estimate(value, self.wallet, self.observation), 'newStakeOnNewAssertion')
        for change in ({'value': '0x1'}, {'from': '0x'+'2'*40}, {'to': admission.WETH},
                       {'input': value['data']}, {'accessList': [{}]}, {'private-key': 'inert forbidden'}):
            with self.assertRaises(ValueError): transactions.estimate(dict(value, **change), self.wallet, self.observation)


if __name__ == '__main__': unittest.main()
