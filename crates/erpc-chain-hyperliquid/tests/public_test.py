# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Source-shaped public API fixtures without contacting a blockchain node."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
root = Path(__file__).parents[1] / 'templates/node'
sys.path.insert(0, str(root))
spec = importlib.util.spec_from_file_location('hyperliquid_public_fixture', root / 'erpc_hl_public.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class Public(unittest.TestCase):
    def test_official_roots_cannot_direct_native_bootstrap_to_private_or_special_addresses(self):
        profile = json.loads((root/'catalog.json').read_bytes())['networks']['mainnet']
        for peer in ['127.0.0.1', '100.64.0.1', '192.0.0.9', '192.31.196.1', '224.0.0.1', 'example.invalid', '::1']:
            with patch.object(p, 'post', return_value=[peer]), self.assertRaises(ValueError):
                p.root_peers(profile)
        with patch.object(p, 'post', return_value=['8.8.8.8', '8.8.8.8']):
            self.assertEqual(p.root_peers(profile)['root_node_ips'], [{'Ip': '8.8.8.8'}])
        with patch.object(p, 'post', return_value=[]):
            with self.assertRaises(ValueError):
                p.root_peers(profile)
        with patch.object(p, 'post') as request:
            self.assertIsNone(p.root_peers({'chain': 'Testnet'}))
            request.assert_not_called()

    def test_fresh_evm_alone_cannot_hide_stale_or_unknown_native_core(self):
        profile = {'chain_id': 999}
        head = {'number': '0x10', 'timestamp': hex(10000), 'hash': '0x' + 'a' * 64}
        with patch.object(p, 'evm', side_effect=lambda method, _: '0x3e7' if method == 'eth_chainId' else head):
            for core, ready in [({'specialStatuses': None, 'time': 10000000}, True),
                                ({'time': 9000000}, False), ({'time': True}, False), ({}, False)]:
                with patch.object(p, 'post', return_value=core):
                    self.assertEqual(p.observe(profile, now=10001)['ready'], ready)
        with patch.object(p, 'evm', return_value='0x3e6'):
            self.assertFalse(p.observe(profile, now=10001)['ready'])
        with patch.object(p, 'evm', side_effect=ValueError('unavailable')):
            self.assertFalse(p.observe(profile, now=10001)['ready'])


if __name__ == '__main__':
    unittest.main()
