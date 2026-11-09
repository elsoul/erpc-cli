# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Service and retention fixtures; no systemd service or native client runs."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
sys.dont_write_bytecode = True
folder = Path(__file__).parents[1] / 'templates/node'
sys.path.insert(0, str(folder))
import erpc_hl_units as units
IDENTITIES={'erpc-hyperliquid':{'uid':995,'gid':995},'erpc-hyperliquid-rpc':{'uid':996,'gid':996}}
spec = importlib.util.spec_from_file_location('hyperliquid_retention_fixture', folder / 'retention.py')
r = importlib.util.module_from_spec(spec);spec.loader.exec_module(r)


class Profiles(unittest.TestCase):
    def test_both_networks_bind_chain_config_and_keep_gateway_under_another_identity(self):
        for network in ('mainnet', 'testnet'):
            values = units.render({'network': network, 'owner': 'a' * 32, 'role': 'rpc'}, {'id': 'visor-' + 'b' * 16},IDENTITIES)
            native = values['erpc-hyperliquid-node.service']
            self.assertIn('run-non-validator --serve-eth-rpc --serve-info', native)
            self.assertNotIn('run-validator', native)
            self.assertIn('BindReadOnlyPaths=/etc/hyperliquid/visor.json:', native)
            self.assertEqual('gossip.json:' in native, network == 'mainnet')
            self.assertIn('Environment=GNUPGHOME=/etc/hyperliquid/gnupg', native)
            self.assertIn('User=996', values['erpc-hyperliquid-rpc.service'])
            for key in ('erpc-hyperliquid-node.service', 'erpc-hyperliquid-rpc.service'):
                self.assertIn('ExecStartPre=+/usr/bin/python3 -I', values[key])
            self.assertIn('firewall-load '+ 'a'*32, values['erpc-hyperliquid-firewall.service'])
            self.assertIn('ExecStart=/usr/bin/python3 -I -c', values['erpc-hyperliquid-firewall.service'])
        with self.assertRaises(ValueError):
            units.render({'network': 'mainnet', 'owner': 'a' * 32, 'role': 'validator'}, {'id': 'visor-' + 'b' * 16},IDENTITIES)

    def test_inline_release_bootstrap_uses_exact_reviewed_canonical_trust(self):
        source = (folder/'erpc_hl_trust.py').read_text()
        repository = folder.parents[3]
        for marker,name in [('TRUSTED IMPORTS','python-trust.py'),('TRUSTED RELEASE','python-release.py')]:
            embedded = source.split('# BEGIN ERPC '+marker+'\n',1)[1].split('# END ERPC '+marker,1)[0]
            self.assertEqual(embedded,(repository/'crates/erpc-ssh/src'/name).read_text())
        command = units.controller_bootstrap()
        self.assertIn('/usr/bin/python3 -I -c',command)
        program = bytes.fromhex(command.split("fromhex('",1)[1].split("')",1)[0]).decode()
        self.assertLess(program.index('selected=trusted_release('),program.index('runpy.run_path('))
        self.assertIn('control.py',program)

    def test_old_public_outputs_are_pruned_but_latest_snapshots_and_private_native_state_remain(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = ['replica_cmds/session/date/1', 'periodic_abci_states/date/1.rmp',
                     'periodic_abci_states/date/2.rmp', 'periodic_abci_states/date/3.rmp',
                     'hyperliquid_data/node_config.json', 'visor_child_stderr/date/error',
                     'unknown-output/data']
            for name in paths:
                path = root / name;path.parent.mkdir(parents=True, exist_ok=True);path.write_bytes(b'inert output')
                os.utime(path, (1, 1))
            self.assertEqual(r.prune(root, now=200000), 2)
            for name in paths[2:]:self.assertTrue((root / name).exists(), name)
            outside = root / 'outside';outside.write_bytes(b'preserved')
            (root / 'replica_cmds/linked').symlink_to(outside)
            with self.assertRaises(ValueError):r.prune(root, now=200000)
            self.assertEqual(outside.read_bytes(), b'preserved')


if __name__ == '__main__':unittest.main()
