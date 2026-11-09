#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Production unit builder: numeric credential recipient and private Engine IPC."""
import pathlib
import sys
import types
import unittest
from unittest import mock

sys.dont_write_bytecode = True
TEMPLATES = pathlib.Path(__file__).resolve().parents[1] / 'templates'
sys.path[:0] = [str(TEMPLATES / 'validator'), str(TEMPLATES / 'authority')]
import av_units as units
from av_files import HOME, ROOT
from arc_files import Refused


class Units(unittest.TestCase):
    def setUp(self):
        self.state = {'contract': {'network': 'testnet'}, 'accounts':
                      {'execution': 997, 'consensus': 996, 'engine': 995}, 'signer_used': False}
        self.policy = {'approved': True, 'fee_recipient': '0x' + 'a' * 40, 'phase': 'observer',
                       'execution_peers': ['enode://' + 'b' * 128 + '@192.0.2.1:30303'],
                       'sentry_peers': ['/ip4/192.0.2.2/tcp/27000/p2p/12D3KooWabcdefgh'],
                       'management_allow': [], 'monitoring_allow': [], 'ssh_port': 22}
        self.target = {'version': 'v0.8.1', 'commit': 'ab09dbfd9553a7ad48f9c134ec5e808c36512c74',
                       'archive_sha256': 'a' * 64, 'platform': 'x86_64-unknown-linux-gnu'}

    def make(self):
        source = {'images': {name: 'a' * 64 for name in ('arc-node-execution', 'arc-node-consensus', 'arc-snapshots')}}
        with mock.patch.object(units.release, 'qualify', return_value=source), \
             mock.patch.object(units.helpers, 'systemd_command',
                               side_effect=lambda _folder, _hash, action, role: '/inert-external-check ' + action + ' ' + role):
            return units.make(types.SimpleNamespace(), self.state, self.target, self.policy, TEMPLATES / 'validator', 'b' * 64)

    def test_only_original_cl_uid_receives_local_peer_key(self):
        generated, runtime = self.make()
        self.assertIn('User=996\nGroup=996\n', generated['consensus'])
        self.assertIn('LoadCredentialEncrypted=arc-validator-key:' + ROOT + '/consensus-key.cred', generated['consensus'])
        for component in ('execution', 'bootstrap'):
            self.assertNotIn('LoadCredential', generated[component])
            self.assertNotIn('--private-key', runtime[component]['argv'])
        for component, unit in generated.items():
            self.assertIn('ExecCondition=+/inert-external-check condition ' + component, unit)
            self.assertIn('LimitCORE=0', unit)
            self.assertIn('SendSIGKILL=no', unit)
        self.assertNotIn('--validator', runtime['consensus']['argv'])
        self.assertNotIn('--suggested-fee-recipient', runtime['consensus']['argv'])

    def test_local_signing_cannot_be_promoted_as_a_production_validator_unit(self):
        self.policy['phase'] = 'validator'
        with self.assertRaisesRegex(Refused, 'remote-signing authority'):
            self.make()

    def test_engine_directory_allows_cl_traversal_and_socket_io_without_rebinding(self):
        generated, runtime = self.make()
        self.assertIn('User=997\nGroup=995\nSupplementaryGroups=997 995', generated['execution'])
        self.assertIn('RuntimeDirectoryMode=0710', generated['execution'])
        self.assertIn('UMask=0007', generated['execution'])
        self.assertIn('SupplementaryGroups=996 995', generated['consensus'])
        args = runtime['execution']['argv']
        self.assertEqual(args[args.index('--ipc.permissions') + 1], '0o660')
        self.assertNotIn('--http', args)
        self.assertNotIn('--ws', args)
        self.assertNotIn('--execution-endpoint', runtime['consensus']['argv'])
        self.assertEqual(runtime['consensus']['argv'][runtime['consensus']['argv'].index('--execution-socket') + 1],
                         units.ENGINE_RUN + '/auth.ipc')

    def test_native_minimal_snapshot_and_runtime_use_same_profile(self):
        generated, runtime = self.make()
        for component in ('execution', 'consensus'):
            self.assertIn('--minimal', runtime[component]['argv'])
        args = runtime['bootstrap']['argv']
        self.assertEqual(args[args.index('--el-profile') + 1], 'minimal')
        self.assertEqual(args[args.index('--consensus-path') + 1], HOME + '/bootstrap/consensus')
        self.assertIn('Type=oneshot', generated['bootstrap'])
        self.assertIn('bootstrap-complete bootstrap', generated['bootstrap'])

    def test_observer_never_votes_and_used_signer_cannot_change_to_observer(self):
        self.policy['phase'] = 'observer'
        _, runtime = self.make()
        self.assertNotIn('--validator', runtime['consensus']['argv'])
        self.assertIn('--no-consensus', runtime['consensus']['argv'])
        self.policy['execution_peers'] = []
        self.policy['sentry_peers'] = []
        _, runtime = self.make()
        self.assertIn('--follow', runtime['consensus']['argv'])
        self.state['signer_used'] = True
        self.state['signing_history'] = {'inert': 'original'}
        with self.assertRaises(Refused):
            self.make()


if __name__ == '__main__':
    unittest.main()
