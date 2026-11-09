#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Inert observations of exact native writers and pinned snapshot children."""
import copy
import pathlib
import sys
import tempfile
import os
import types
import unittest
from unittest import mock

sys.dont_write_bytecode = True
TEMPLATES = pathlib.Path(__file__).resolve().parents[1] / 'templates'
sys.path[:0] = [str(TEMPLATES / 'validator'), str(TEMPLATES / 'authority')]
import av_process as process
from arc_files import Refused


class Processes(unittest.TestCase):
    def setUp(self):
        self.context = types.SimpleNamespace(path=pathlib.Path)
        self.state = {'accounts': {'execution': 991, 'consensus': 992, 'engine': 993}}
        self.runtime = {
            'execution': {'binary': '/inert/arc-node-execution', 'sha256': 'a' * 64,
                          'argv': ['/inert/arc-node-execution', 'node', '--minimal']},
            'consensus': {'binary': '/inert/arc-node-consensus', 'sha256': 'b' * 64,
                          'argv': ['/inert/arc-node-consensus', 'start']},
            'bootstrap': {'binary': '/inert/arc-snapshots', 'sha256': 'c' * 64,
                          'argv': ['/inert/arc-snapshots', 'download', '--chain', 'arc-testnet',
                                   '--el-profile', 'minimal', '--execution-path', '/inert/bootstrap/execution',
                                   '--consensus-path', '/inert/bootstrap/consensus']},
        }

    def observed(self, role):
        uid = str(self.state['accounts']['consensus' if role == 'consensus' else 'execution'])
        gid = '993' if role == 'execution' else uid
        value = self.runtime[role]
        return {'pid': 1234, 'start': 5678, 'uids': [uid] * 4, 'gids': [gid] * 4,
                'groups': [uid, '993'], 'exe': value['binary'], 'image': value['sha256'],
                'argv': list(value['argv']), 'cgroup': '/system.slice/' + process.UNITS[role],
                'inode': [1, 2], 'deleted': False}

    def child(self):
        value = self.observed('bootstrap')
        value['exe'] = self.runtime['execution']['binary']
        value['image'] = self.runtime['execution']['sha256']
        value['argv'] = [value['exe'], 'download', '--chain', 'arc-testnet', '--datadir',
                         '/inert/bootstrap/execution', '--minimal', '--manifest-url', 'native-opaque-reference']
        return value

    def test_numeric_roles_have_distinct_primary_groups_and_exact_supplementary_groups(self):
        for role in process.UNITS:
            self.assertEqual(process.classify(self.context, self.state, self.observed(role), [self.runtime]), role)
        for field, value in [('uids', ['992'] * 4), ('gids', ['991'] * 4), ('groups', ['991', '993', '994'])]:
            observed = self.observed('execution')
            observed[field] = value
            with self.assertRaises(Refused):
                process.classify(self.context, self.state, observed, [self.runtime])

    def test_pinned_manifest_download_and_help_children_are_shutdown_only(self):
        for argv in (self.child()['argv'], ['/inert/arc-node-execution', 'download', '--help']):
            observed = self.child()
            observed['argv'] = argv
            self.assertEqual(process.classify(self.context, self.state, observed, [self.runtime]), 'bootstrap')
            with self.assertRaises(Refused):
                process.matches(self.context, self.state, 'execution', observed, self.runtime, stopping=True)

    def test_snapshot_child_cannot_widen_to_other_data_chain_profile_or_identity(self):
        for index, replacement in [(3, 'arc-mainnet'), (5, '/inert/original/execution'),
                                   (6, '--archive'), (7, '--config'), (8, 'invalid\nreference')]:
            observed = self.child()
            observed['argv'][index] = replacement
            with self.assertRaises(Refused):
                process.classify(self.context, self.state, observed, [self.runtime])
        for field, replacement in [('cgroup', '/system.slice/foreign.service'), ('image', 'd' * 64),
                                   ('uids', ['992'] * 4), ('gids', ['993'] * 4), ('groups', ['991'])]:
            observed = self.child()
            observed[field] = replacement
            with self.assertRaises(Refused):
                process.classify(self.context, self.state, observed, [self.runtime])

    def test_child_remains_a_writer_with_missing_service_unit(self):
        inactive = {'LoadState': 'not-found', 'ActiveState': 'inactive', 'MainPID': '0'}
        with mock.patch.object(process, 'candidates', return_value=[self.child()]), \
             mock.patch.object(process, 'properties', return_value=inactive):
            with self.assertRaisesRegex(Refused, 'writer is still present'):
                process.quiescent(self.context, self.state, {'bootstrap'}, [self.runtime])

    def test_pid_generation_must_still_match_before_any_graceful_signal(self):
        value = self.child()
        replaced = copy.deepcopy(value)
        replaced['start'] += 1
        with mock.patch.object(process, 'candidates', return_value=[value]), \
             mock.patch.object(process.os, 'pidfd_open', return_value=123, create=True), \
             mock.patch.object(process.os, 'close') as close, \
             mock.patch.object(process, 'process', return_value=replaced), \
             mock.patch.object(process.signal, 'pidfd_send_signal', create=True) as send:
            with self.assertRaisesRegex(Refused, 'changed before shutdown'):
                process.signal_owned(self.context, self.state, {'bootstrap'}, [self.runtime])
            send.assert_not_called()
            close.assert_called_once_with(123)

    def test_original_uid_is_not_hidden_by_root_owned_nondumpable_proc_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            row = root / 'proc' / str(os.getpid() + 1000000)
            row.mkdir(parents=True)
            (row / 'status').write_text('Uid:\t991 991 991 991\n')
            (row / 'cgroup').write_text('0::/foreign-orphan-scope\n')
            context = types.SimpleNamespace(path=lambda path: root / path.lstrip('/'))
            original = self.observed('execution')
            original['cgroup'] = '/foreign-orphan-scope'
            with mock.patch.object(process, 'process', return_value=original) as observed:
                values = process.candidates(context, self.state)
                self.assertEqual(values, [original])
                observed.assert_called_once()
            with self.assertRaises(Refused):
                process.classify(self.context, self.state, original, [self.runtime])

    def test_foreign_image_under_original_identity_does_not_authorize_signal(self):
        value = self.child()
        value['image'] = 'd' * 64
        with mock.patch.object(process, 'candidates', return_value=[value]), \
             mock.patch.object(process.os, 'pidfd_open', create=True) as opened, \
             mock.patch.object(process.signal, 'pidfd_send_signal', create=True) as send:
            with self.assertRaises(Refused):
                process.signal_owned(self.context, self.state, {'bootstrap'}, [self.runtime])
            opened.assert_not_called()
            send.assert_not_called()


if __name__ == '__main__':
    unittest.main()
