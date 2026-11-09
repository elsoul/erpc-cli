#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual carried prepare/controller/helpers/NSS-model composition on temporary files."""
import base64
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from contextlib import ExitStack
from unittest.mock import patch
sys.dont_write_bytecode = True
SOURCE = pathlib.Path(__file__).resolve().parents[1] / 'templates/authority'
sys.path.insert(0, str(SOURCE))
import control
import arc_accounts as accounts
import arc_helpers as helpers
import arc_protocol as protocol
import arc_units as units
from arc_files import Refused


class Host(control.Control):
    def __init__(self, root):
        super().__init__(root, owner=os.getuid())
        self.users, self.groups, self.nss_calls = {}, {}, []
        self.mkdir('/etc/erpc/arc/authority')
        self.mkdir('/var/lib')
        self.write_bytes('/etc/os-release', b'ID=ubuntu\nVERSION_ID=24.04\n', 0o644)
        self.write_bytes('/etc/machine-id', b'0' * 32, 0o644)
        self.source = self.mkdir('/opt/erpc/runs/inert/authority', mode=0o755)
        for file in SOURCE.iterdir():
            if not file.is_file():
                continue
            self.write_bytes('/opt/erpc/runs/inert/authority/' + file.name, file.read_bytes(), 0o644)

    def command(self, *argv, **kwargs):
        if argv[:2] == ('/usr/bin/systemctl', '--version'):
            return subprocess.CompletedProcess(argv, 0, b'systemd 255\n', b'')
        if argv[0] == '/usr/bin/findmnt':
            if '--list' in argv:
                value = {'filesystems': [{'target': str(self.root)}]}
            else:
                value = {'filesystems': [{'target': str(self.root), 'uuid': 'fixture-volume', 'fstype': 'ext4', 'options': 'rw'}]}
            return subprocess.CompletedProcess(argv, 0, json.dumps(value).encode(), b'')
        if argv[0] == '/usr/sbin/groupadd':
            self.nss_calls.append('group')
            self.groups['arc'] = types.SimpleNamespace(gr_name='arc', gr_gid=int(argv[3]), gr_mem=[])
        elif argv[0] == '/usr/sbin/useradd':
            self.nss_calls.append('user')
            self.users['arc'] = types.SimpleNamespace(pw_name='arc', pw_uid=int(argv[3]), pw_gid=int(argv[5]),
                                                     pw_dir='/var/lib/arc', pw_shell='/usr/sbin/nologin')
        else:
            raise AssertionError(argv)
        return subprocess.CompletedProcess(argv, 0, b'', b'')


class Preparation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name).resolve()
        self.c = Host(self.root)
        self.stack = ExitStack()
        def named(collection, name):
            if name not in collection:
                raise KeyError(name)
            return collection[name]
        def number(collection, field, wanted):
            for value in collection.values():
                if getattr(value, field) == wanted:
                    return value
            raise KeyError(wanted)
        for function, value in (
            ('getpwall', lambda: list(self.c.users.values())),
            ('getpwnam', lambda name: named(self.c.users, name)),
            ('getpwuid', lambda uid: number(self.c.users, 'pw_uid', uid)),
        ):
            self.stack.enter_context(patch.object(accounts.pwd, function, value))
        for function, value in (
            ('getgrall', lambda: list(self.c.groups.values())),
            ('getgrnam', lambda name: named(self.c.groups, name)),
            ('getgrgid', lambda gid: number(self.c.groups, 'gr_gid', gid)),
        ):
            self.stack.enter_context(patch.object(accounts.grp, function, value))
        self.stack.enter_context(patch.object(accounts.os, 'getgrouplist', lambda name, gid: [gid]))
        self.stack.enter_context(patch.object(os, 'statvfs', lambda _: types.SimpleNamespace(f_bavail=3_000_000_000_000, f_frsize=1)))
        self.stack.enter_context(patch.object(control, '__file__', str(self.c.source / 'control.py')))
        self.contract = {'owner': 'i' * 26, 'network': 'testnet', 'chain_id': 5042002,
                         'genesis_hash': protocol.NETWORKS['testnet']['genesis_hash'],
                         'public_key': base64.b64encode(bytes([1]) * 32).decode(),
                         'rpc_type': 'full', 'host_key_sha256': 'a' * 64}
        self.request = {'schema': control.SCHEMA, 'action': 'prepare', 'contract': self.contract,
                        'helpers': helpers.source(self.c, self.c.source)[2]}

    def tearDown(self):
        self.stack.close()
        self.tmp.cleanup()

    def test_actual_prepare_qualifies_original_layout_before_nss_and_reuses_same_account(self):
        home = self.c.path('/var/lib/arc')
        home.mkdir(mode=0o700)
        (home / 'lost+found').mkdir(mode=0o700)
        ino = home.stat().st_ino
        self.assertTrue(self.c.dispatch({'schema': control.SCHEMA, 'action': 'preflight'})['fresh'])
        first = self.c.dispatch(self.request)
        self.assertTrue(first['prepared'])
        self.assertEqual(self.c.nss_calls, ['group', 'user'])
        self.assertEqual(home.stat().st_ino, ino)
        self.assertEqual(home.stat().st_mode & 0o777, 0o755)
        state = self.c.state(self.contract)
        self.assertTrue(state['account_established'])
        selected = self.c.path('/usr/local/lib/erpc/arc/current').resolve()
        self.assertEqual(selected.name, self.request['helpers'])
        self.assertEqual(helpers.source(self.c, selected)[2], selected.name)
        self.assertEqual(self.c.dispatch(self.request), first)
        self.assertEqual(self.c.nss_calls, ['group', 'user'])

    def test_visible_helper_rename_is_resynchronized_before_pointer_publication(self):
        real=os.fsync
        releases=self.c.path('/usr/local/lib/erpc/arc/releases')
        target=releases/self.request['helpers']
        def fail(fd):
            if releases.exists() and target.exists() and os.fstat(fd).st_ino==releases.stat().st_ino:
                raise OSError('inert helper parent sync fault')
            real(fd)
        with patch.object(os,'fsync',fail):
            for _ in range(3):
                with self.assertRaises(OSError):self.c.dispatch(self.request)
                self.assertFalse(self.c.path('/usr/local/lib/erpc/arc/current').exists())
                self.assertEqual(self.c.nss_calls,[])
        self.assertTrue(self.c.dispatch(self.request)['prepared'])
        self.assertEqual(self.c.path('/usr/local/lib/erpc/arc/current').resolve(),target)

    def test_actual_prepare_never_adopts_unknown_data_or_permission_drift(self):
        home = self.c.path('/var/lib/arc')
        home.mkdir(mode=0o755)
        (home / 'native-data').write_text('unowned')
        with self.assertRaises(Refused):
            self.c.dispatch(self.request)
        self.assertEqual(self.c.nss_calls, [])
        self.assertFalse(self.c.path(control.OWNER).exists())
        (home / 'native-data').unlink()
        self.c.dispatch(self.request)
        home.chmod(0o777)
        with self.assertRaises(Refused):
            self.c.dispatch(self.request)
        self.assertEqual(home.stat().st_mode & 0o777, 0o777)
        self.assertEqual(self.c.nss_calls, ['group', 'user'])

    def test_initial_receipt_sync_failure_refuses_nss_on_every_retry(self):
        real = os.fsync
        root_inode = self.c.ROOT.stat().st_ino
        def fail(fd):
            if os.fstat(fd).st_ino == root_inode:
                raise OSError('inert authority directory fsync fault')
            real(fd)
        with patch.object(os, 'fsync', fail):
            for _ in range(3):
                with self.assertRaises(OSError):
                    self.c.dispatch(self.request)
                self.assertEqual(self.c.nss_calls, [])
        state = self.c.json(control.OWNER)
        original = state['service_uid']
        self.assertEqual(self.c.dispatch(self.request)['uid'], original)
        self.assertEqual(self.c.nss_calls, ['group', 'user'])

    def test_standard_distribution_release_link_is_allowed_but_unknown_target_is_not(self):
        self.c.mkdir('/usr/lib', mode=0o755)
        original = self.c.path('/etc/os-release')
        original.rename(self.c.path('/usr/lib/os-release'))
        original.symlink_to('../usr/lib/os-release')
        self.c.platform()
        original.unlink()
        original.symlink_to('../other-release')
        with self.assertRaises(Refused):
            self.c.platform()
        self.assertEqual(self.c.nss_calls, [])

    def install_inert_units(self):
        self.c.dispatch(self.request)
        self.c.mkdir('/etc/systemd/system', mode=0o755)
        self.c.mkdir('/proc', mode=0o755)
        state = self.c.state(self.contract)
        state['stopped'] = []
        state['phase'] = 'running'
        state['intent'] = 'inert-delayed-deploy'
        self.c.save(state)
        self.commands = []
        original = self.c.command
        def command(*argv, **kwargs):
            if argv[0] == '/usr/bin/systemctl':
                self.commands.append(argv)
                return subprocess.CompletedProcess(argv, 0, b'', b'')
            return original(*argv, **kwargs)
        self.c.command = command
        text = {name: 'inert original ' + name + '\n' for name in units.UNITS}
        runtime = {name: {'binary': '/inert/' + name, 'sha256': 'a' * 64, 'argv': []} for name in units.UNITS}
        units.publish(self.c, state, text, runtime, {})
        self.commands.clear()
        return state

    def test_actual_stop_and_destroy_still_drain_after_primary_and_secondary_sync_failures(self):
        self.install_inert_units()
        root_inode = self.c.ROOT.stat().st_ino
        real = os.fsync
        for action in ('stop', 'destroy'):
            self.commands.clear()
            def fail(fd):
                if os.fstat(fd).st_ino == root_inode:
                    raise OSError('inert persistent cancellation synchronization fault')
                real(fd)
            with patch.object(os, 'fsync', fail), self.assertRaises(Refused):
                self.c.dispatch({'schema': control.SCHEMA, 'action': action,
                                 'contract': self.contract, 'layer': 'both'})
            self.assertEqual({row[-1] for row in self.commands if row[1] == 'stop'}, set(units.UNITS.values()))
            self.assertEqual({row[-1] for row in self.commands if row[1] == 'disable'}, set(units.UNITS.values()))
            retained = self.c.state(self.contract)
            self.assertNotIn('intent', retained)
            self.assertTrue(self.c.cancelled(retained, 'execution'))
            self.assertTrue(self.c.cancelled(retained, 'consensus'))
            self.assertTrue(self.c.path('/etc/erpc/arc/authority/units').is_dir())

    def test_consensus_only_stop_preserves_execution_while_foreign_contract_never_mutates(self):
        self.install_inert_units()
        bad = dict(self.contract, owner='z' * 26)
        with self.assertRaises(Refused):
            self.c.dispatch({'schema': control.SCHEMA, 'action': 'stop', 'contract': bad, 'layer': 'both'})
        self.assertEqual(self.commands, [])
        result = self.c.dispatch({'schema': control.SCHEMA, 'action': 'stop',
                                  'contract': self.contract, 'layer': 'consensus'})
        self.assertEqual(result['applied'], 'stopped')
        stopped = {row[-1] for row in self.commands if row[1] == 'stop'}
        self.assertEqual(stopped, {'arc-consensus.service', 'arc-snapshots.service'})
        state = self.c.state(self.contract)
        self.assertFalse(self.c.cancelled(state, 'execution'))
        self.assertTrue(self.c.cancelled(state, 'consensus'))



if __name__ == '__main__':
    unittest.main()
