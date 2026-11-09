# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual receipt/fsync failures with modeled NSS; never creates host accounts."""
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).parents[1] / 'templates/aqa'))
import erpc_aqa_common as common
import erpc_aqa_accounts as setup
import erpc_aqa_state as lifecycle


class Accounts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.state = lifecycle.State(self.root)
        self.users, self.groups, self.calls = {}, {}, []
        self.patches = []
        def install(obj, name, value):
            item = patch.object(obj, name, value, create=True)
            item.start(); self.patches.append(item)
        def get(records, field, value):
            for record in records.values():
                if getattr(record, field) == value: return record
            raise KeyError(value)
        for module, methods, records in ((setup.pwd, ('getpwnam', 'getpwuid', 'getpwall'), self.users),
                                         (setup.grp, ('getgrnam', 'getgrgid', 'getgrall'), self.groups)):
            prefix = 'pw' if module is setup.pwd else 'gr'
            install(module, methods[0], lambda value, r=records, p=prefix: get(r, p+'_name', value))
            install(module, methods[1], lambda value, r=records, p=prefix: get(r, p+('_uid' if p == 'pw' else '_gid'), value))
            install(module, methods[2], lambda r=records: list(r.values()))
        install(setup.os, 'getgrouplist', lambda name, gid: [gid])
        install(setup, 'execute', self.command)
        install(lifecycle, 'read', lambda path: common.read(path, owner=os.getuid()))

    def tearDown(self):
        for item in reversed(self.patches): item.stop()
        self.temporary.cleanup()

    def command(self, argv):
        self.calls.append(argv)
        name = argv[-1]
        if argv[0].endswith('groupadd'):
            self.groups[name] = SimpleNamespace(gr_name=name, gr_gid=int(argv[argv.index('--gid')+1]), gr_mem=[])
        else:
            self.users[name] = SimpleNamespace(pw_name=name, pw_uid=int(argv[argv.index('--uid')+1]),
                pw_gid=int(argv[argv.index('--gid')+1]), pw_dir=argv[argv.index('--home-dir')+1], pw_shell='/usr/sbin/nologin')

    def test_visible_reservation_never_authorizes_nss_until_directory_sync_recovers(self):
        original = os.fsync
        def failed(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode): raise OSError('inert directory fsync failure')
            original(fd)
        with patch.object(os, 'fsync', side_effect=failed):
            for _ in range(2):
                with self.assertRaises(OSError): setup.provision_accounts(self.state)
                self.assertEqual(self.calls, [])
                self.assertTrue((self.root/'account-reservation.json').exists())
        reserved = self.state.get('account-reservation.json')
        self.assertEqual(setup.provision_accounts(self.state), reserved)
        self.assertEqual(len(self.calls), 2)

    def test_completed_visible_receipt_is_resynchronized_and_never_recreates_accounts(self):
        original = os.fsync
        def failed(fd):
            if (self.root/'accounts.json').exists() and stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError('inert completed receipt persistence failure')
            original(fd)
        with patch.object(os, 'fsync', side_effect=failed):
            for _ in range(2):
                with self.assertRaises(OSError): setup.provision_accounts(self.state)
                self.assertEqual(len(self.calls), 2)
        expected = self.state.get('account-reservation.json')
        self.assertEqual(setup.provision_accounts(self.state), expected)
        self.assertEqual(len(self.calls), 2)

    def test_hidden_numeric_identity_and_primary_group_usage_are_not_allocated(self):
        self.users['other'] = SimpleNamespace(pw_name='other',pw_uid=4000,pw_gid=999,pw_dir='/inert',pw_shell='/bin/sh')
        original = setup.pwd.getpwuid
        hidden = SimpleNamespace(pw_name='directory-user',pw_uid=998)
        with patch.object(setup.pwd,'getpwuid',side_effect=lambda uid: hidden if uid==998 else original(uid)):
            result=setup.provision_accounts(self.state)
        self.assertEqual(result[setup.NATIVE]['uid'],997)

    def test_direct_numeric_profile_or_enumerated_alias_drift_refuses_without_repair(self):
        result=setup.provision_accounts(self.state)
        count=len(self.calls);name=setup.NATIVE;uid=result[name]['uid']
        original=setup.pwd.getpwuid
        wrong=SimpleNamespace(**dict(vars(self.users[name]),pw_dir='/inert/changed'))
        with patch.object(setup.pwd,'getpwuid',side_effect=lambda number: wrong if number==uid else original(number)):
            with self.assertRaises(ValueError): setup.provision_accounts(self.state)
        self.groups['alias']=SimpleNamespace(gr_name='alias',gr_gid=result[name]['gid'],gr_mem=[])
        with self.assertRaises(ValueError): setup.provision_accounts(self.state)
        self.assertEqual(len(self.calls),count)


if __name__ == '__main__': unittest.main()
