#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""NSS and account commands are inert; original state is a real private tempfile."""
import os
from pathlib import Path
import sys
from types import SimpleNamespace as Record
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from validator_state import StateFailures
import accounts


class Accounts(unittest.TestCase):
    def setUp(self):
        StateFailures.setUp(self)
        self.users = {}; self.groups = {}; self.memberships = {}
        self.calls = []
        specs = {role: (name, str(self.root / role)) for role, (name, _) in accounts.SPECS.items()}
        patch.object(accounts, 'SPECS', specs).start()
        def lookup(values, match):
            for value in values:
                if match(value): return value
            raise KeyError('inert missing NSS entry')
        patch.object(accounts.pwd, 'getpwall', side_effect=lambda: list(self.users.values())).start()
        patch.object(accounts.grp, 'getgrall', side_effect=lambda: list(self.groups.values())).start()
        patch.object(accounts.pwd, 'getpwnam', side_effect=lambda name: lookup(self.users.values(), lambda v: v.pw_name == name)).start()
        patch.object(accounts.pwd, 'getpwuid', side_effect=lambda uid: lookup(self.users.values(), lambda v: v.pw_uid == uid)).start()
        patch.object(accounts.grp, 'getgrnam', side_effect=lambda name: lookup(self.groups.values(), lambda v: v.gr_name == name)).start()
        patch.object(accounts.grp, 'getgrgid', side_effect=lambda gid: lookup(self.groups.values(), lambda v: v.gr_gid == gid)).start()
        patch.object(accounts.os, 'getgrouplist', side_effect=lambda name, gid: self.memberships.get(name, [gid])).start()
        self.store.reserve(self.contract)

    def account_command(self, argv):
        self.assertTrue((self.path / 'accounts-intent.json').is_file())
        self.calls.append(argv)
        name = argv[-1]
        if argv[0] == '/usr/sbin/groupadd':
            self.groups[name] = Record(gr_name=name, gr_gid=int(argv[argv.index('--gid') + 1]), gr_mem=[])
        else:
            self.assertEqual(argv[0], '/usr/sbin/useradd')
            self.users[name] = Record(pw_name=name, pw_uid=int(argv[argv.index('--uid') + 1]),
                pw_gid=int(argv[argv.index('--gid') + 1]), pw_dir=argv[argv.index('--home-dir') + 1],
                pw_shell=argv[argv.index('--shell') + 1])

    def test_original_ids_are_reserved_before_creation_and_retries_do_not_recreate(self):
        records = accounts.ensure(self.store, self.contract, self.account_command)
        self.assertEqual(len(self.calls), 4)
        self.assertNotEqual(records['node']['uid'], records['transport']['uid'])
        self.assertEqual(accounts.ensure(self.store, self.contract, self.account_command), records)
        self.assertEqual(len(self.calls), 4)
        self.assertTrue(all(Path(v['home']).stat().st_mode & 0o777 == 0o755 for v in records.values()))

    def test_partial_group_creation_resumes_only_the_original_ids(self):
        def interrupted(argv):
            self.account_command(argv)
            if argv[0].endswith('groupadd'): raise OSError('inert after group creation')
        with self.assertRaises(OSError): accounts.ensure(self.store, self.contract, interrupted)
        original = self.store.get('accounts-intent.json')
        accounts.ensure(self.store, self.contract, self.account_command)
        self.assertEqual(self.store.get('accounts.json'), original)
        self.assertEqual(sum(argv[0].endswith('groupadd') for argv in self.calls), 2)

    def test_unknown_accounts_and_primary_gid_collisions_are_not_adopted_or_reserved(self):
        name, home = accounts.SPECS['node']
        self.users[name] = Record(pw_name=name, pw_uid=40000, pw_gid=40000, pw_dir=home, pw_shell=accounts.SHELL)
        with self.assertRaises(ValueError): accounts.ensure(self.store, self.contract, self.account_command)
        self.assertEqual(self.calls, []); self.assertFalse((self.path / 'accounts-intent.json').exists())
        self.users.clear()
        self.users['unrelated'] = Record(pw_name='unrelated', pw_uid=30000, pw_gid=20000, pw_dir='/inert', pw_shell='/bin/false')
        records = accounts.ensure(self.store, self.contract, self.account_command)
        self.assertNotIn(20000, [value['gid'] for value in records.values()])

    def test_direct_lookup_drift_and_supplementary_groups_refuse_but_retained_ids_survive(self):
        records = accounts.ensure(self.store, self.contract, self.account_command)
        node = records['node']; count = len(self.calls)
        wrong = Record(pw_name=node['name'], pw_uid=40000, pw_gid=40000, pw_dir=node['home'], pw_shell=node['shell'])
        with patch.object(accounts.pwd, 'getpwnam', return_value=wrong):
            with self.assertRaises(ValueError): accounts.verify(self.store, self.contract)
            self.assertEqual(accounts.retained(self.store, self.contract), records)
        self.memberships[node['name']] = [node['gid'], 998]
        with self.assertRaisesRegex(ValueError, 'supplementary'): accounts.verify(self.store, self.contract)
        self.assertEqual(accounts.retained(self.store, self.contract), records); self.assertEqual(len(self.calls), count)

    def test_visible_intent_requires_sync_before_any_nss_change(self):
        with patch.object(accounts, 'synchronize', side_effect=OSError('inert fsync failure')):
            with self.assertRaises(OSError): accounts.ensure(self.store, self.contract, self.account_command)
        self.assertEqual(self.calls, []); self.assertTrue((self.path / 'accounts-intent.json').exists())
        accounts.ensure(self.store, self.contract, self.account_command)
        self.assertEqual(len(self.calls), 4)

    def test_unknown_or_inaccessible_home_is_not_repaired_or_adopted(self):
        home = Path(accounts.SPECS['node'][1]); home.mkdir(mode=0o700)
        with self.assertRaises(ValueError): accounts.ensure(self.store, self.contract, self.account_command)
        self.assertEqual(home.stat().st_mode & 0o777, 0o700); self.assertEqual(self.calls, [])


if __name__ == '__main__':
    # StateFailures is imported as a shared fixture, not a second test target.
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(Accounts))
    result = unittest.TextTestRunner().run(suite)
    raise SystemExit(not result.wasSuccessful())
