#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual account/receipt helpers over inert NSS and a private filesystem."""
import copy
import contextlib
import os
import pathlib
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.dont_write_bytecode = True
TEMPLATES = pathlib.Path(__file__).resolve().parents[1] / 'templates'
sys.path[:0] = [str(TEMPLATES / 'validator'), str(TEMPLATES / 'authority')]
import av_accounts as accounts
from av_files import Files, HOME, ROOT
from arc_files import Refused


def user(name, number, home, gid=None):
    return types.SimpleNamespace(pw_name=name, pw_uid=number, pw_gid=number if gid is None else gid,
                                 pw_dir=home, pw_shell='/usr/sbin/nologin')


def group(name, number, members=()):
    return types.SimpleNamespace(gr_name=name, gr_gid=number, gr_mem=list(members))


class Accounts(unittest.TestCase):
    def setUp(self):
        self.patches = contextlib.ExitStack()
        self.addCleanup(self.patches.close)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        self.users, self.groups, self.commands = [], [], []
        self.context = Files(self.root, owner=os.getuid(), run=self.run_command)
        self.context.mkdir(ROOT)
        def find(rows, field, value):
            for row in rows:
                if getattr(row, field) == value:
                    return row
            raise KeyError(value)
        for name, function in {
            'getpwall': lambda: list(self.users),
            'getpwnam': lambda value: find(self.users, 'pw_name', value),
            'getpwuid': lambda value: find(self.users, 'pw_uid', value),
        }.items():
            self.patches.enter_context(mock.patch.object(accounts.pwd, name, function))
        for name, function in {
            'getgrall': lambda: list(self.groups),
            'getgrnam': lambda value: find(self.groups, 'gr_name', value),
            'getgrgid': lambda value: find(self.groups, 'gr_gid', value),
        }.items():
            self.patches.enter_context(mock.patch.object(accounts.grp, name, function))
        self.patches.enter_context(mock.patch.object(accounts.os, 'getgrouplist', lambda name, primary:
                          [primary] + [row.gr_gid for row in self.groups if name in row.gr_mem]))

    def run_command(self, command, **_kwargs):
        self.commands.append(command)
        name = command[-1]
        if command[0] == '/usr/sbin/groupadd':
            self.groups.append(group(name, int(command[command.index('--gid') + 1])))
        elif command[0] == '/usr/sbin/useradd':
            self.users.append(user(name, int(command[command.index('--uid') + 1]),
                                   command[command.index('--home-dir') + 1]))
            self.groups[0].gr_mem.append(name)
        else:
            raise AssertionError('unexpected host command')
        return types.SimpleNamespace(returncode=0, stdout=b'', stderr=b'')

    def prepare(self):
        state = {'accounts': accounts.reserve()}
        self.context.save(state)
        accounts.provision(self.context, state)
        return state

    def test_reservation_precedes_nss_and_slots_cannot_read_each_others_private_group(self):
        old = os.umask(0o077)
        try:
            state = self.prepare()
        finally:
            os.umask(old)
        self.assertEqual(len(self.commands), 5)
        self.assertEqual(self.context.json(ROOT + '/owner.json'), state)
        accounts.verify(state['accounts'])
        self.assertEqual(len(set(state['accounts'][name] for name in ('execution', 'consensus', 'engine'))), 3)
        self.assertEqual(set(self.groups[0].gr_mem), set(accounts.SLOTS.values()))
        self.assertTrue(all(not row.gr_mem for row in self.groups[1:]))

    def test_unknown_name_and_primary_gid_are_not_adopted(self):
        self.users.append(user('existing', 500, '/nonexistent', gid=999))
        self.assertNotIn(999, accounts.reserve().values())
        self.users.append(user('erpc-arc-cl', 800, HOME + '/consensus'))
        with self.assertRaises(Refused):
            accounts.reserve()
        self.assertEqual(self.commands, [])

    def test_first_receipt_sync_failure_never_mutates_nss_even_on_visible_retry(self):
        state = {'accounts': accounts.reserve()}
        actual = os.fsync
        def fail(descriptor):
            if os.fstat(descriptor).st_ino == self.context.ROOT.stat().st_ino:
                raise OSError('inert persistent receipt directory failure')
            return actual(descriptor)
        with mock.patch.object(os, 'fsync', fail):
            for _ in range(3):
                with self.assertRaises(OSError):
                    accounts.provision(self.context, state)
                self.assertEqual(self.commands, [])
        accounts.provision(self.context, state)
        self.assertEqual(len(self.commands), 5)

    def test_partial_nss_mutation_reuses_original_numbers(self):
        state = {'accounts': accounts.reserve()}
        original = copy.deepcopy(state['accounts'])
        perform = self.context.command
        count = 0
        def interruption(*args, **kwargs):
            nonlocal count
            count += 1
            if count == 4:
                raise OSError('inert interruption')
            return perform(*args, **kwargs)
        with mock.patch.object(self.context, 'command', interruption):
            with self.assertRaises(OSError):
                accounts.provision(self.context, state)
        resumed = self.context.json(ROOT + '/owner.json')
        accounts.provision(self.context, resumed)
        self.assertEqual({name: resumed['accounts'][name] for name in ('execution', 'consensus', 'engine')},
                         {name: original[name] for name in ('execution', 'consensus', 'engine')})
        self.assertEqual(len(self.commands), 5)

    def test_missing_established_account_and_extra_groups_refuse_without_recreation(self):
        state = self.prepare()
        original = list(self.users)
        self.users.pop()
        with self.assertRaises(Refused):
            accounts.provision(self.context, state)
        self.users[:] = original
        self.groups.append(group('foreign', 800, ['erpc-arc-cl']))
        with self.assertRaises(Refused):
            accounts.verify(state['accounts'])
        self.assertEqual(len(self.commands), 5)

    def test_name_id_lookup_disagreement_and_duplicate_uid_refuse(self):
        state = self.prepare()
        with mock.patch.object(accounts.pwd, 'getpwuid', return_value=None):
            with self.assertRaises(Refused):
                accounts.verify(state['accounts'])
        self.users.append(user('alias', state['accounts']['execution'], '/nonexistent'))
        with self.assertRaises(Refused):
            accounts.verify(state['accounts'])

    def test_shared_engine_group_cannot_have_extra_or_missing_members(self):
        state = self.prepare()
        original = list(self.groups[0].gr_mem)
        for members in [[], original + ['foreign']]:
            self.groups[0].gr_mem = members
            with self.assertRaises(Refused):
                accounts.verify(state['accounts'])


if __name__ == '__main__':
    unittest.main()
