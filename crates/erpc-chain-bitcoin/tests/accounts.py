# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original numeric reservation with inert NSS/commands and real durable files."""
import copy
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0,str(Path(__file__).parent))
import lifecycle
c = lifecycle.c


class Accounts(unittest.TestCase):
    def setUp(self):
        self.fixture = lifecycle.HostTests('runTest'); self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.state = c.read_state()
        for name in ('account-intent.json','account.json','native-releases.json','source-floor.json'):
            (c.ROOT/name).unlink()
        self.users = {}; self.groups = {}; self.calls = []
        self.extra_groups = []
        def user(row):
            return SimpleNamespace(pw_name=row['name'],pw_uid=row['uid'],pw_gid=row['gid'],
                                   pw_dir=row['home'],pw_shell=row['shell'])
        def group(row):
            return SimpleNamespace(gr_name=row['name'],gr_gid=row['gid'],gr_mem=row['members'])
        def named(rows,name,convert):
            if name not in rows: raise KeyError(name)
            return convert(rows[name])
        def numbered(rows,field,value,convert):
            found = next((row for row in rows.values() if row[field]==value),None)
            if found is None: raise KeyError(value)
            return convert(found)
        patch.object(c.pwd,'getpwall',side_effect=lambda:[user(row) for row in self.users.values()]).start()
        patch.object(c.grp,'getgrall',side_effect=lambda:[group(row) for row in self.groups.values()]).start()
        patch.object(c.pwd,'getpwnam',side_effect=lambda name:named(self.users,name,user)).start()
        patch.object(c.grp,'getgrnam',side_effect=lambda name:named(self.groups,name,group)).start()
        patch.object(c.pwd,'getpwuid',side_effect=lambda value:numbered(self.users,'uid',value,user)).start()
        patch.object(c.grp,'getgrgid',side_effect=lambda value:numbered(self.groups,'gid',value,group)).start()
        patch.object(c.os,'getgrouplist',side_effect=lambda name,gid:[gid,*self.extra_groups]).start()
        def command(argv,**_kwargs):
            self.calls.append(argv)
            if argv[0]=='/usr/sbin/groupadd':
                self.groups[argv[-1]]={'name':argv[-1],'gid':int(argv[argv.index('--gid')+1]),'members':[]}
            elif argv[0]=='/usr/sbin/useradd':
                self.users[argv[-1]]={'name':argv[-1],'uid':int(argv[argv.index('--uid')+1]),
                    'gid':int(argv[argv.index('--gid')+1]),'home':argv[argv.index('--home-dir')+1],
                    'shell':argv[argv.index('--shell')+1]}
            else: raise AssertionError(argv)
            return b''
        self.command = command
        patch.object(c,'run',side_effect=command).start()

    def test_original_numeric_reservation_precedes_nss_and_retry_reuses_the_same_identity(self):
        def interrupted(argv,**kwargs):
            self.assertTrue((c.ROOT/'account-intent.json').exists())
            result = self.command(argv,**kwargs)
            if argv[0]=='/usr/sbin/groupadd': raise c.Refused('inert interrupted group completion')
            return result
        with patch.object(c,'run',side_effect=interrupted), self.assertRaises(c.Refused):
            c.account_ensure(self.state)
        original = (c.ROOT/'account-intent.json').read_bytes()
        self.assertFalse((c.ROOT/'account.json').exists())
        record = c.account_ensure(self.state)
        self.assertEqual((c.ROOT/'account-intent.json').read_bytes(),original)
        self.assertEqual([call[0] for call in self.calls],['/usr/sbin/groupadd','/usr/sbin/useradd'])
        self.assertEqual(c.verified_account(self.state),record)

    def test_persistent_directory_sync_failure_refuses_nss_on_every_retry(self):
        real = os.fsync
        def failure(fd):
            if os.fstat(fd).st_ino == c.ROOT.stat().st_ino:
                raise OSError('inert original reservation barrier')
            return real(fd)
        with patch.object(c.os,'fsync',side_effect=failure):
            for _ in range(3):
                with self.assertRaises(OSError): c.account_ensure(self.state)
                self.assertEqual(self.calls,[])
        original = (c.ROOT/'account-intent.json').read_bytes()
        c.account_ensure(self.state)
        self.assertEqual((c.ROOT/'account-intent.json').read_bytes(),original)

    def test_allocation_excludes_primary_gids_and_keyed_only_numeric_owners(self):
        self.users['unrelated']={'name':'unrelated','uid':1500,'gid':20000,'home':'/nonexistent','shell':'/usr/sbin/nologin'}
        original = c.pwd.getpwuid
        with patch.object(c.pwd,'getpwuid',side_effect=lambda uid:SimpleNamespace(pw_uid=uid) if uid==20001 else original(uid)):
            self.assertEqual(c.account_plan()['uid'],20002)
        with patch.object(c.pwd,'getpwnam',return_value=SimpleNamespace(pw_name=c.ACCOUNT_NAME)), self.assertRaises(c.Refused):
            c.account_plan()
        self.assertEqual(self.calls,[])

    def test_name_id_home_shell_and_supplementary_group_drift_never_replace_original_authority(self):
        original = c.account_ensure(self.state)
        self.calls.clear()
        for field,value in [('uid',original['uid']+1),('gid',original['gid']+1),('home','/changed'),('shell','/bin/sh')]:
            saved = copy.deepcopy(self.users[c.ACCOUNT_NAME])
            self.users[c.ACCOUNT_NAME][field] = value
            with self.assertRaises(c.Refused): c.verified_account(self.state)
            self.assertEqual(c.retained_account(self.state),original)
            self.users[c.ACCOUNT_NAME] = saved
        self.extra_groups = [500]
        with self.assertRaises(c.Refused): c.verified_account(self.state)
        self.assertEqual(self.calls,[])

    def test_keyed_lookup_disagreement_or_unavailable_nss_fails_closed(self):
        c.account_ensure(self.state); self.calls.clear()
        with patch.object(c.pwd,'getpwuid',side_effect=KeyError), self.assertRaises(c.Refused):
            c.verified_account(self.state)
        with patch.object(c.grp,'getgrgid',side_effect=OSError('inert NSS unavailable')), self.assertRaises(OSError):
            c.verified_account(self.state)
        self.assertEqual(self.calls,[])


if __name__ == '__main__': unittest.main()
