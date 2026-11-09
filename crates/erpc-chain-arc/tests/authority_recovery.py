#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual controller publication interruptions; no native node or operational key."""
import os
import pathlib
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).parent))
import authority_lifecycle as lifecycle
import authority_migration as migration_fixture
import arc_custody as custody
import arc_files as files


class Recovery(unittest.TestCase):
    def fixture(self, cls=lifecycle.Lifecycle):
        value = cls('runTest')
        value.setUp()
        return value

    def test_every_promotion_receipt_publication_can_resume_without_replacing_data_or_key(self):
        # Discover actual controller writes, then interrupt both sides of each write.
        count = []
        f = self.fixture()
        try:
            f.install(); f.native_snapshot()
            write = f.c.write_bytes
            def observe(*args, **kwargs):
                count.append(args[0]); return write(*args, **kwargs)
            with patch.object(f.c, 'write_bytes', observe): f.call('activate', intent=f.intent)
        finally: f.tearDown()
        self.assertGreater(len(count), 3)
        for position in range(len(count)):
            for after in (False, True):
                with self.subTest(position=position, after=after, file=count[position]):
                    f = self.fixture()
                    try:
                        f.install(); f.native_snapshot()
                        stage = f.c.path('/var/lib/arc/bootstrap')
                        original = {name: (stage/name).stat().st_ino for name in ('execution','consensus')}
                        cipher = f.c.read(custody.CREDENTIAL)
                        write, calls = f.c.write_bytes, []
                        def interrupted(*args, **kwargs):
                            index = len(calls); calls.append(args[0])
                            if index == position and not after: raise OSError('inert before publication')
                            result = write(*args, **kwargs)
                            if index == position and after: raise OSError('inert after publication')
                            return result
                        with patch.object(f.c, 'write_bytes', interrupted), self.assertRaises(OSError):
                            f.call('activate', intent=f.intent)
                        f.call('stop', layer='both')
                        f.intent = 'c'*32
                        f.install(); f.call('activate', intent=f.intent)
                        for name, inode in original.items():
                            self.assertEqual((f.c.path('/var/lib/arc')/name).stat().st_ino, inode)
                        self.assertEqual(f.c.read(custody.CREDENTIAL), cipher)
                    finally: f.tearDown()

    def test_original_receipt_persistent_directory_sync_failure_never_promotes_restore(self):
        f = self.fixture()
        try:
            old = f.c.read(custody.CREDENTIAL)
            f.c.cipher = b'inert different seal of the same public test vector'
            real_sync = os.fsync
            root = f.real_stat(f.c.ROOT)
            def refuse_root(fd):
                info = f.real_fstat(fd)
                if ((info.st_dev,info.st_ino)==(root.st_dev,root.st_ino) and
                        f.c.state(f.contract)['credential']['sha256']==files.digest(f.c.cipher)):
                    raise OSError('inert persistent authority directory failure')
                return real_sync(fd)
            # The standalone restore function begins after caller shutdown, so this
            # targets its post-rename receipt barrier rather than cancellation.
            for _ in range(3):
                state = f.c.state(f.contract)
                with patch.object(os,'fsync',refuse_root), self.assertRaises(OSError):
                    custody.restore_original(f.c,state,b'inert public vector')
                self.assertEqual(f.c.read(custody.CREDENTIAL),old)
                self.assertEqual(f.c.state(f.contract)['credential']['sha256'],files.digest(f.c.cipher))
            result = f.call('credential-restore',key={'fixture':'public inert vector'})
            self.assertEqual(result['public_key'],f.public)
            self.assertEqual(f.c.read(custody.CREDENTIAL),f.c.cipher)
            retained = '/etc/erpc/arc/authority/cipher-history/'+files.digest(old)+'.cred'
            self.assertEqual(f.c.read(retained),old)
        finally: f.tearDown()

    def test_each_migration_publication_retains_original_account_data_and_cipher(self):
        count=[]
        f=self.fixture(migration_fixture.Migration)
        try:
            result=f.c.dispatch(f.migration_request);f.c.write_bytes(result['archive'],f.archive)
            write=f.c.write_bytes
            def observe(*args,**kwargs): count.append(args[0]);return write(*args,**kwargs)
            with patch.object(f.c,'write_bytes',observe):f.c.dispatch(dict(f.migration_request,action='migrate'))
        finally:f.tearDown()
        self.assertGreater(len(count),20)
        for position in range(len(count)):
            with self.subTest(position=position,file=count[position]):
                f=self.fixture(migration_fixture.Migration)
                try:
                    original=f.c.path('/var/lib/arc').stat().st_ino
                    key=f.c.read(custody.CREDENTIAL)
                    result=f.c.dispatch(f.migration_request);f.c.write_bytes(result['archive'],f.archive)
                    write,calls=f.c.write_bytes,[]
                    def interrupted(*args,**kwargs):
                        index=len(calls);calls.append(args[0]);result=write(*args,**kwargs)
                        if index==position:raise OSError('inert migration post-publication failure')
                        return result
                    with patch.object(f.c,'write_bytes',interrupted),self.assertRaises(OSError):
                        f.c.dispatch(dict(f.migration_request,action='migrate'))
                    f.migrate()
                    state=f.c.state(f.contract)
                    self.assertTrue(state['retired'] and state['migrated'])
                    self.assertEqual(state['service_uid'],f.evidence['uid'])
                    self.assertEqual(f.c.path('/var/lib/arc').stat().st_ino,original)
                    self.assertEqual(f.c.read(custody.CREDENTIAL),key)
                    self.assertEqual(f.c.path('/var/lib/arc/execution/db/mdbx.dat').read_bytes(),b'original legacy block history')
                finally:f.tearDown()


if __name__=='__main__':unittest.main()
