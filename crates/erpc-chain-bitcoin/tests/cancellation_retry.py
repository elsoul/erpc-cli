# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Sole pending stop evidence survives failed replacement and retention barriers."""
import contextlib
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
import lifecycle
c=lifecycle.c


class Retry(unittest.TestCase):
    def pending_only(self,operation):
        fixture=lifecycle.HostTests('runTest');fixture.setUp()
        old=fixture.request('begin-install');fixture.begin(old)
        fixture.service='active'
        original_open=os.open;original_sync=os.fsync
        def no_cancellation(path,flags,*args,**kwargs):
            if Path(path)==c.ROOT/'cancelled.json.new' and flags&os.O_CREAT:
                raise OSError('inert cancellation creation failure')
            return original_open(path,flags,*args,**kwargs)
        def no_owner_sync(fd):
            candidate=c.ROOT/'owner.json.new'
            if candidate.exists() and os.fstat(fd).st_ino==candidate.stat().st_ino:
                raise OSError('inert pending owner file barrier failure')
            return original_sync(fd)
        with patch.object(c.os,'open',side_effect=no_cancellation),patch.object(c.os,'fsync',side_effect=no_owner_sync):
            with self.assertRaises(c.Refused):c.locked(fixture.request(operation))
        self.assertFalse((c.ROOT/'cancelled.json').exists())
        self.assertFalse((c.ROOT/'cancelled.json.new').exists())
        self.assertTrue((c.ROOT/'owner.json.new').is_file())
        self.assertEqual(fixture.service,'inactive')
        self.assertEqual(c.cancellation_record(),{'stopped':True,'generation':2,'retired':operation=='destroy'})
        return fixture,old

    @contextlib.contextmanager
    def fault(self,point,history=False):
        original_open=os.open;original_fdopen=os.fdopen;original_sync=os.fsync
        original_replace=os.replace;original_unlink=Path.unlink
        tripped=[];renamed=[]
        def selected(path):
            path=Path(path)
            return path.parent==c.ROOT/'cancellation-history' if history else path==c.ROOT/'owner.json.new'
        def trip():tripped.append(point);raise OSError('inert '+point+' interruption')
        def opening(path,flags,*args,**kwargs):
            if point=='open' and flags&os.O_CREAT and selected(path):trip()
            return original_open(path,flags,*args,**kwargs)
        def unlinking(path,*args,**kwargs):
            if point=='unlink' and selected(path):trip()
            return original_unlink(path,*args,**kwargs)
        def fd_selected(fd):
            info=os.fstat(fd)
            parent=c.ROOT/'cancellation-history'
            candidates=list(parent.glob('*.new')) if history and parent.exists() else [c.ROOT/'owner.json.new']
            return any(path.exists() and path.stat().st_ino==info.st_ino and selected(path) for path in candidates)
        def opening_stream(fd,*args,**kwargs):
            stream=original_fdopen(fd,*args,**kwargs)
            if point!='write' or not fd_selected(fd):return stream
            class Partial:
                def __enter__(self):return self
                def __exit__(self,*exc):return stream.__exit__(*exc)
                def __getattr__(self,name):return getattr(stream,name)
                def write(self,value):
                    stream.write(value[:13]);stream.flush();trip()
            return Partial()
        def replacing(source,destination,*args,**kwargs):
            target=selected(source)
            if point=='rename' and target:trip()
            result=original_replace(source,destination,*args,**kwargs)
            if target:renamed.append(Path(destination))
            return result
        def syncing(fd):
            if point=='fsync' and fd_selected(fd):trip()
            if point=='directory':
                directory=c.ROOT/'cancellation-history' if history else c.ROOT
                # A completed retained record is also re-synced on retries.
                published=renamed or (history and directory.exists() and list(directory.glob('*.json')))
                if published and os.fstat(fd).st_ino==directory.stat().st_ino:trip()
            return original_sync(fd)
        with contextlib.ExitStack() as stack:
            for owner,name,replacement in [(c.os,'open',opening),(c.os,'fdopen',opening_stream),
                    (c.os,'replace',replacing),(c.os,'fsync',syncing),(Path,'unlink',unlinking)]:
                stack.enter_context(patch.object(owner,name,replacement))
            yield tripped

    def assert_replay_refused(self,fixture,old,operation):
        fence=c.cancellation_record()
        self.assertTrue(fence['stopped']);self.assertGreaterEqual(c.generation(c.read_state()),2)
        if operation=='destroy':self.assertTrue(fence['retired'])
        fixture.calls.clear()
        for action in ('prepare','begin-install','install-artifacts','activate','authorize'):
            with self.assertRaises(c.Refused):c.locked(dict(old,action=action))
        self.assertEqual(fixture.calls,[])
        self.assertEqual((c.ROOT/'data/chainstate-fixture').read_text(),'persistent-state')

    def recover(self,fixture,old,operation):
        c.locked(fixture.request('stop'))
        if operation=='destroy':self.assertEqual(c.read_state()['phase'],'retired')
        self.assert_replay_refused(fixture,old,operation)
        fresh=fixture.request('begin-install',generation=c.generation(c.read_state()))
        fresh['intent']='e'*32;fixture.begin(fresh)
        c.locked(dict(fresh,action='install-artifacts'));c.locked(dict(fresh,action='activate'))
        self.assertEqual(fixture.service,'active');self.assertFalse(c.stopped())
        self.assertFalse(any((c.ROOT/'cancellation-history').iterdir()))
        with self.assertRaises(c.Refused):c.locked(dict(old,action='activate'))

    def test_replacement_failures_preserve_sole_pending_stop_and_retirement(self):
        for operation in ('stop','destroy'):
            for retry in ('authorize','stop'):
                for point in ('unlink','open','write','fsync','rename','directory'):
                    with self.subTest(operation=operation,retry=retry,point=point):
                        fixture,old=self.pending_only(operation)
                        try:
                            new=fixture.request(retry,generation=c.generation(c.read_state()));new['intent']='d'*32
                            with self.fault(point) as tripped,self.assertRaises((OSError,c.Refused)):
                                c.locked(new)
                            self.assertTrue(tripped)
                            self.assert_replay_refused(fixture,old,operation)
                            self.recover(fixture,old,operation)
                        finally:fixture.doCleanups()

    def test_retained_publication_failures_never_delete_the_original_pending_file(self):
        for operation in ('stop','destroy'):
            for retry in ('authorize','stop'):
                for point in ('open','write','fsync','rename','directory'):
                    with self.subTest(operation=operation,retry=retry,point=point):
                        fixture,old=self.pending_only(operation)
                        try:
                            pending=(c.ROOT/'owner.json.new').read_bytes()
                            new=fixture.request(retry,generation=c.generation(c.read_state()));new['intent']='d'*32
                            with self.fault(point,history=True) as tripped:
                                for _ in range(2):
                                    if retry=='stop':fixture.service='active'
                                    with self.assertRaises((OSError,c.Refused)):c.locked(new)
                                    if retry=='stop':self.assertEqual(fixture.service,'inactive')
                                    self.assertEqual((c.ROOT/'owner.json.new').read_bytes(),pending)
                                    self.assert_replay_refused(fixture,old,operation)
                            self.assertTrue(tripped)
                            self.recover(fixture,old,operation)
                        finally:fixture.doCleanups()


if __name__=='__main__':unittest.main()
