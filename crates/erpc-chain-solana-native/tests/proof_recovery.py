#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Real controller recovery and file durability faults; native/PID1 remain inert."""
import os
from pathlib import Path
import stat
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parent))
from activation import Activation
import native_proof as proof
import native_files as files
import native_state as lifecycle


class Host:
    def __init__(self):
        self.fixture=Activation();self.fixture.setUp()
        self.fixture.proof_stop_patch.stop()
        self.state=self.fixture.state;self.contract=self.fixture.contract
        self.node_command=self.fixture.inner.command
        self.fixture.inner.command=self.command
        self.starts=[];self.stops=[]
        patch.object(proof,'OUTPUT',self.state.directory).start()
        patch.object(proof,'root_directory',lambda *_args,**_kwargs:None).start()
        patch.object(proof,'read',lambda p,n=1048576,owner=0:files.read(p,n,os.getuid())).start()
        patch.object(proof,'sync_file',lambda p:files.sync_file(p,os.getuid())).start()
        def identity(_state,_contract,role):
            return dict(self.fixture.identity) if role=='validator' else {'public':'5'*44,'cipher_sha256':'e'*64}
        patch.object(proof.custody,'complete',side_effect=identity).start()
        self.cipher=self.fixture.inner.root/'original-encrypted-identity'
        self.cipher.write_bytes(b'inert encrypted identity must remain unchanged')

    def close(self):self.fixture.doCleanups()

    def command(self,args,**kwargs):
        if len(args)<2 or args[1]!=proof.UNIT:return self.node_command(args,**kwargs)
        path=proof.runtime.UNITS/proof.UNIT
        if args[0]=='show':
            if args[-2:]==['--property=LoadState','--value']:return 'loaded\n' if path.exists() else 'not-found\n'
            rows=dict(line.split('=',1) for line in path.read_text().splitlines() if '=' in line)
            values={'LoadState':'loaded','FragmentPath':str(path),'DropInPaths':'','User':rows['User'],
                    'Group':rows['Group'],'NeedDaemonReload':'no','MainPID':'0','ActiveState':'inactive',
                    'Result':'success','ExecMainStatus':'0'}
            return ''.join(k+'='+v+'\n' for k,v in values.items())
        if args[0]=='stop':self.stops.append(path.read_bytes());return ''
        if args[0]=='start':
            proof.guard(self.state,self.contract,self.command)
            self.starts.append(path.read_bytes())
            rows=dict(line.split('=',1) for line in path.read_text().splitlines() if '=' in line)
            output=Path(rows['StandardOutput'].removeprefix('truncate:'))
            output.write_text(self.fixture.policy['bls']+'\n');output.chmod(0o600)
            return ''
        raise AssertionError('unexpected inert proof command')

    def first_then_new(self,legacy=False):
        value=self.fixture
        value.authorize();value.dispatch('begin-runtime')
        if legacy:
            # The previous publisher had one current receipt, without retained
            # definitions. Model that format at creation, not by repairing or
            # deleting state after a publication failure.
            with patch.object(proof,'retain',return_value=None):value.dispatch('prove-validator')
        else:value.dispatch('prove-validator')
        self.old=self.state.get(proof.RECEIPT);self.old_unit=(proof.runtime.UNITS/proof.UNIT).read_bytes()
        value.dispatch('recover-cutover')
        value.inner.intent='6'*32;value.inner.request=dict(value.inner.request,intent=value.inner.intent)
        value.inner.completed_candidate()
        name='candidate-'+value.inner.intent+'.json';candidate=self.state.get(name)
        candidate['files']={'solana-keygen':{'sha256':'d'*64,'size':100}};self.state.put(name,candidate)
        value.inner.dispatch('begin-runtime');value.inner.dispatch('install-runtime',firewall={'run':'next-sync','bundle':'4'*64})
        value.inner.dispatch('activate-runtime')
        value.intent='7'*32;value.request=dict(value.request,intent=value.intent)
        value.authorize();value.dispatch('begin-runtime')
        self.starts.clear();self.stops.clear()

    def derive(self):return self.fixture.dispatch('prove-validator')


class PublicationRecovery(unittest.TestCase):
    def host(self,legacy=False):
        value=Host();self.addCleanup(value.close);value.first_then_new(legacy);return value

    def faults(self,kind,position,action):
        calls=[];real_sync=os.fsync;real_replace=os.replace;real_atomic=files.atomic
        def hit(detail):
            calls.append(detail)
            if len(calls)==position:raise OSError('inert publication fault')
        def sync(fd):
            if kind=='fsync':hit('directory' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'file')
            return real_sync(fd)
        def replace(source,destination):
            if kind=='rename-before':hit(Path(destination).name)
            result=real_replace(source,destination)
            if kind=='rename-after':hit(Path(destination).name)
            return result
        def atomic(path,raw,mode=0o600):
            if kind=='write':hit(path.name)
            return real_atomic(path,raw,mode)
        with patch.object(os,'fsync',sync),patch.object(os,'replace',replace), \
             patch.object(lifecycle,'atomic',atomic),patch.object(proof,'atomic',atomic):action()
        return calls

    def test_each_write_rename_and_file_directory_sync_failure_keeps_retry_and_recovery(self):
        for kind in ('write','rename-before','rename-after','fsync'):
            baseline=self.host(legacy=True)
            events=self.faults(kind,0,baseline.derive)
            baseline.close()
            self.assertTrue(events)
            print('proof publication:',kind,len(events),'fault points, each with retry and recovery')
            for position in range(1,len(events)+1):
                for continuation in ('retry','recover'):
                    with self.subTest(kind=kind,position=position,continuation=continuation):
                        host=self.host(legacy=True);original=host.cipher.read_bytes()
                        with self.assertRaises(OSError):self.faults(kind,position,host.derive)
                        unit=proof.runtime.UNITS/proof.UNIT
                        # Stale authority can stop its exact original unit;
                        # it must never satisfy this new activation's guard.
                        if unit.read_bytes()==host.old_unit:
                            with self.assertRaises(ValueError):proof.guard(host.state,host.contract,host.command)
                        proof.stop(host.state,host.contract,host.command)
                        self.assertTrue(host.stops)
                        if continuation=='retry':
                            self.assertEqual(host.derive()['intent'],'7'*32)
                        else:
                            self.assertTrue(host.fixture.dispatch('recover-cutover')['recovered'])
                            self.assertFalse((host.state.directory/'cutover.json').exists())
                            with self.assertRaises(ValueError):host.derive()
                        self.assertEqual(host.cipher.read_bytes(),original)
                        self.assertEqual((host.state.directory/'retained-history').read_text(),'keep original native history')
                        retained=host.state.directory/proof.retained_name(host.old)
                        self.assertEqual(host.state.get(retained.name) if retained.exists() else host.state.get(proof.RECEIPT),host.old)
                        host.close()

    def test_retained_unit_can_stop_but_neither_it_nor_unknown_bytes_can_start(self):
        host=self.host();host.derive();path=proof.runtime.UNITS/proof.UNIT
        path.write_bytes(host.old_unit)
        proof.stop(host.state,host.contract,host.command)
        with self.assertRaisesRegex(ValueError,'unit changed'):proof.guard(host.state,host.contract,host.command)
        path.write_bytes(b'inert unrelated service definition');stops=len(host.stops)
        with self.assertRaises(ValueError):proof.stop(host.state,host.contract,host.command)
        with self.assertRaises(ValueError):host.derive()
        self.assertEqual(len(host.stops),stops)
        self.assertEqual(path.read_bytes(),b'inert unrelated service definition')


if __name__=='__main__':
    raise SystemExit(not unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(PublicationRecovery)).wasSuccessful())
