# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual artifact/ELF/FD sequencing; kernel seals and keygen execution are inert."""
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'templates/node'))
import native_migration_bls as bls


def executable(library=b'libc.so.6',tag=None):
    raw=bytearray(640);raw[:7]=b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HH',raw,16,3,62);struct.pack_into('<Q',raw,32,64);struct.pack_into('<HH',raw,54,56,3)
    interpreter=b'/lib64/ld-linux-x86-64.so.2\0';strings=library+b'\0'
    headers=[(1,5,0,0x400000,0,640,640,4096),(3,4,256,0x400100,0,len(interpreter),len(interpreter),1),(2,6,320,0x400140,0,64,64,8)]
    for index,header in enumerate(headers):struct.pack_into('<IIQQQQQQ',raw,64+56*index,*header)
    raw[256:256+len(interpreter)]=interpreter;raw[440:440+len(strings)]=strings
    for index,entry in enumerate([(5,0x400000+440),(10,len(strings)),(1 if tag is None else tag,0),(0,0)]):
        struct.pack_into('<qQ',raw,320+16*index,*entry)
    return bytes(raw)


@unittest.skipIf(os.name!='posix','native FD fixture requires POSIX')
class NativeProof(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.addCleanup(patch.stopall)
        self.root=Path(self.temp.name).resolve();self.path=self.root/'home/solv/agave/target/release/solana-keygen'
        self.path.parent.mkdir(parents=True);self.raw=executable();self.path.write_bytes(self.raw);self.path.chmod(0o755)
        source=copy.deepcopy(bls.ORIGINAL_SOURCES['sources']['mainnet'][0])
        self.request={'role':'validator','network':'mainnet','historical':{'uid':1001},'artifact_evidence':{'source':source},
            'keygen_evidence':{'document_sha256':'a'*64,'network':'mainnet','source':source,
                'executable_sha256':hashlib.sha256(self.raw).hexdigest(),'executable_bytes':len(self.raw)}}
        real=Path.lstat
        def metadata(path,*args,**kwargs):
            info=real(path,*args,**kwargs);values={k:getattr(info,k) for k in dir(info) if k.startswith('st_')}
            values['st_uid']=0
            if path in self.root.parents:values['st_mode']&=~0o022
            return SimpleNamespace(**values)
        patch.object(Path,'lstat',metadata).start();patch.object(bls.legacy,'ROOT',self.root).start()
        patch.object(bls,'platform',lambda request:None).start()
        self.events=[];self.seals={};self.fds={};self.next=0
        def create(name,flags):
            self.next+=1;path=self.root/('inert-memory-'+str(self.next));fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_RDWR,0o600)
            self.fds[fd]=name;self.events.append(('create',name));return fd
        patch.object(bls.os,'memfd_create',create,create=True).start()
        for name,value in [('MFD_CLOEXEC',1),('MFD_ALLOW_SEALING',2)]:patch.object(bls.os,name,value,create=True).start()
        for name,value in [('F_ADD_SEALS',100),('F_GET_SEALS',101),('F_SEAL_WRITE',1),('F_SEAL_GROW',2),('F_SEAL_SHRINK',4),('F_SEAL_SEAL',8)]:patch.object(bls.fcntl,name,value,create=True).start()
        def seals(fd,command,value=None):
            if command==100:self.seals[fd]=value;self.events.append(('sealed',self.fds[fd]));return 0
            self.assertEqual(command,101);return self.seals.get(fd,0)
        patch.object(bls.fcntl,'fcntl',seals).start()
        def invoke(image,args,private_fd=None):
            self.assertEqual(self.seals[image],15);self.assertEqual(os.pread(image,len(self.raw),0),self.raw)
            if args==['--version']:
                self.assertIsNone(private_fd);self.events.append(('version','public'));return ('solana-keygen '+source['version']+'\n').encode()
            self.assertEqual(args,['bls_pubkey','/proc/self/fd/'+str(private_fd)]);self.assertEqual(self.seals[private_fd],15)
            self.assertEqual(os.fstat(private_fd).st_mode&0o7777,0o400)
            self.assertEqual(json.loads(os.pread(private_fd,4096,0)),list(range(64)))
            self.events.append(('derive','public'));return ('3'*66+'\n').encode()
        patch.object(bls,'invoke',invoke).start()
    def test_exact_artifact_is_sealed_and_executable_before_private_input_is_constructed(self):
        with bls.artifact(self.request) as image:self.assertEqual(bls.derive(image,bytearray(range(64))),'3'*66)
        self.assertLess(self.events.index(('version','public')),self.events.index(('create','erpc-original-identity')))
        self.assertEqual(self.path.read_bytes(),self.raw)
    def test_wrong_independent_artifact_or_source_never_executes(self):
        for field,value in [('executable_sha256','b'*64),('executable_bytes',len(self.raw)+1)]:
            request=copy.deepcopy(self.request);request['keygen_evidence'][field]=value
            with patch.object(bls,'invoke') as invoke:
                with self.assertRaises(ValueError):
                    with bls.artifact(request):pass
                invoke.assert_not_called()
        request=copy.deepcopy(self.request);request['keygen_evidence']['source']['commit']='b'*40
        with self.assertRaises(ValueError):bls.evidence(request)
    def test_noexec_or_incomplete_seals_refuse_without_private_fd_or_policy_changes(self):
        real=os.fchmod
        def noexec(fd,mode):
            if mode==0o500:raise PermissionError('inert existing noexec policy')
            real(fd,mode)
        with patch.object(bls.os,'fchmod',noexec),patch.object(bls,'invoke') as invoke:
            with self.assertRaises(PermissionError):
                with bls.artifact(self.request):pass
            invoke.assert_not_called()
        with patch.object(bls.fcntl,'fcntl',return_value=0),patch.object(bls,'invoke') as invoke:
            with self.assertRaisesRegex(ValueError,'sealed'):
                with bls.artifact(self.request):pass
            invoke.assert_not_called()
        self.assertNotIn(('create','erpc-original-identity'),self.events)
    def test_sealed_executable_bytes_are_rehashed_not_only_the_original_input(self):
        original=os.write
        def corrupt(fd,value):
            changed=bytearray(value)
            if len(changed)==len(self.raw):changed[-1]^=1
            return original(fd,changed)
        with patch.object(bls.os,'write',side_effect=corrupt),patch.object(bls,'invoke') as invoke:
            with self.assertRaisesRegex(ValueError,'sealed original keygen content'):
                with bls.artifact(self.request):pass
            invoke.assert_not_called()

    def test_untrusted_ancestor_or_symlink_is_not_adopted(self):
        self.path.parent.chmod(0o777)
        with self.assertRaises(ValueError):bls.original_path(self.request)
        self.path.parent.chmod(0o755);other=self.path.with_name('retained');self.path.rename(other);self.path.symlink_to(other.name)
        with self.assertRaises(ValueError):bls.original_path(self.request)
    def test_custom_loader_dependencies_rpath_and_audit_metadata_are_refused(self):
        for raw in [executable(b'/home/solv/unqualified.so'),executable(tag=15),executable(tag=29),executable(tag=0x6ffffefc)]:
            with tempfile.TemporaryFile() as file:
                file.write(raw);file.flush()
                with self.assertRaises(ValueError):bls.elf(file.fileno(),len(raw))
    def test_fixed_native_argv_environment_and_fd_transfer_are_not_operator_parameters(self):
        from importlib.util import spec_from_file_location,module_from_spec
        spec=spec_from_file_location('unpatched_bls',Path(bls.__file__));module=module_from_spec(spec);spec.loader.exec_module(module)
        with patch.object(module.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=b'public\n',stderr=b'')) as run:
            self.assertEqual(module.invoke(17,['bls_pubkey','/proc/self/fd/18'],18),b'public\n')
            args,kwargs=run.call_args
            self.assertEqual(args[0],['/usr/bin/unshare','--net','--','/usr/bin/setpriv','--no-new-privs','--bounding-set=-all',
                '--inh-caps=-all','--ambient-caps=-all','--clear-groups','--','/proc/self/fd/17','bls_pubkey','/proc/self/fd/18'])
            self.assertEqual(kwargs['pass_fds'],(17,18));self.assertEqual(kwargs['cwd'],'/')
            self.assertEqual(set(kwargs['env']),{'PATH','HOME','LANG','LC_ALL'})
            self.assertEqual(kwargs['stdin'],module.subprocess.DEVNULL)
            for args in (['new'],['pubkey','/home/solv/identity.json'],['bls_pubkey','/proc/self/fd/18','--outfile','/tmp/key']):
                run.reset_mock()
                with self.assertRaises(ValueError):module.invoke(17,args,18)
                run.assert_not_called()


if __name__=='__main__':unittest.main()
