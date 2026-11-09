# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Real temporary namespaces/publication; only root UID and host/NSS edges are modeled."""
import contextlib
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
SOURCE=Path(__file__).parents[1]/'templates/aqa';sys.path.insert(0,str(SOURCE))
import erpc_aqa_common as common
import erpc_aqa_host as host
import erpc_aqa_custody as custody
import erpc_aqa_state as states


class Host(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve();self.root.chmod(0o755)
        self.stack=contextlib.ExitStack();self.addCleanup(self.stack.close)
        def install(obj,name,value,**kw):return self.stack.enter_context(patch.object(obj,name,value,**kw))
        self.install=install;self.foreign=set();real_lstat=os.lstat;real_fstat=os.fstat;real_scandir=os.scandir
        def metadata(path,*args,**kwargs):
            values=list(real_lstat(path,*args,**kwargs));candidate=Path(path)
            values[4]=77 if candidate in self.foreign else 0
            if candidate in self.root.parents:values[0]=(values[0]&~0o022)|0o001
            return os.stat_result(values)
        def descriptor(fd):
            values=list(real_fstat(fd));values[4]=0;return os.stat_result(values)
        class Rows(list):
            def __enter__(self):return iter(self)
            def __exit__(self,*args):return False
        def scan(directory):
            with real_scandir(directory) as rows:
                return Rows(types.SimpleNamespace(name=row.name,path=row.path,stat=lambda *,follow_symlinks=True,p=row.path:metadata(p)) for row in rows)
        install(os,'lstat',metadata);install(Path,'lstat',lambda path:metadata(path))
        install(os,'fstat',descriptor);install(os,'scandir',scan)
        for name,path in {'ROOT':'state','CONFIG':'config','HELPERS':'helpers','RELEASES':'native',
                          'SYSTEMD':'units','FIREWALL_ROOT':'erpc/hyperliquid-aqa','FIREWALL':'lib/rpc-firewall.py',
                          'MACHINE':'machine-id','SOURCE':'source'}.items():install(host,name,self.root/path)
        host.SYSTEMD.mkdir(mode=0o755)
        host.SOURCE.mkdir(mode=0o755)
        for name in common.RUNTIME_FILES:common.atomic(host.SOURCE/name,(SOURCE/name).read_bytes(),0o444)
        common.atomic(host.MACHINE,b'a'*32,0o444)
        self.catalog=host.catalog();pin=self.catalog['artifact']
        self.c={'schema':1,'profile':'hyperliquid-aqa','owner':'a'*32,'network':'testnet','host_binding':'b'*64,
                'identity':{'validator':'0x'+'a'*40,'consensus_signer':'0x'+'b'*40,'agent_master':'0x'+'c'*40,
                            'agent':'0x'+'d'*40,'agent_public_key':'04'+'11'*64,'agent_name':'erpc-aqa'}}
        self.policy={'management_allow':['192.0.2.0/24']}
        self.target={'id':'aqa-'+self.catalog['version'],'sha256':pin['sha256'],'signed_at':pin['signed_at'],
                     'helper_sha':host.helper_digest(),'config_id':common.digest(common.json_bytes(self.policy))}
        self.request={'contract':self.c,'policy':self.policy,'target':self.target,'intent':'e'*32}
        install(host,'hardware',lambda:None)
        install(host.accounts,'lookup',lambda *args:None)
        install(host,'execute',lambda *args,**kw:types.SimpleNamespace(stdout=b'not-found'))
        install(custody,'ROOT',host.ROOT)

    def reserve(self):return host.reserve(self.request)

    def test_clean_reservation_and_public_helper_modes_survive_umask077(self):
        old=os.umask(0o077)
        try:
            state=self.reserve();selected=host.publish_helpers();host.protected_paths()
        finally:os.umask(old)
        self.assertEqual(state.get('owner.json')['contract'],self.c)
        self.assertEqual(stat.S_IMODE((host.ROOT/'owner.json').stat().st_mode),0o600)
        directory=host.HELPERS/'releases'/selected
        self.assertEqual(directory.stat().st_mode&0o777,0o755)
        self.assertTrue(all((directory/name).stat().st_mode&0o777==0o444 for name in common.RUNTIME_FILES))
        self.assertEqual(Path(host.trusted_release(str(host.HELPERS),[list(common.RUNTIME_FILES)])),directory)

    def test_unknown_namespaces_and_owner_mutation_never_become_a_reservation(self):
        host.ROOT.mkdir(mode=0o700);common.atomic(host.ROOT/'agent-import.json',b'{}')
        with self.assertRaises(ValueError):self.reserve()
        self.assertFalse((host.ROOT/'owner.json').exists())
        (host.ROOT/'agent-import.json').unlink();state=self.reserve()
        wrong=copy.deepcopy(self.request);wrong['contract']['network']='mainnet'
        with self.assertRaises(ValueError):host.reserve(wrong)
        self.assertEqual(state.get('owner.json')['contract'],self.c)

    def test_permissions_ancestors_and_extra_boot_overrides_refuse_without_repair(self):
        self.reserve();path=host.SYSTEMD/(common.UNIT+'.d');path.mkdir()
        extra=path/'99-override.conf';common.atomic(extra,b'[Service]\nExecStartPre=\n',0o644)
        with self.assertRaises(ValueError):host.protected_paths()
        self.assertEqual(extra.read_bytes(),b'[Service]\nExecStartPre=\n');extra.unlink()
        for mode in (0o755,0o777):
            host.ROOT.chmod(mode)
            if mode==0o777:
                with self.assertRaises(ValueError):host.owned(self.c)
            else:host.owned(self.c)
            self.assertEqual(host.ROOT.stat().st_mode&0o777,mode)
        host.ROOT.chmod(0o700);self.foreign.add(host.ROOT)
        with self.assertRaises(ValueError):host.owned(self.c)

    def test_managed_symlinks_and_shared_owner_receipts_are_rejected(self):
        self.reserve();original=host.ROOT/'owner.json';outside=self.root/'outside'
        os.link(original,outside)
        with self.assertRaises(ValueError):host.owned(self.c)
        outside.unlink();original.rename(outside);original.symlink_to(outside)
        with self.assertRaises(ValueError):host.owned(self.c)
        self.assertTrue(original.is_symlink())

    def test_legitimate_interrupted_helper_pointer_resumes_same_immutable_content(self):
        self.reserve();selected=host.publish_helpers();pointer=host.HELPERS/'current'
        pointer.rename(host.HELPERS/'current.pending')
        self.assertEqual(host.publish_helpers(),selected)
        self.assertTrue(pointer.is_symlink());host.protected_paths()
        (host.HELPERS/'releases'/selected/'control.py').chmod(0o666)
        with self.assertRaises(ValueError):host.publish_helpers()

    def test_real_preparation_and_configure_bind_exact_receipt_before_publication(self):
        state=self.reserve();account={'uid':995,'gid':995}
        for name in ('accounts.json','account-reservation.json'):state.put(name,{host.accounts.NATIVE:account})
        state.authorize(self.c,self.request['intent'],self.target)
        self.install(host.accounts,'accounts',lambda value:value)
        self.install(host,'capacity',lambda:None);self.install(host,'clock',lambda:None)
        stops=[];self.install(host,'stop_owned',lambda c:stops.append(c['owner']))
        self.install(host.process,'quiescent',lambda *args:None)
        self.install(custody,'identity',lambda *args:{'dotenv_sha256':'f'*64,'cipher_sha256':'e'*64})
        self.install(host.public,'observe',lambda c:{'approval':{'name':'erpc-aqa','valid_until':None},'validator_active':True})
        native=host.RELEASES/self.catalog['version'];native.mkdir(mode=0o755)
        binary=native/'publish_daemon';common.atomic(binary,b'inert no execution',0o555)
        interpreter=self.root/'inert-python';common.atomic(interpreter,b'inert no interpreter execution',0o555)
        self.install(host,'INTERPRETER',interpreter)
        self.install(host.artifact,'install',lambda _:binary);self.install(host.artifact,'check',lambda _:binary)
        host.prepare(self.request)
        self.assertEqual(stops,[self.c['owner']]);self.assertTrue((host.ROOT/'installing.json').exists())
        expected=('require-confirmed','c'*32,'d'*64)
        calls=[]
        def firewall(*args):
            calls.append(args)
            if args!=expected:raise ValueError('inert different confirmation')
        self.install(host,'firewall',firewall)
        request=dict(self.request,run='c'*32,bundle='e'*64)
        with self.assertRaises(ValueError):host.configure(request)
        self.assertFalse((host.CONFIG/'runtime.json').exists())
        self.assertEqual(list(host.SYSTEMD.iterdir()),[])
        request['bundle']='d'*64;old=os.umask(0o077)
        try:host.configure(request)
        finally:os.umask(old)
        self.assertEqual(calls,[('require-confirmed','c'*32,'e'*64),expected])
        installed=state.guard(self.c,self.request['intent'])
        self.assertEqual(installed['receipt']['firewall'],{'run':'c'*32,'bundle':'d'*64})
        self.assertEqual((host.CONFIG/'runtime.json').stat().st_mode&0o777,0o444)
        for name,checksum in installed['receipt']['units'].items():
            path=host.SYSTEMD/name;self.assertEqual(common.digest(path.read_bytes()),checksum)
            self.assertEqual(path.stat().st_mode&0o777,0o644)
        self.assertEqual(host.qualify(self.c,self.request['intent'])[1],account)
        state.cancel(self.c,False,lambda:None)
        with self.assertRaises(ValueError):host.configure(request)
        self.assertTrue((host.ROOT/'stopped').exists())

    def test_exact_decrypted_dotenv_and_clean_exec_environment_with_no_parent_fallback(self):
        self.reserve();identity={'uid':995,'gid':995};body=b'INERT_DOTENV_FIXTURE=1\n'
        credential=self.root/'runtime'/'credentials'/'unit'/'.env';credential.parent.mkdir(parents=True)
        common.atomic(credential,body,0o400);self.install(custody,'DECRYPTED',credential)
        native=host.RELEASES/self.catalog['version'];native.mkdir(mode=0o755)
        binary=native/'publish_daemon';common.atomic(binary,b'inert nonexecutable publisher',0o555)
        version=copy.deepcopy(self.catalog);version['artifact']['binary_size']=binary.stat().st_size
        version['artifact']['binary_sha256']=common.digest(binary.read_bytes());self.install(host,'catalog',lambda:version)
        value={'contract':self.c,'account':identity,'version':version['version'],
               'binary_sha256':version['artifact']['binary_sha256'],'dotenv_sha256':common.digest(body)}
        common.atomic(host.CONFIG/'runtime.json',common.json_bytes(value),0o444)
        for name,value in [('getuid',995),('geteuid',995),('getgid',995),('getgroups',[995])]:
            self.install(os,name,lambda v=value:v,create=True)
        calls=[];self.install(os,'execve',lambda *args:calls.append(args))
        cwd=Path.cwd()
        try:
            with patch.dict(os.environ,{'PUBLISHER_PRIVATE_KEY':'inert ambient poison','NETWORK':'mainnet','HTTP_PROXY':'inert proxy'}):
                host.launch(self.c['owner'])
            self.assertEqual(Path.cwd(),credential.parent)
            self.assertEqual(calls[0][0],binary);self.assertEqual(calls[0][1],[str(binary)])
            self.assertEqual(set(calls[0][2]),{'PATH','HOME','LANG','LC_ALL'})
            credential.unlink();common.atomic(credential.parent.parent/'.env',body,0o400)
            with self.assertRaises(FileNotFoundError):host.launch(self.c['owner'])
            self.assertEqual(len(calls),1)
            common.atomic(credential,b'substituted credential',0o400)
            with self.assertRaises(ValueError):host.launch(self.c['owner'])
            self.assertEqual(len(calls),1)
        finally:os.chdir(cwd)


if __name__=='__main__':unittest.main()
