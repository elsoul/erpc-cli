#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual helper publisher and optional pinned Ansible invocation in temp paths.

The Ansible fixture substitutes only host paths/root UID and the outer sealed
source trust anchor. It never runs apt, sudo, NSS, Docker, nftables or a node.
"""
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'templates/validator/node'))
import host
import publication
import protocol
import state
import storage


def confined_lock_source(text, destination):
    """Require the actual lock assignment to be redirected before any fixture runs."""
    redirected, count = re.subn(r'^CONTROL = .+$',
        lambda _: 'CONTROL = Path('+repr(str(destination))+')', text, flags=re.MULTILINE)
    if count != 1:
        raise AssertionError('expected exactly one operation-lock assignment in fixture source')
    return redirected


class Publication(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup); self.addCleanup(patch.stopall)
        self.root = Path(temp.name).resolve()
        patch.object(storage, 'ROOT_UID', os.getuid()).start(); patch.object(storage, 'TRUST_ANCHOR', self.root).start()
        self.source = self.root/'work/validator/node'; self.source.mkdir(parents=True)
        for path in (ROOT/'templates/validator/node').glob('*.py'): shutil.copyfile(path,self.source/path.name)
        shutil.copyfile(ROOT.parent/'erpc-chain-rollup/templates/scripts/upstreams.py', self.source/'upstreams.py')
        values = {'ROOT':self.root/'state','DATA':self.root/'state/data','HELPERS':self.root/'lib/helpers',
                  'CONFIG':self.root/'config','CUSTODY':self.root/'keys','UPSTREAM_CUSTODY':self.root/'parent-keys',
                  'TLS_CUSTODY':self.root/'tls-keys','UNITS':self.root/'units','RUNTIME':self.root/'run','FIREWALL':self.root/'firewall',
                  'FIREWALL_HELPER':self.root/'lib/rpc-firewall.py','DOCKER':self.root/'missing-docker'}
        self.paths = values
        for name,value in values.items(): patch.object(host,name,value).start()
        host.UNITS.mkdir(); (self.root/'lib').mkdir()
        storage.directory(host.ROOT,create=True); self.store = state.State(host.ROOT)
        self.expected = {'owner':'a'*26,'family':'arbitrum','network':'mainnet','platform':'amd64',
                         'role':'assertion-validator','wallet':'0x'+'1'*40,'creation':'b'*32,
                         'host_binding':'c'*64,'data_uuid':'00000000-0000-0000-0000-000000000001'}
        self.store.reserve(self.expected); self.intent = 'd'*32
        self.prepare()

    def prepare(self):
        self.digest = publication.profile(self.source)[0]
        self.target = {'phase':'observing','version':protocol.VERSION,'commit':protocol.COMMIT,
                       'image':protocol.IMAGE,'image_id':protocol.IMAGE_ID,'helpers_sha256':self.digest,'config_id':'b'*64}
        self.store.prepare(self.expected,self.intent,self.target,lambda:None)

    def publish(self): return publication.publish(self.store,self.expected,self.intent,self.source,lambda:None)

    def test_complete_missing_destination_and_interrupted_same_profile_retry(self):
        real = publication.write; count = [0]
        def fail(path,contents,**kwargs):
            real(path,contents,**kwargs); count[0] += 1
            if count[0] == 3: raise OSError('inert interrupted profile publication')
        with patch.object(publication,'write',side_effect=fail), self.assertRaises(OSError): self.publish()
        self.assertFalse((host.ROOT/'helpers.json').exists())
        self.assertTrue(self.publish()['published'])
        self.assertEqual(publication.profile(host.HELPERS)[0],self.digest)
        publication.verify(self.store,self.expected,self.target)

    def test_unsafe_ancestor_or_extra_writable_sibling_refuses_before_copy_without_repair(self):
        parent = host.HELPERS.parent; parent.chmod(0o777)
        with self.assertRaises(ValueError): self.publish()
        self.assertFalse(host.HELPERS.exists()); self.assertEqual(parent.stat().st_mode&0o777,0o777)
        parent.chmod(0o755); outside = self.root/'outside';outside.mkdir();host.HELPERS.symlink_to(outside)
        with self.assertRaises(ValueError): self.publish()
        self.assertEqual(list(outside.iterdir()),[]);host.HELPERS.unlink();host.HELPERS.mkdir()
        extra = host.HELPERS/'unowned.py';extra.write_text('inert untrusted sibling');extra.chmod(0o666)
        with self.assertRaises(ValueError): self.publish()
        self.assertEqual(extra.stat().st_mode&0o777,0o666);self.assertEqual(len(list(host.HELPERS.iterdir())),1)

    def test_post_copy_substitution_never_publishes_profile_authority(self):
        real = publication.write
        def substitute(path,raw,**kwargs):
            real(path,raw,**kwargs)
            if path.name == 'control.py': path.write_text('inert substituted source; never executed')
        with patch.object(publication,'write',side_effect=substitute), self.assertRaises(ValueError): self.publish()
        self.assertFalse((host.ROOT/'helpers.json').exists())

    def test_scoped_operation_lock_is_confined_before_fixture_execution(self):
        text = (self.source/'locking.py').read_text()
        destination = self.root/'operation.lock'
        redirected = confined_lock_source(text, destination)
        import scope
        for prefix in ('arbitrum-validator', 'robinhood-mainnet-validator', 'robinhood-testnet-validator'):
            with self.subTest(namespace=prefix), patch.object(scope, 'NAMESPACE', prefix):
                namespace = {'__name__': 'inert_fixture_locking'}
                exec(compile(redirected, '<inert fixture locking>', 'exec'), namespace)
                self.assertEqual(namespace['CONTROL'], destination)
                with namespace['locked'](namespace['CONTROL']):
                    self.assertTrue(destination.is_file())
                    self.assertEqual(destination.stat().st_mode & 0o7777, 0o600)
        for invalid in (text.replace('CONTROL = ', 'RENAMED = '), text+'\nCONTROL = Path("/inert")\n'):
            with self.assertRaises(AssertionError): confined_lock_source(invalid, destination)

    def ansible_fixture(self):
        try:
            import ansible
            import yaml
        except ImportError: self.skipTest('run this composed fixture with pinned Ansible2.18.19 Python')
        if ansible.__version__ != '2.18.19': self.skipTest('pinned Ansible2.18.19 is required')
        storage_path = self.source/'storage.py'; text = storage_path.read_text()
        text = text.replace('ROOT_UID = 0','ROOT_UID = '+str(os.getuid()))
        text = text.replace("TRUST_ANCHOR = Path('/')",'TRUST_ANCHOR = Path('+repr(str(self.root))+')')
        storage_path.write_text(text)
        text = (self.source/'host.py').read_text()
        import re
        for name,value in self.paths.items():
            text = re.sub(r'^'+name+r' = .+$',name+' = Path('+repr(str(value))+')',text,flags=re.MULTILINE)
        (self.source/'host.py').write_text(text)
        proc = self.root/'inert-proc';proc.mkdir()
        text = (self.source/'processes.py').read_text().replace("PROC = Path('/proc')",'PROC = Path('+repr(str(proc))+')')
        (self.source/'processes.py').write_text(text)
        locking = self.source/'locking.py'
        locking.write_text(confined_lock_source(locking.read_text(), self.root/'operation.lock'))
        entry = self.source/'entry.py';text = entry.read_text()
        text = text.replace('trusted_imports(Path(__file__).absolute().parent)',
                            "import sys\nsys.dont_write_bytecode = True\nsys.path.insert(0, os.path.normpath(str(Path(__file__).absolute().parent)))\nimport storage\nstorage.directory(Path(os.path.normpath(str(Path(__file__).absolute().parent))))")
        entry.write_text(text)
        records = {'node':{'name':'erpc-nitro-validator','home':'/var/lib/erpc-nitro-validator','shell':'/usr/sbin/nologin','uid':20000,'gid':20000},
                   'transport':{'name':'erpc-nitro-validator-l1','home':'/var/lib/erpc-nitro-validator-l1','shell':'/usr/sbin/nologin','uid':20001,'gid':20001}}
        self.store.put('accounts.json',{'contract':self.expected,'accounts':records});self.prepare()
        full = yaml.safe_load((ROOT/'templates/validator/ansible/prepare.yml').read_text())
        task = next(task for task in full[0]['tasks'] if task['name'].startswith('Publish and verify'))
        play = [{'name':'inert real publication task','hosts':'all','connection':'local','gather_facts':False,'tasks':[task]}]
        ansible_dir = self.source.parent/'ansible';ansible_dir.mkdir()
        script = ansible_dir/'prepare.yml';script.write_text(yaml.safe_dump(play))
        variables = self.root/'vars.json';variables.write_text(json.dumps({'ansible_python_interpreter':sys.executable,
            'validator_request':{'action':'prepare','contract':self.expected,'intent':self.intent,'target':self.target}}))
        return [sys.executable,'-m','ansible.cli.playbook','-i','localhost,',str(script),'-e','@'+str(variables)]

    def test_real_pinned_ansible_publication_task_accepts_only_checked_destination(self):
        argv = self.ansible_fixture()
        env = {'PATH':os.environ.get('PATH','/usr/bin:/bin'),'HOME':str(self.root),'LC_ALL':os.environ.get('LANG','en_US.UTF-8'),
               'ANSIBLE_LOCAL_TEMP':str(self.root/'ansible-local'),'ANSIBLE_REMOTE_TEMP':str(self.root/'ansible-remote'),
               'ANSIBLE_NOCOLOR':'1','PYTHONDONTWRITEBYTECODE':'1'}
        parent = host.HELPERS.parent;parent.chmod(0o777)
        refused = subprocess.run(argv,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
        self.assertNotEqual(refused.returncode,0);self.assertFalse(host.HELPERS.exists())
        self.assertEqual(parent.stat().st_mode&0o777,0o777);parent.chmod(0o755)
        accepted = subprocess.run(argv,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
        self.assertEqual(accepted.returncode,0,(accepted.stdout+accepted.stderr).decode())
        self.assertTrue((host.ROOT/'helpers.json').exists())
        self.assertEqual(publication.profile(host.HELPERS)[0],self.digest)


if __name__ == '__main__': unittest.main()
