# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Execute real prepare/configure/identity/publication orchestration with inert artifacts."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'templates/scripts'))

@unittest.skipUnless(os.name=='posix' and importlib.util.find_spec('tomllib'),'native install requires POSIX and Python 3.11+; managed hosts use 3.12')
class Installer(unittest.TestCase):
    def setUp(self):
        import control,install,state,identity,artifacts
        self.modules=(control,install,state,identity,artifacts)
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.source=self.root/'source';self.source.mkdir()
        for name in install.SCRIPTS:
            source=ROOT.parent/'erpc-chain-rollup/templates/scripts/upstreams.py' if name=='upstreams.py' else ROOT/'templates/scripts'/name
            shutil.copyfile(source,self.source/name)
        self.profile=json.loads((ROOT/'networks/amoy.json').read_text());self.payload={};self.calls=[]
        self.genesis=b'{"inert":"migrated genesis"}'
        self.bind(self.profile['heimdall_genesis'],self.genesis)
        for name,pin in self.profile['configs'].items():
            text={'bor':'chain="amoy"\n"db.engine"="pebble"\n[protocol-marker]\nheight=12345\n',
                'heimdall_config':'[p2p]\nseeds="fixture-peers"\n',
                'heimdall_app':'pruning="default"\n[custom]\nchain="amoy"\n'}[name]
            self.bind(pin,text.encode())
        self.bind(self.profile['verifier']['assets']['x86_64'],b'inert verifier')
        for name,release in self.profile['releases'].items():
            for kind,pin in release['assets']['x86_64'].items():self.bind(pin,('inert '+name+' '+kind).encode())
        self.expected=state.contract('amoy','i'*26,'x86_64',self.profile['bor_genesis_hash'],self.profile['heimdall_genesis']['sha256'])
        for path in ('etc','opt/erpc','var/lib','run','usr/local/lib/erpc/polygon/releases'):(self.root/path).mkdir(parents=True,exist_ok=True)
        self.state=state.State(self.root,self.command,usage=lambda:(2_000_000_000_000,0),owner=os.getuid(),proof=type('FixtureAuthority',(),{'initial':lambda self:None,'can_start':lambda self,*args:None,'unoccupied':lambda self:None,'quiescent':lambda self:None,'startable':lambda self,*args:None,'listener':lambda self,*args:('fixture',)})())
        # NSS creation/privilege drift is exercised separately in accounts_test.py.
        def accounts(_self,expected):
            value={name:{'uid':uid,'gid':uid} for name,uid in [('bor',1001),('heimdall',1002),('parent',1003)]}
            if expected['role']=='validator':value['broker']={'uid':os.getuid(),'gid':os.getgid()}
            return value
        self.state.accounts=type('FixtureAccounts',(),{'preflight':lambda *_:None,'verify':accounts,'retained_uids':lambda *_:set()})()
        import volume_fixture
        volume_fixture.attach(self,self.state)
        self.control=control.Control(self.state,self.source)
        self.control.reserve(self.expected)
        for path in ('etc/credstore.encrypted/polygon','opt/polygon/downloads','opt/polygon/releases','var/lib/polygon'):
            (self.root/path).mkdir(parents=True,exist_ok=True)
        self.request={'contract':self.expected,'profile':self.profile,'helpers':self.control.helpers,'intent':'a'*32,'advertise':'8.8.8.8','action':'prepare'}
    def bind(self,pin,data):
        pin['sha256']=hashlib.sha256(data).hexdigest();pin['bytes']=len(data);self.payload[pin['url']]=data
    def command(self,args,**kwargs):
        self.calls.append(args);out=b''
        if args[0].endswith('/heimdalld') and args[1]=='init':
            home=Path(args[args.index('--home')+1]);self.assertIn('memory',(home/'config/client.toml').read_text());(home/'data').mkdir()
            for name in ('node_key.json','priv_validator_key.json'):
                (home/'config'/name).write_text(json.dumps({'priv_key':{'type':'inert','value':'not-a-key'}}))
            (home/'data/priv_validator_state.json').write_text('{"height":"0","round":0,"step":0}')
        elif args[0]=='/usr/bin/systemd-creds':
            out=b'inert cipher:'+kwargs['input'] if args[1]=='encrypt' else kwargs['input'].removeprefix(b'inert cipher:')
        elif args[:2]==['systemd-creds','encrypt']:Path(args[-1]).write_bytes(b'inert cipher:'+kwargs['input'])
        elif args[:2]==['systemctl','show']:out=b'0' if '--property=MainPID' in args else b'not-found'
        elif args[:2]==['systemctl','is-active']:out=b'inactive'
        return subprocess.CompletedProcess(args,0,out,b'')
    def fetch(self,pin,destination):
        data=self.payload[pin['url']];self.assertEqual(hashlib.sha256(data).hexdigest(),pin['sha256'])
        destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes(data);return destination
    def extract(self,package,destination,name,run):
        path=destination/'usr/bin'/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'inert authenticated '+package.read_bytes());return path
    def prepare(self,request=None,version_callback=None):
        control,install,state,identity,artifacts=self.modules
        original=identity.initialize
        def initialize(*args):
            return original(*args,generate_bor=lambda:(b'not-a-key','a'*128),temporary=lambda **kwargs:tempfile.TemporaryDirectory(dir=self.root/'run'))
        with patch.object(artifacts,'fetch',side_effect=self.fetch),patch.object(artifacts,'extract',side_effect=self.extract),\
                patch.object(artifacts,'signature') as signature,patch.object(artifacts,'native_version',side_effect=version_callback) as version,\
                patch.object(identity,'initialize',side_effect=initialize):
            result=self.control.dispatch(request or self.request)
            self.assertEqual(signature.call_count,2);self.assertEqual(version.call_count,2)
            for call in signature.call_args_list:
                self.assertTrue(call.args[4].startswith('https://github.com/0xPolygon/'));self.assertEqual(len(call.args[5]),40)
            return result
    def test_real_installer_preserves_identity_history_and_authenticates_both_layers(self):
        import tomllib
        self.prepare()
        installed=self.modules[1].installed(self.state,self.expected,require_units=False)
        self.assertEqual(installed['helpers'],self.control.helpers)
        config=tomllib.loads((self.root/'etc/polygon/bor.toml').read_text())
        self.assertEqual(config['protocol-marker']['height'],12345);self.assertEqual(config['db.engine'],'pebble')
        self.assertFalse(config['miner']['mine']);self.assertTrue(config['accounts']['disable-bor-wallet'])
        identity=(self.root/'etc/polygon/identity.json').read_bytes()
        history=self.root/'var/lib/polygon/heimdall/data/priv_validator_state.json';history.write_text('{"height":"123","round":1,"step":2}')
        self.prepare(dict(self.request,intent='b'*32))
        self.assertEqual((self.root/'etc/polygon/identity.json').read_bytes(),identity)
        self.assertEqual(json.loads(history.read_text())['height'],'123')
        self.assertEqual(len([c for c in self.calls if c[0].endswith('/heimdalld')]),1)
        self.assertFalse(list((self.root/'run').iterdir()))
        self.assertFalse(any(c[:2]==['systemctl','start'] for c in self.calls))

    def test_validator_prepare_authenticates_artifacts_before_custody_without_initializing_or_arming_firewall(self):
        self.expected=dict(self.expected,role='validator',signer='0x'+'1'*40,stake_owner='0x'+'2'*40)
        self.profile['validator']={'phase':'observing','signer':self.expected['signer'],
            'sentries':[{'address':'8.8.8.8','bor_node_id':'a'*128,'heimdall_node_id':'b'*40}]}
        self.state.write('/etc/polygon/contract.json',dict(self.expected,runtime_protocol=3))
        storage=self.state.read('/etc/polygon/storage.json');storage['contract']=self.expected
        self.state.write('/etc/polygon/storage.json',storage)
        self.request['contract']=self.expected
        import broker,broker_docker,broker_runtime
        wanted=broker.identity(self.expected)
        image={'Id':wanted['config'],'Os':'linux','Architecture':'amd64','RepoDigests':[wanted['image']],
            'Config':{'Entrypoint':['docker-entrypoint.sh'],'Cmd':['rabbitmq-server'],'Env':['RABBITMQ_VERSION=4.4.0']}}
        from types import SimpleNamespace
        daemon=SimpleNamespace(call=lambda *args,**kwargs:subprocess.CompletedProcess(args,0,json.dumps([image]).encode(),b''))
        credential={'format':1,'contract':self.expected,'password':'a'*64,'cookie':'b'*64}
        with patch.object(os,'fchown') as handoff,patch.object(broker_docker,'Docker',return_value=daemon), \
                patch.object(broker_runtime,'generate',return_value=credential) as generate:
            result=self.prepare()
        generate.assert_called_once()
        self.assertEqual(broker_runtime.original(self.state,self.expected),credential)
        handoff.assert_called_once()
        self.assertEqual(self.state.read('/etc/polygon/broker-data.json')['state'],'established')
        self.assertEqual(self.state.read('/etc/polygon/broker-image.json'),{'contract':self.expected,'image':wanted})
        self.assertTrue(result['native_prepared']);self.assertTrue(result['requires_validator_custody'])
        self.assertNotIn('prepared',result)
        self.assertFalse(self.state.path('/etc/polygon/identity.json').exists())
        self.assertFalse(self.state.path('/etc/polygon/installed.json').exists())
        self.assertTrue(self.state.path('/etc/polygon/preparing').exists())
        receipt=self.state.read('/etc/polygon/native-prepared.json')
        self.assertEqual(receipt['contract'],self.expected);self.assertEqual(receipt['helpers'],self.control.helpers)
        self.assertEqual(set(receipt['binaries']),{'bor','heimdall'})
        self.assertFalse(any(args[0] in ('nft','systemd-run') or args[:2]==['systemctl','start'] for args in self.calls))
        import signer
        request=dict(self.request,action='validator-key',original_signer='inert-not-a-key')
        with patch.object(signer,'stage') as stage:
            self.assertEqual(self.control.dispatch(request),{'original_signer_staged':True})
            stage.assert_called_once();stage.reset_mock()
            self.state.invalidate('stopped')
            with self.assertRaises(ValueError):self.control.dispatch(request)
            stage.assert_not_called()
    def test_unprotected_package_executable_is_rejected_before_native_execution(self):
        from types import SimpleNamespace
        original=Path.lstat;observed=[]
        def foreign(path,*args,**kwargs):
            value=original(path,*args,**kwargs)
            if path.name=='heimdalld':return SimpleNamespace(st_uid=os.getuid()+1,st_mode=value.st_mode,st_nlink=value.st_nlink)
            return value
        with patch.object(Path,'lstat',foreign):
            with self.assertRaises(ValueError):self.prepare(version_callback=lambda *args,**kwargs:observed.append(args))
        self.assertFalse(observed);self.assertTrue((self.root/'etc/polygon/preparing').exists())

    def test_lost_initialized_home_and_private_history_never_regenerate(self):
        self.prepare()
        shutil.rmtree(self.root/'var/lib/polygon/heimdall')
        before=len([c for c in self.calls if c[0].endswith('/heimdalld')])
        with self.assertRaises(ValueError):self.prepare(dict(self.request,intent='c'*32))
        self.assertEqual(len([c for c in self.calls if c[0].endswith('/heimdalld')]),before)
        self.assertFalse((self.root/'var/lib/polygon/heimdall').exists())
        self.assertTrue((self.root/'etc/polygon/preparing').exists())


@unittest.skipUnless(os.name=='posix' and importlib.util.find_spec('yaml') and shutil.which('ansible-playbook'),
    'actual template publication requires the pinned Ansible environment')
class CredentialUnitPublication(unittest.TestCase):
    def test_actual_prepare_tasks_use_returned_original_numeric_accounts(self):
        import yaml
        def load(name):
            spec=importlib.util.spec_from_file_location('polygon_unit_'+name,ROOT/'tests'/(name+'.py'))
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
        fixture=load('control').Lifecycle();fixture.setUp();self.addCleanup(fixture.doCleanups)
        render=load('render')
        accounts={name:{'uid':uid,'gid':uid+100} for name,uid in [('bor',701),('heimdall',702),('parent',703)]}
        fixture.state.accounts.verify=lambda expected:accounts
        with tempfile.TemporaryDirectory() as folder:
            directory=Path(folder);helper=directory/'control.py'
            helper.write_text('import json,sys\nvalue=json.load(sys.stdin)\nassert value["action"]=="prepare"\nprint('+repr(json.dumps({'runtime_accounts':accounts}))+')\n')
            play=yaml.safe_load((ROOT/'templates/ansible/polygon/prepare.yml').read_text())[0]
            # Execute the actual command→register→set_fact→template tasks only.
            # The command is an inert fixture; all writes stay in the temp tree.
            tasks=play['tasks'][:4]
            for task in tasks:
                template=task.get('ansible.builtin.template')
                if template:
                    template['dest']=str(fixture.state.path('/etc/systemd/system'))+'/'+template['dest'].rsplit('/',1)[1]
                    template.pop('owner');template.pop('group')
            values=render.values(fixture.profile,'x86_64',fixture.contract,fixture.control.helpers,([],[]))
            values.pop('polygon_runtime_accounts')
            values.update(polygon_scripts=str(directory),polygon_templates=str(ROOT/'templates/jinja'),polygon_request=fixture.request)
            file=directory/'publication.yml'
            file.write_text(yaml.safe_dump([{'name':'Inert actual numeric credential recipient publication','hosts':'localhost',
                'gather_facts':False,'become':False,'vars':values,'tasks':tasks}]))
            environment=dict(os.environ,ANSIBLE_NOCOLOR='1',OBJC_DISABLE_INITIALIZE_FORK_SAFETY='YES')
            result=subprocess.run([shutil.which('ansible-playbook'),'-i','localhost,','-c','local',str(file)],
                stdout=subprocess.PIPE,stderr=subprocess.STDOUT,env=environment,timeout=120)
            self.assertEqual(result.returncode,0,result.stdout.decode())
            for name,unit in fixture.module.host.UNITS.items():
                text=fixture.state.path('/etc/systemd/system/'+unit).read_text()
                self.assertIn('User='+str(accounts[name]['uid'])+'\n',text)
                self.assertIn('Group='+str(accounts[name]['gid'])+'\n',text)
                self.assertEqual(sum(line.startswith('ExecCondition=') for line in text.splitlines()),1)
            fixture.control.dispatch(dict(fixture.request,action='seal'))

if __name__=='__main__':unittest.main()
