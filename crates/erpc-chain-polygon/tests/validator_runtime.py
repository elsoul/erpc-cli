# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Real controller finalization and unit sealing with inert native/crypto adapters."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import shutil
import tempfile
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'templates/scripts'))


def module(name):
    spec=importlib.util.spec_from_file_location('polygon_validator_test_'+name,ROOT/'tests'/(name+'.py'))
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


@unittest.skipUnless(os.name=='posix','controller finalization uses POSIX host receipts')
class Finalization(unittest.TestCase):
    def enter(self,value):
        result=value.start();self.addCleanup(value.stop);return result
    def setUp(self):
        import broker,broker_runtime,gateway,identity,install,launch,local_tls,validator_runtime
        from state import canonical,profile_digest
        self.module=validator_runtime;self.broker_runtime=broker_runtime;self.local_tls=local_tls;self.install=install
        self.fixture=module('control').Lifecycle();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        fixture=self.fixture;self.state=fixture.state;self.control=fixture.control;self.profile=fixture.profile
        self.state.path('/run').mkdir(exist_ok=True)
        self.expected=dict(fixture.contract,role='validator',signer='0x'+'1'*40,stake_owner='0x'+'2'*40)
        self.profile['validator']={'phase':'observing','signer':self.expected['signer'],
            'sentries':[{'address':'8.8.8.8','bor_node_id':'a'*128,'heimdall_node_id':'b'*40}]}
        self.request=dict(fixture.request,contract=self.expected,profile=self.profile,action='validator-finalize')
        self.state.write('/etc/polygon/contract.json',dict(self.expected,runtime_protocol=3))
        storage=self.state.read('/etc/polygon/storage.json');storage['contract']=self.expected
        self.state.write('/etc/polygon/storage.json',storage)
        self.accounts={name:{'uid':uid,'gid':uid} for name,uid in [('bor',999),('heimdall',998),('parent',997),('broker',996)]}
        self.state.accounts.verify=lambda expected:self.accounts
        original=self.state.read('/etc/polygon/identity.json');original['contract']=self.expected
        original['validator']={'signer':self.expected['signer'],'public_key':'0x04'+'a'*128}
        for name in ('bor-signer.json','bor-password','heimdall-observer-key.json'):
            raw=('inert original ciphertext '+name).encode()
            fixture.file('/etc/credstore.encrypted/polygon/original/'+name,raw)
            original['ciphertexts'][name]=hashlib.sha256(raw).hexdigest()
        for name in ('/etc/polygon/identity.json','/etc/credstore.encrypted/polygon/original/receipt.json'):self.state.write(name,original)
        history={'contract':self.expected,'identity_sha256':hashlib.sha256(canonical(original)).hexdigest(),'state':'initialized'}
        for name in ('/etc/polygon/history.json','/etc/credstore.encrypted/polygon/original/home-state.json'):self.state.write(name,history)
        self.state.write('/var/lib/polygon/heimdall/erpc-home.json',self.expected)
        fixture.file('/var/lib/polygon/heimdall/data/priv_validator_observer_state.json',b'original observer history')
        self.state.path('/etc/polygon/empty-ca').mkdir()
        self.installed=self.state.read('/etc/polygon/installed.json')
        self.installed.update(contract=self.expected,profile=self.profile,profile_sha256=profile_digest(self.profile))
        self.installed.pop('units',None)
        raw=canonical(launch.metadata(self.expected,self.profile,self.installed['binaries']))
        fixture.file('/etc/polygon/launch.json',raw);self.installed['files']['/etc/polygon/launch.json']=hashlib.sha256(raw).hexdigest()
        self.state.write('/etc/polygon/installed.json',self.installed)
        self.state.write('/etc/polygon/intent.json',{'intent':self.request['intent'],'profile':self.profile,'helpers':self.control.helpers})
        fixture.file('/etc/polygon/preparing',b'inert fence')
        upstream=self.state.read('/etc/polygon/upstream.json');upstream['contract']=self.expected
        self.state.write('/etc/polygon/upstream.json',upstream)
        run=self.state.run
        def execute(args,**kwargs):
            if args[0]=='/usr/bin/systemd-creds':
                raw=kwargs['input'];out=b'encrypted:'+raw if args[1]=='encrypt' else raw.removeprefix(b'encrypted:')
                return subprocess.CompletedProcess(args,0,out,b'')
            return run(args,**kwargs)
        self.state.run=execute
        self.enter(patch.object(local_tls,'ensure',return_value={'source_intent':self.request['intent']}))
        self.enter(patch.object(local_tls,'publish_credentials',return_value={}))
        self.enter(patch.object(local_tls,'verify_projection',return_value={'source_intent':self.request['intent']}))
        self.native=self.enter(patch.object(install,'prepare',side_effect=lambda *args:self.installed))
        self.enter(patch('secrets.token_hex',side_effect=['a'*64,'b'*64,'c'*64]))
        record={'format':1,'contract':self.expected,'account':self.accounts['broker'],'helpers':self.control.helpers,
            'image':broker.identity(self.expected),'creation':'e'*32,'container_id':'d'*64,'state':'created'}
        self.state.write(broker_runtime.CONTAINER,record)
        self.token=broker_runtime.Container.token(record)
        self.manager=SimpleNamespace(prepare=Mock(return_value=self.token))
        self.container=self.enter(patch.object(broker_runtime,'Container',return_value=self.manager))
        self.original_container_token=lambda value:{key:value[key] for key in ('creation','container_id','helpers')}
        self.container.token=self.original_container_token
    def finalize(self):return self.control.dispatch(self.request)
    def render(self):
        render=module('render')
        values=render.values(self.profile,'x86_64',self.expected,self.control.helpers,([],[]))
        values.update(polygon_runtime_accounts=self.accounts,polygon_broker_token=self.token)
        results=render.render(values)
        for name in ('broker.service',):results[name]=render.ENV.get_template(name+'.j2').render(values)
        for component in ('bor','heimdall'):
            for kind in ('service','timer'):
                name='peer-'+component+'.'+kind
                results[name]=render.ENV.get_template('peer.'+kind+'.j2').render(dict(values,polygon_component=component))
        for name,text in results.items():
            if name.endswith(('.service','.timer')):
                native={'parent.service':'l1-proxy.service'}.get(name,name)
                self.fixture.file('/etc/systemd/system/polygon-'+native,text.encode())
        return results
    def test_actual_finalization_reports_prepared_only_and_native_fixed_key_receives_observer(self):
        result=self.finalize()
        self.assertTrue(result['prepared']);self.assertFalse(result['activated']);self.assertFalse(result['ready'])
        self.assertEqual(result['broker_token'],self.token);self.native.assert_called_once();self.manager.prepare.assert_called_once()
        saved=self.state.read(self.module.RECORD)
        self.assertEqual(saved['native_key']['source'],'heimdall-observer-key.json')
        projected=self.state.path(self.module.NATIVE_KEY).read_bytes().removeprefix(b'encrypted:')
        self.assertEqual(projected,self.state.path('/etc/credstore.encrypted/polygon/original/heimdall-observer-key.json').read_bytes())
        self.assertNotEqual(projected,self.state.path('/etc/credstore.encrypted/polygon/original/heimdall-validator-key.json').read_bytes())
        public=self.state.path(self.module.PUBLIC).read_text()
        self.assertNotIn('amqps:',public);self.assertNotIn('password',public)
        self.assertEqual(self.state.path('/var/lib/polygon/heimdall/data/priv_validator_observer_state.json').read_bytes(),b'original observer history')
        if importlib.util.find_spec('jinja2'):
            rendered=self.render();self.control.dispatch(dict(self.request,action='seal'))
            installed=self.install.installed(self.state,self.expected)
            self.assertEqual(set(installed['units']),self.install.unit_names(self.expected))
            self.assertNotIn('/original/heimdall-validator-key.json',rendered['heimdall.service'])
            self.assertNotIn('bor-password',rendered['bor.service'])
            self.assertNotIn('LoadCredential',rendered['broker.service'])
    def test_observer_readiness_is_not_reported_as_an_active_validator(self):
        import observe
        fixture=module('observe').Observer();fixture.setUp();fixture.profile=self.profile
        self.manager.record=Mock(return_value=self.state.read(self.broker_runtime.CONTAINER))
        self.manager.token=self.original_container_token;self.manager.health=Mock(return_value={'ready':True})
        self.control.sleep=lambda _:setattr(fixture,'height',fixture.height+3)
        self.state.path('/etc/polygon/preparing').unlink()
        with patch.object(self.control,'installation',return_value=self.installed), \
                patch.object(self.control,'read_query',return_value=fixture.query),patch.object(self.control,'runtime',return_value=self.installed):
            value=self.control.status(self.expected)
        self.assertTrue(value['runtime_ready']);self.assertTrue(value['observer_ready'])
        self.assertFalse(value['validator_active']);self.assertFalse(value['ready']);self.assertEqual(value['phase'],'observing')
    def test_external_registration_preparation_never_imports_owner_key_or_submits(self):
        import validator_activation
        self.finalize()
        public={'staking_token':'0x'+'3'*40,'minimum_deposit_base_units':'100000000000000000000000',
            'minimum_heimdall_fee_base_units':'1000000000000000000','registered':False,'parent_active':False}
        with patch.object(self.control,'installation',return_value=self.installed), \
                patch.object(validator_activation.observe,'ValidatorQuery',return_value=Mock()), \
                patch.object(validator_activation.admission,'snapshot',return_value=public):
            result=self.control.dispatch(dict(self.request,action='registration',registration_action='prepare'))
        self.assertTrue(result['prepared']);self.assertFalse(result['eligible'])
        self.assertEqual(result['transaction_submission'],'external only')
        details=result['external_registration']
        self.assertEqual(details['user'],self.expected['stake_owner']);self.assertFalse(details['managed_host_owner_key'])
        self.assertEqual(len(details['signerPubkey']),132);self.assertTrue(details['signerPubkey'].startswith('0x04'))
        self.assertEqual(details['minimum_stake_base_units'],public['minimum_deposit_base_units'])
        self.assertFalse(result['application_guarantees_admission'])
        self.assertNotIn('inert original ciphertext',json.dumps(result))

    def custody_fixture(self):
        from state import canonical
        raw=canonical({'contract':self.expected,'ca':'inert public CA','leaves':{}})
        source=self.request['intent'];cipher=b'encrypted:'+raw
        path=self.local_tls.DIRECTORY+'/'+source+'/bundle'
        self.fixture.file(path,cipher)
        record={'contract':self.expected,'source_intent':source,'cipher_sha256':hashlib.sha256(cipher).hexdigest(),
            'public_ca':'inert public CA','ca_sha256':hashlib.sha256(b'inert public CA').hexdigest(),
            'certificates':{},'not_after':2000000000}
        self.state.write(self.local_tls.RECORD,record)
        return path,record
    def test_actual_activate_and_owned_stop_include_all_auxiliary_units_and_preserve_dependency_backup(self):
        if not importlib.util.find_spec('jinja2'):self.skipTest('strict units need qualified renderer')
        self.finalize();self.render();self.control.dispatch(dict(self.request,action='seal'))
        self.custody_fixture()
        for component,unit in self.fixture.module.host.UNITS.items():
            item=self.accounts[component];self.fixture.unit_recipients[unit]=(item['uid'],item['gid'])
        self.fixture.unit_recipients['polygon-broker.service']=(0,self.accounts['broker']['gid'])
        record=self.state.read(self.broker_runtime.CONTAINER)
        self.manager.record=Mock(return_value=record);self.manager.token=self.original_container_token
        self.manager.bound=Mock(return_value=record)
        token={'run':'r-20261026t120000-abcdef','bundle':'b'*64}
        self.fixture.confirm(token['run'],token['bundle'])
        value=self.control.dispatch(dict(self.request,action='activate',firewall=token))
        self.assertTrue(value['startup_requested'])
        self.assertIn('polygon-broker.service',self.fixture.running)
        self.assertIn('polygon-peer-bor.timer',self.fixture.running)
        saved=self.state.read('/etc/polygon/original-credentials.backup.json')
        self.assertEqual(set(saved['validator_dependencies']['records']),{'tls','bor_auth','broker_auth'})
        self.assertTrue(self.control.stop(self.expected)['stopped']);self.assertFalse(self.fixture.running)
        self.assertEqual(self.state.read('/etc/polygon/original-credentials.backup.json'),saved)
    def test_restore_dependency_ciphertexts_requires_retained_original_receipts_and_never_rolls_back_tls(self):
        self.finalize();tls_path,tls=self.custody_fixture()
        saved=self.module.backup_custody(self.state,self.expected)
        source=self.state.path(self.broker_runtime.CIPHER);original=source.read_bytes();source.unlink()
        public={key:tls[key] for key in ('public_ca','ca_sha256','certificates','not_after')}
        with patch.object(self.local_tls,'validate',return_value=public):
            restored=self.module.restore_custody(self.state,self.expected,saved)
        self.assertEqual(restored['dependency_ciphertexts_restored'],3);self.assertEqual(source.read_bytes(),original)
        newer=dict(tls,source_intent='f'*32)
        self.state.write(self.local_tls.RECORD,newer)
        with patch.object(self.local_tls,'load',return_value=({},newer)) as current:
            result=self.module.restore_custody(self.state,self.expected,saved)
        self.assertEqual(result['dependency_ciphertexts_restored'],2);current.assert_called_once()
        self.assertEqual(self.state.read(self.local_tls.RECORD),newer)
        receipt=self.state.read(self.broker_runtime.RECORD);receipt['cipher_sha256']='0'*64
        self.state.write(self.broker_runtime.RECORD,receipt)
        with patch.object(self.local_tls,'load',return_value=({},newer)):
            with self.assertRaises(ValueError):self.module.restore_custody(self.state,self.expected,saved)
        self.assertEqual(source.read_bytes(),original)

    def test_active_without_original_admission_refuses_before_native_or_secret_work(self):
        from state import profile_digest
        self.profile['validator']['phase']='active'
        self.state.write('/etc/polygon/intent.json',{'intent':self.request['intent'],'profile':self.profile,'helpers':self.control.helpers})
        with self.assertRaises((ValueError,FileNotFoundError)):self.finalize()
        self.native.assert_not_called();self.manager.prepare.assert_not_called()
        self.assertFalse(self.state.path(self.module.NATIVE_KEY).exists())
    def test_validator_units_cover_both_networks_architectures_and_original_phases(self):
        if not importlib.util.find_spec('jinja2'):self.skipTest('strict rendering requires qualified Jinja')
        render=module('render')
        for network in ('mainnet','amoy'):
            for architecture in ('x86_64','aarch64'):
                for phase in ('observing','active'):
                    profile=json.loads((ROOT/'networks'/(network+'.json')).read_text())
                    profile['validator']=dict(self.profile['validator'],phase=phase)
                    expected=dict(self.expected,network=network,architecture=architecture,
                        bor_genesis=profile['bor_genesis_hash'],heimdall_genesis=profile['heimdall_genesis']['sha256'])
                    values=render.values(profile,architecture,expected,self.control.helpers,([],[]))
                    values.update(polygon_runtime_accounts=self.accounts,polygon_broker_token=self.token)
                    result=render.render(values)
                    result['broker.service']=render.ENV.get_template('broker.service.j2').render(values)
                    for component in ('bor','heimdall'):
                        for kind in ('service','timer'):
                            result['peer-'+component+'.'+kind]=render.ENV.get_template('peer.'+kind+'.j2').render(
                                dict(values,polygon_component=component))
                    self.assertEqual(len(result),10)
                    self.assertTrue(all('{{' not in value and '{%' not in value for value in result.values()))
                    self.assertEqual('LoadCredentialEncrypted=bor-password' in result['bor.service'],phase=='active')
                    self.assertNotIn('LoadCredential',result['broker.service'])
                    self.assertNotIn('/original/heimdall-validator-key.json',result['heimdall.service'])
                    self.assertNotIn('tcp dport { 8545, 8546 } accept',result['firewall.nft'])
                    for component in ('bor','heimdall','parent'):
                        lines=result[component+'.service'].splitlines()
                        self.assertIn('User='+str(self.accounts[component]['uid']),lines)
                        self.assertIn('Group='+str(self.accounts[component]['gid']),lines)
                        self.assertTrue(any(line.startswith('ExecCondition=') for line in lines))

    def test_actual_ansible_publishes_all_original_definitions_without_starting_clients(self):
        if not importlib.util.find_spec('yaml') or not shutil.which('ansible-playbook'):
            self.skipTest('actual publication requires the qualified Ansible CLI')
        import yaml
        self.finalize();render=module('render')
        values=render.values(self.profile,'x86_64',self.expected,self.control.helpers,([],[]))
        with tempfile.TemporaryDirectory() as folder:
            directory=Path(folder);helper=directory/'control.py'
            public={'runtime_accounts':self.accounts,'broker_token':self.token}
            helper.write_text('import json,sys\nvalue=json.load(sys.stdin)\nassert value["action"]=="validator-finalize"\nprint('+repr(json.dumps(public))+')\n')
            play=yaml.safe_load((ROOT/'templates/ansible/polygon/validator-finalize.yml').read_text())[0]
            tasks=play['tasks'][:7]
            for task in tasks:
                definition=task.get('ansible.builtin.template')
                if definition:
                    definition['dest']=str(self.state.path('/etc/systemd/system'))+'/'+definition['dest'].rsplit('/',1)[1]
                    definition.pop('owner');definition.pop('group')
            values.pop('polygon_runtime_accounts')
            values.update(polygon_scripts=str(directory),polygon_templates=str(ROOT/'templates/jinja'),polygon_request=self.request)
            file=directory/'publication.yml'
            file.write_text(yaml.safe_dump([{'name':'Inert actual stopped validator publication','hosts':'localhost',
                'gather_facts':False,'become':False,'vars':values,'tasks':tasks}]))
            result=subprocess.run([shutil.which('ansible-playbook'),'-i','localhost,','-c','local',str(file)],
                stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=120,
                env=dict(os.environ,ANSIBLE_NOCOLOR='1',OBJC_DISABLE_INITIALIZE_FORK_SAFETY='YES'))
            self.assertEqual(result.returncode,0,result.stdout.decode())
        self.control.dispatch(dict(self.request,action='seal'))
        self.assertEqual(set(self.state.read('/etc/polygon/installed.json')['units']),self.install.unit_names(self.expected))

    def test_explicit_active_projection_changes_only_the_runtime_identity_not_original_histories(self):
        from state import profile_digest
        self.finalize()
        names=['/var/lib/polygon/heimdall/data/priv_validator_state.json',
            '/var/lib/polygon/heimdall/data/priv_validator_observer_state.json']
        before={name:self.state.path(name).read_bytes() for name in names}
        self.profile['validator']['phase']='active'
        self.state.write('/etc/polygon/intent.json',{'intent':self.request['intent'],'profile':self.profile,'helpers':self.control.helpers})
        binding=self.module.publish_key(self.state,self.expected,self.request['intent'],self.profile,self.control.helpers)
        self.assertEqual(binding['source'],'heimdall-validator-key.json')
        projected=self.state.path(self.module.NATIVE_KEY).read_bytes().removeprefix(b'encrypted:')
        self.assertEqual(projected,self.state.path('/etc/credstore.encrypted/polygon/original/heimdall-validator-key.json').read_bytes())
        self.assertEqual({name:self.state.path(name).read_bytes() for name in names},before)

    def test_root_bor_publication_keeps_observer_empty_and_delivers_only_original_active_v3(self):
        import identity
        self.accounts['bor']={'uid':os.getuid(),'gid':os.getgid()}
        self.assertFalse(self.module.bor_files(self.state,self.expected,self.installed)['signer_delivered'])
        folder=self.state.path('/run/erpc-polygon-validator/bor-keystore')
        self.assertEqual(list(folder.iterdir()),[])
        self.profile['validator']['phase']='active'
        raw=json.dumps({'version':3,'address':self.expected['signer'][2:],'crypto':'inert public fixture'}).encode()
        cipher=b'encrypted:'+raw
        original={'ciphertexts':{'bor-signer.json':hashlib.sha256(cipher).hexdigest()}}
        source=self.state.path('/etc/credstore.encrypted/polygon/original/bor-signer.json');source.write_bytes(cipher)
        with patch.object(identity,'receipt',return_value=original):
            self.assertTrue(self.module.bor_files(self.state,self.expected,self.installed)['signer_delivered'])
            self.assertEqual((folder/'original.json').read_bytes(),raw)
            self.assertEqual((folder/'original.json').stat().st_mode&0o777,0o440)
            self.profile['validator']['phase']='observing'
            with self.assertRaises(ValueError):self.module.bor_files(self.state,self.expected,self.installed)
        self.assertEqual((folder/'original.json').read_bytes(),raw)

    def test_wrong_phase_ciphertext_cannot_satisfy_runtime_verification(self):
        self.finalize()
        source=self.state.path('/etc/credstore.encrypted/polygon/original/heimdall-validator-key.json').read_bytes()
        self.state.path(self.module.NATIVE_KEY).write_bytes(b'encrypted:'+source)
        with self.assertRaises(ValueError):self.module.verify(self.state,self.expected,self.installed)
    def test_seal_rejects_hot_original_delivery_and_stale_container_stop_token(self):
        if not importlib.util.find_spec('jinja2'):self.skipTest('strict renderer is exercised with pinned Ansible')
        self.finalize();self.render()
        unit=self.state.path('/etc/systemd/system/polygon-heimdall.service');original=unit.read_text()
        unit.write_text(original.replace('/polygon/heimdall-runtime-key.json','/polygon/original/heimdall-validator-key.json'))
        with self.assertRaises(ValueError):self.control.dispatch(dict(self.request,action='seal'))
        unit.write_text(original)
        unit=self.state.path('/etc/systemd/system/polygon-broker.service')
        unit.write_text(unit.read_text().replace('d'*64,'f'*64))
        with self.assertRaises(ValueError):self.control.dispatch(dict(self.request,action='seal'))


if __name__=='__main__':unittest.main()
