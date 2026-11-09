# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Production play requests reach actual controller/state; packages and native tools are inert."""
import json
from pathlib import Path
import shutil
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
try:
    import yaml
    from jinja2 import Environment,StrictUndefined
except ImportError:yaml=None
sys.path.insert(0,str(Path(__file__).parent))
import authority_runtime as fixtures
import control
import eth_namespace as namespace


@unittest.skipUnless(yaml,'run with the pinned Ansible Python environment')
class ProductionPlay(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.Runtime();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        f=self.fixture;self.env=Environment(undefined=StrictUndefined)
        self.env.filters['combine']=lambda a,b:dict(a,**b);self.env.filters['to_json']=json.dumps
        self.source={key:f.target[key] for key in ('pair','rpc_bind','metrics_bind','checkpoint')}
        self.source.update(reth_commit='1'*40,lighthouse_commit='2'*40,reth_archive='3'*64,lighthouse_archive='4'*64)
        f.install(control,'initialize_jwt',lambda *_:None)
        self.crypto=[]
        f.install(control,'initialize_jwt',lambda *_:self.crypto.append('original private phase'))
        f.install(control,'State',lambda _:f.state)
        self.tasks=yaml.safe_load((Path(__file__).parents[1]/'templates/ansible/eth-rpc/deploy.yml').read_text())[1]['tasks']
        self.history=f.state.directory/'original-history';self.history.write_bytes(b'retained original history')

    def execute(self,stop_after=None):
        f=self.fixture
        f.request('reserve-deploy',intent=f.intent,target=self.source,operation='deploy')
        variables={'eth_authority_request':{'action':'prepare','contract':f.c},'eth_authority_intent':f.intent,
                   'eth_authority_source':self.source,'eth_control':['/usr/bin/python3','-I','-c','inert carried loader','inert/control.py','request'],
                   'erpc_fw_confirmed_run':'r-inert','erpc_fw_confirmed_bundle':'d'*64}
        actions=[]
        for task in self.tasks:
            if 'ansible.builtin.include_tasks' in task:
                self.assertEqual(task['ansible.builtin.include_tasks'],'tasks/install_release.yml')
                stage=f.root/'opt'/(self.source['pair']+'.pending-'+f.intent);stage.mkdir(exist_ok=True)
                for client in ('reth','lighthouse'):shutil.copyfile(f.root/'opt'/self.source['pair']/client,stage/client)
                continue
            if 'ansible.builtin.set_fact' in task:
                variables['eth_original_accounts']=json.loads(variables['eth_original']['stdout'])['accounts']['users'];continue
            command=task['ansible.builtin.command'];self.assertEqual(command['argv'],'{{ eth_control }}')
            request=json.loads(self.env.from_string(command['stdin']).render(**variables));actions.append(request['action'])
            result=control.dispatch(f.state,f.c,request)
            if request['action']=='bootstrap' and result['snapshot']!='complete':
                control.boot('snapshot-complete',f.intent)
                result=control.dispatch(f.state,f.c,request)
                self.assertEqual(result['snapshot'],'complete')
            if 'register' in task:variables[task['register']]={'stdout':json.dumps(result)}
            if request['action']==stop_after:f.request('stop')
        return actions

    def test_actual_production_order_reaches_qualified_source_original_material_and_activation(self):
        actions=self.execute()
        self.assertEqual(actions,['check-deploy','qualify','begin','engine-init','install','bootstrap','activate'])
        self.assertTrue(self.fixture.active);self.assertFalse(self.fixture.state.exists('pending.json'))
        self.assertEqual(self.crypto,['original private phase']);self.assertEqual(self.history.read_bytes(),b'retained original history')

    def test_stop_after_public_qualification_prevents_private_material_and_native_start(self):
        with self.assertRaises(ValueError):self.execute('qualify')
        self.assertEqual(self.crypto,[]);self.assertFalse(self.fixture.active)
        self.assertEqual(self.history.read_bytes(),b'retained original history')

    def test_stop_after_cutover_prevents_late_private_material_and_unit_publication(self):
        with self.assertRaises(ValueError):self.execute('begin')
        self.assertEqual(self.crypto,[]);self.assertFalse(self.fixture.active)
        self.assertFalse(self.fixture.state.exists('installed-'+self.fixture.intent+'.json'))

    def test_stop_after_bootstrap_keeps_completion_but_refuses_old_activation(self):
        with self.assertRaises(ValueError):self.execute('bootstrap')
        self.assertFalse(self.fixture.active);self.assertTrue(self.fixture.state.exists('snapshot.json'))
        self.assertTrue(self.fixture.state.exists('cutover.json'));self.assertEqual(self.history.read_bytes(),b'retained original history')

    def test_same_release_access_change_keeps_original_binary_authority(self):
        self.execute();self.fixture.intent='e'*32;self.source['rpc_bind']='0.0.0.0';self.execute()
        self.assertEqual(self.fixture.state.get('active.json')['receipt']['units']['target']['rpc_bind'],'0.0.0.0')

    def test_same_version_source_substitution_refuses_before_stopping_original_runtime(self):
        self.execute();self.fixture.intent='f'*32;self.source['reth_commit']='9'*40
        self.fixture.calls.clear()
        with self.assertRaisesRegex(ValueError,'substitut'):self.execute()
        self.assertTrue(self.fixture.active);self.assertFalse(any(call[1]=='stop' for call in self.fixture.calls))


@unittest.skipUnless(yaml,'run with the pinned Ansible Python environment')
class ValidatorCompatibility(unittest.TestCase):
    def test_existing_validator_reaches_its_own_signed_install_tasks_with_real_variable_scope(self):
        try:
            from ansible.parsing.dataloader import DataLoader
            from ansible.template import Templar
        except ImportError:self.skipTest('run this real Ansible templating case with the pinned runtime')
        root=Path(__file__).parents[1]/'templates'
        play=yaml.safe_load((root/'validator/deploy.yml').read_text())[0]
        block=next(task['block'] for task in play['tasks'] if 'block' in task)
        include=next(task['ansible.builtin.include_tasks'] for task in block if 'ansible.builtin.include_tasks' in task)
        tasks=yaml.safe_load((root/'validator'/include).read_text())
        self.assertEqual((root/'validator'/include).resolve(),(root/'validator/install_release.yml').resolve())
        source=(root/'validator/install_release.yml').read_text()
        self.assertNotIn('eth_authority_',source);self.assertIn('VALIDSIG',source)
        self.assertIn('sha256:{{ item.sha256 }}',source)
        values={'playbook_dir':str(root/'validator'),'eth_opt':'/opt/erpc-eth-validator',
            'eth_release_dir':'/opt/erpc-eth-validator/reth-v2.8.1--lighthouse-v8.3.2',
            'eth_gpg':str(root/'gpg'),'eth_reth_version':'v2.8.1','eth_lighthouse_version':'v8.3.2','eth_reth_commit':'1'*40,
            'eth_installed_pair':{'stat':{'exists':False}},'ev_loader':'inert authenticated loader',
            'ev_request':{'contract':{'role':'validator'},'request':{'owner':'fixture','intent':'a'*32}},'ev_intent':'a'*32,
            'eth_reth_url':'https://github.com/inert/reth.tar.gz','eth_lighthouse_url':'https://github.com/inert/lighthouse.tar.gz',
            'ev_accounts':{'users':{'ev-reth':{'uid':991,'gid':991},'ev-beacon':{'uid':992,'gid':992}}}}
        templar=Templar(loader=DataLoader(),variables=values)
        def flatten(tasks):
            for task in tasks:
                yield task
                if 'block' in task:yield from flatten(task['block'])
        rendered=[]
        for client in ('reth','lighthouse'):
            templar.available_variables=dict(values,item={'client':client,'url':'https://github.com/inert/'+client+'.tar.gz',
                'sha256':'2'*64,'fingerprint':'3'*40})
            for task in flatten(tasks):
                for module in ('ansible.builtin.command','ansible.builtin.shell','ansible.builtin.unarchive'):
                    if module in task:rendered.append(templar.template(task[module],fail_on_undefined=True))
        import shlex
        commands=[shlex.split(row) if isinstance(row,str) else row['argv'] for row in rendered if isinstance(row,str) or (isinstance(row,dict) and 'argv' in row)]
        self.assertTrue(any(command[-1]=='--version' and command[-2].endswith('/reth') for command in commands))
        self.assertTrue(any(command[-1]=='--version' and command[-2].endswith('/lighthouse') for command in commands))
        conditions=[task['failed_when'] for task in tasks if 'failed_when' in task]
        for reported,should_fail in [('reth Version: 2.8.1\nCommit SHA: '+'1'*40,False),('reth Version: 2.8.10\nCommit SHA: '+'1'*40,True),('reth Version: 2.8.1\nCommit SHA: '+'1'*41,True)]:
            templar.available_variables=dict(values,eth_reth_reported={'rc':0,'stdout':reported})
            self.assertEqual(templar.template('{{ '+conditions[0]+' }}'),should_fail)
        for reported,should_fail in [('Lighthouse v8.3.2-a376def',False),('Lighthouse v8.3.20-a376def',True)]:
            templar.available_variables=dict(values,eth_lighthouse_reported={'rc':0,'stdout':reported})
            self.assertEqual(templar.template('{{ '+conditions[1]+' }}'),should_fail)


if __name__=='__main__':unittest.main()
