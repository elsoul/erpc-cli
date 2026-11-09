#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Production Ansible templating connected to the actual original host controller.

Package/native/NSS/systemd effects are modeled; production request envelopes,
register values, until expressions and original receipt transitions are actual.
Run with the pinned Ansible environment for the template/controller composition.
"""
import copy
import json
import pathlib
import sys
import unittest
sys.dont_write_bytecode=True
try:
    import yaml
    from ansible.parsing.dataloader import DataLoader
    from ansible.template import Templar
except ImportError:
    print('Ansible template composition requires the pinned environment')
    raise SystemExit(0)
sys.path.insert(0,str(pathlib.Path(__file__).parent))
import authority_lifecycle as lifecycle
import arc_files as files
import arc_protocol as protocol
ROOT=pathlib.Path(__file__).resolve().parents[1]
VALUES=json.load(sys.stdin)


class Plays(unittest.TestCase):
    def setUp(self):
        self.f=lifecycle.Lifecycle('runTest');self.f.setUp()
        self.path=ROOT/'templates/ansible/arc-rpc'
        self.vars=yaml.safe_load((self.path/'vars.yml').read_text())
        self.vars.update(VALUES)
        self.vars.update(playbook_dir=str(self.path),arc_authority_intent=self.f.intent,
                         erpc_fw_confirmed_run='r-inert',erpc_fw_confirmed_bundle='f'*64,
                         submitted_firewall_bundle={'stat':{'checksum':'f'*64}})
        state=self.f.c.state(self.f.contract)
        self.f.contract=self.vars['arc_authority_contract'];self.f.public=self.f.contract['public_key']
        state['contract']=self.f.contract;state['credential']['public_key']=self.f.public;self.f.c.save(state)
        self.templar=Templar(loader=DataLoader(),variables=self.vars)
    def tearDown(self):self.f.tearDown()
    def tasks(self,play):return yaml.safe_load((self.path/play).read_text())[0]['tasks']
    def render(self,value):
        self.templar.available_variables=self.vars
        return self.templar.template(value,fail_on_undefined=True)
    def request(self,task):
        command=self.render(task['ansible.builtin.command'])
        self.assertEqual(command['argv'][:3],['/usr/bin/python3','-I','-c'])
        self.assertIn('trusted_imports',command['argv'][3])
        self.assertTrue(command['argv'][4].endswith('/../../authority/control.py'))
        raw=command['stdin'];request=json.loads(raw) if isinstance(raw,str) else raw
        response=self.f.c.dispatch(request)
        if 'register' in task:self.vars[task['register']]={'stdout':json.dumps(response),'rc':0}
        return response

    def test_real_task_envelopes_receipts_and_queued_snapshot_wait(self):
        task=next(task for task in self.tasks('init.yml') if task['name'].startswith('Qualify and durably'))
        self.assertTrue(self.request(task)['prepared'])
        apt=next(task for task in self.tasks('init.yml') if 'ansible.builtin.apt' in task)
        self.assertEqual(apt['ansible.builtin.apt']['policy_rc_d'],101)
        self.f.call('reserve',intent=self.f.intent,target=self.f.target,policy=self.f.policy)
        self.assertTrue(self.request(self.tasks('firewall.yml')[0])['prepared'])
        self.f.call('firewall-confirm',intent=self.f.intent,operation='r-inert',bundle='f'*64)
        tasks=self.tasks('deploy.yml')
        begin=self.request(tasks[0]);self.f.c.write_bytes(begin['archive'],self.f.archive)
        installed=self.request(tasks[2]);self.assertEqual(installed['phase'],'bootstrap')
        poll=tasks[3]
        self.assertEqual(self.request(poll)['phase'],'bootstrap')
        self.assertFalse(self.render('{{ '+poll['until']+' }}'))
        # A queued/not-yet-running service cannot cause premature activation.
        self.assertEqual(self.f.c.jobs,['arc-snapshots.service'])
        self.f.native_snapshot()
        self.assertEqual(self.request(poll)['phase'],'bootstrap-complete')
        self.assertTrue(self.render('{{ '+poll['until']+' }}'))
        self.assertTrue(self.request(tasks[4])['startup_requested'])
        self.request(tasks[5])
        self.assertFalse(self.render('{{ '+tasks[5]['until']+' }}'))

    def test_rendered_long_deploy_refuses_different_confirmation_before_download(self):
        self.f.call('reserve',intent=self.f.intent,target=self.f.target,policy=self.f.policy)
        self.f.call('firewall-prepare',intent=self.f.intent,helpers=self.f.helper)
        self.f.call('firewall-confirm',intent=self.f.intent,operation='r-inert',bundle='f'*64)
        self.vars['erpc_fw_confirmed_bundle']='e'*64
        with self.assertRaises(files.Refused):self.request(self.tasks('deploy.yml')[0])
        self.assertFalse(self.f.c.path('/opt/arc/downloads').exists())

    def test_all_supported_network_and_type_legacy_proofs_and_firewalls_render_strictly(self):
        count=0
        for network in protocol.NETWORKS.values():
            for kind in ('full','archive','provider'):
                self.vars.update(arc_chain=network['chain'],arc_chain_id=network['chain_id'],arc_rpc_type=kind,
                                 arc_follow=[row['http']+',wss='+row['ws'] for row in network['follow']],
                                 arc_relays=[row['http'] for row in network['follow']])
                for path in (ROOT/'templates/legacy').glob('*.j2'):
                    text=self.render(path.read_text())
                    self.assertIn('ExecStart=/opt/arc/current/',text)
                    self.assertNotIn('--validator',text)
                    count+=1
                text=self.render((ROOT/'templates/jinja/erpc-arc.nft.j2').read_text())
                self.assertIn('tcp dport 22',text);count+=1
        self.assertEqual(count,24)


if __name__=='__main__':unittest.main()
