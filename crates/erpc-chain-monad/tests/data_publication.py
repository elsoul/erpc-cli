# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Run the actual prepare task with pinned Ansible and inert host boundaries."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import yaml
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]


class DataPublication(unittest.TestCase):
    def test_actual_task_never_follows_native_data_links(self):
        task=next(task for task in yaml.safe_load((ROOT/'templates/ansible/monad/prepare.yml').read_text())[0]['tasks']
                  if task['name']=='Prepare original native directories without following node-controlled paths')
        self.assertNotIn('ansible.builtin.file',task)
        self.assertEqual(task['ansible.builtin.command']['argv'][0:2],['/usr/bin/python3','-I'])
        for scenario in ('safe','data','data/ledger','data/ledger/headers'):
            with self.subTest(scenario=scenario),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);outside=root/'unrelated';outside.mkdir(mode=0o755)
                original=outside/'original';original.write_bytes(b'unrelated retained bytes')
                driver=root/'driver.py'
                driver.write_text('''import json,sys
from pathlib import Path
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,TESTS)
import data_layout as tests
t=tests.DataLayout();t.setUp()
try:
 t.prepare()
 if SCENARIO != 'safe':
  path=t.root/SCENARIO;path.rename(t.root/'retained-native-directory');path.symlink_to(OUTSIDE)
 request=json.loads(sys.stdin.read())
 assert request['operation']=='prepare-data' and request['initial'] is True
 c=tests.control
 with patch.object(c,'ROOT',t.root),patch.object(c,'STATE',t.state),patch.object(c,'contract',lambda value:value),patch.object(c,'paths'),patch.object(c.namespace,'paths'),patch.object(c,'quiescent'),patch.object(c,'account',return_value=tests.fixture.types.SimpleNamespace(pw_uid=t.uid,pw_gid=t.gid)):
  print(json.dumps(c.dispatch(request)))
finally:t.doCleanups()
'''.replace('TESTS',repr(str(ROOT/'tests'))).replace('SCENARIO',repr(scenario)).replace('OUTSIDE',repr(str(outside))))
                selected=copy.deepcopy(task)
                selected['ansible.builtin.command']['argv']=[sys.executable,'-I',str(driver),'within-run']
                catalog=json.loads((ROOT/'templates/node/catalog.json').read_bytes())
                request={'contract':{'owner':'inert-owner','network':'testnet'},
                         'target':{key:catalog[key] for key in ('version','consensus_commit','execution_commit')}}
                play=[{'hosts':'all','gather_facts':False,'vars':{'monad_initial':True,'monad_request':request},'tasks':[selected]}]
                path=root/'play.yml';path.write_text(yaml.safe_dump(play))
                result=subprocess.run([sys.executable,'-I','-m','ansible.cli.playbook','-i','localhost,','-c','local',str(path)],
                    env=dict(os.environ,ANSIBLE_NOCOLOR='1',PYTHONDONTWRITEBYTECODE='1'),capture_output=True,text=True,timeout=60)
                self.assertEqual(result.returncode==0,scenario=='safe',result.stdout+result.stderr)
                self.assertEqual(outside.stat().st_mode&0o777,0o755)
                self.assertEqual({p.name for p in outside.iterdir()},{'original'})
                self.assertEqual(original.read_bytes(),b'unrelated retained bytes')


    def test_actual_recovery_play_uses_carried_controller_and_never_rewrites_native_history(self):
        original_play=yaml.safe_load((ROOT/'templates/ansible/monad/recover-data-filesystem.yml').read_text())[0]
        self.assertEqual(len(original_play['tasks']),1)
        for scenario in ('safe','wrong-uuid','not-stopped','foreign-inode'):
            with self.subTest(scenario=scenario),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);result_file=root/'result.json';driver=root/'driver.py'
                driver.write_text('''import json,sys
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,TESTS)
import data_layout as tests
t=tests.DataLayout();t.setUp()
try:
 original=t.legacy()
 payload=t.root/'data/wal/history';payload.write_bytes(b'inert original history')
 if SCENARIO=='not-stopped':(t.root/'stopped').unlink()
 if SCENARIO=='foreign-inode':
  value=t.state.get('data-ready.json');value['binding']['inode']+=1;t.state.put('data-ready.json',value)
 request=json.loads(sys.stdin.read())
 assert request['operation']=='recover-data-filesystem'
 try:result=t.recover(request['original_uuid'])
 finally:
  assert payload.read_bytes()==b'inert original history'
  Path(RESULT).write_text(json.dumps({'history_retained':True,'ready_format':t.state.get('data-ready.json').get('format'),'stopped':(t.root/'stopped').exists()}))
 print(json.dumps(result))
finally:t.doCleanups()
'''.replace('TESTS',repr(str(ROOT/'tests'))).replace('SCENARIO',repr(scenario)).replace('RESULT',repr(str(result_file))))
                task=copy.deepcopy(original_play['tasks'][0])
                task['ansible.builtin.command']['argv']=[sys.executable,'-I',str(driver),'within-run']
                identifier='00000000-0000-0000-0000-00000000000'+('2' if scenario=='wrong-uuid' else '1')
                request={'contract':{'owner':'inert-owner','network':'testnet'},'original_uuid':identifier}
                path=root/'play.yml';path.write_text(yaml.safe_dump([{'hosts':'all','gather_facts':False,
                    'vars':{'monad_request':request},'tasks':[task]}]))
                completed=subprocess.run([sys.executable,'-I','-m','ansible.cli.playbook','-i','localhost,','-c','local',str(path)],
                    env=dict(os.environ,ANSIBLE_NOCOLOR='1',PYTHONDONTWRITEBYTECODE='1'),capture_output=True,text=True,timeout=60)
                self.assertEqual(completed.returncode==0,scenario=='safe',completed.stdout+completed.stderr)
                result=json.loads(result_file.read_bytes());self.assertTrue(result['history_retained'])
                self.assertEqual(result['ready_format'],2 if scenario=='safe' else None)
                self.assertEqual(result['stopped'],scenario!='not-stopped')


    def test_actual_recovery_play_resumes_reviewed_legacy_intermediate_states(self):
        source=yaml.safe_load((ROOT/'templates/ansible/monad/recover-data-filesystem.yml').read_text())[0]
        for scenario in ('initial','selected','initial-payload','selected-wrong-uuid'):
            with self.subTest(scenario=scenario),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);result_file=root/'result.json';driver=root/'driver.py'
                driver.write_text('''import json,sys
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,TESTS)
import incomplete_data_recovery as tests
t=tests.Recovery();t.setUp()
try:
 original=t.old_initial() if SCENARIO.startswith('initial') else t.old_selection('handoff')
 if SCENARIO=='initial-payload':(t.root/'data/unknown-history').write_bytes(b'retain native payload')
 request=json.load(sys.stdin)
 assert request['operation']=='recover-data-filesystem'
 try:result=t.recover(request['original_uuid'])
 finally:
  expected=SCENARIO in ('initial','selected')
  if expected:t.preserved(original)
  else:
   for name,raw in original.items():assert (t.root/name).read_bytes()==raw
  Path(RESULT).write_text(json.dumps({'originals_retained':True,'ready':t.state.get('data-ready.json') if (t.root/'data-ready.json').exists() else None}))
 print(json.dumps(result))
finally:t.doCleanups()
'''.replace('TESTS',repr(str(ROOT/'tests'))).replace('SCENARIO',repr(scenario)).replace('RESULT',repr(str(result_file))))
                task=copy.deepcopy(source['tasks'][0]);task['ansible.builtin.command']['argv']=[sys.executable,'-I',str(driver),'within-run']
                identifier='00000000-0000-0000-0000-00000000000'+('3' if scenario.endswith('wrong-uuid') else '2' if scenario.startswith('selected') else '1')
                play=root/'play.yml';play.write_text(yaml.safe_dump([{'hosts':'all','gather_facts':False,
                    'vars':{'monad_request':{'contract':{'owner':'inert-owner','network':'testnet'},'original_uuid':identifier}},'tasks':[task]}]))
                completed=subprocess.run([sys.executable,'-I','-m','ansible.cli.playbook','-i','localhost,','-c','local',str(play)],
                    env=dict(os.environ,ANSIBLE_NOCOLOR='1',PYTHONDONTWRITEBYTECODE='1'),capture_output=True,text=True,timeout=60)
                self.assertEqual(completed.returncode==0,scenario in ('initial','selected'),completed.stdout+completed.stderr)
                result=json.loads(result_file.read_bytes());self.assertTrue(result['originals_retained'])
                if scenario in ('initial','selected'):
                    self.assertEqual(result['ready']['format'],2);self.assertEqual(result['ready']['final'],scenario=='selected')


if __name__=='__main__':unittest.main()
