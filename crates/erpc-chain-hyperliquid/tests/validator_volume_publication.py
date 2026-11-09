# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual carried Ansible recovery task with inert original storage/custody fixtures."""
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


class Publication(unittest.TestCase):
    def test_carried_task_changes_only_original_stopped_volume_authority(self):
        source=yaml.safe_load((ROOT/'templates/ansible/hyperliquid/recover-private-filesystem.yml').read_text())[0]
        self.assertEqual(len(source['tasks']),1)
        for scenario in ('safe','wrong-uuid','not-stopped','foreign-inode'):
            with self.subTest(scenario=scenario),tempfile.TemporaryDirectory() as temporary:
                directory=Path(temporary);output=directory/'result.json';driver=directory/'driver.py'
                driver.write_text('''import json,sys
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,TESTS)
import validator_volume as tests
t=tests.Volume();t.setUp()
try:
 path,original=t.legacy();before=path.read_bytes()
 if SCENARIO=='not-stopped':(t.root/'stopped').unlink()
 if SCENARIO=='foreign-inode':
  saved=t.state.get('validator-native-path.json');saved['inode']+=1;t.state.put('validator-native-path.json',saved)
 request=json.load(sys.stdin)
 assert request['action']=='recover-validator-filesystem'
 try:result=t.invoke(request['original_uuid'])
 finally:
  assert path.read_bytes()==before
  Path(OUTPUT).write_text(json.dumps({'retained':True,'format':t.state.get('validator-native-path.json').get('format'),'stopped':(t.root/'stopped').exists()}))
 print(json.dumps(result))
finally:t.doCleanups()
'''.replace('TESTS',repr(str(ROOT/'tests'))).replace('SCENARIO',repr(scenario)).replace('OUTPUT',repr(str(output))))
                task=copy.deepcopy(source['tasks'][0])
                task['ansible.builtin.command']['argv']=[sys.executable,'-I',str(driver),'play']
                identifier='00000000-0000-0000-0000-00000000000'+('2' if scenario=='wrong-uuid' else '1')
                request={'original_uuid':identifier,'contract':{'owner':'inert original'}}
                play=directory/'play.yml';play.write_text(yaml.safe_dump([{'hosts':'all','gather_facts':False,
                    'vars':{'hyperliquid_request':request},'tasks':[task]}]))
                result=subprocess.run([sys.executable,'-I','-m','ansible.cli.playbook','-i','localhost,','-c','local',str(play)],
                    capture_output=True,text=True,timeout=60,env=dict(os.environ,ANSIBLE_NOCOLOR='1',PYTHONDONTWRITEBYTECODE='1'))
                self.assertEqual(result.returncode==0,scenario=='safe',result.stdout+result.stderr)
                record=json.loads(output.read_bytes());self.assertTrue(record['retained'])
                self.assertEqual(record['format'],2 if scenario=='safe' else None)
                self.assertEqual(record['stopped'],scenario!='not-stopped')


if __name__=='__main__':unittest.main()
