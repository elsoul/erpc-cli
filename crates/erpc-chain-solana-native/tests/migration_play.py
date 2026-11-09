# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Pinned Ansible public-stage composition; only an inert tempfile observer runs."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
sys.dont_write_bytecode=True
try:
    import ansible.release
    import yaml
    QUALIFIED=ansible.release.__version__=='2.18.19'
except ImportError:
    QUALIFIED=False
SOURCE=Path(__file__).resolve().parents[1]/'templates/ansible/solana-native/migration.yml'


@unittest.skipUnless(QUALIFIED,'use the qualified hash-pinned Ansible2.18.19 interpreter')
class PublicPlay(unittest.TestCase):
    def execute(self,action,extra=False):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);play=yaml.safe_load(SOURCE.read_text())
            self.assertEqual(len(play),1);self.assertTrue(play[0]['become'])
            # No sudo/root action in this test. Keep both production tasks and
            # their expressions/argv/stdin unchanged; model only root ownership
            # by using the test account and an inert public-result observer.
            play[0]['become']=False
            (root/'play.yml').write_text(yaml.safe_dump(play))
            marker=root/'observed.json'
            loader="import json,pathlib,sys; value=json.load(sys.stdin); pathlib.Path("+repr(str(marker))+").write_text(json.dumps({'argv':sys.argv[1:],'request':value}))"
            request={'action':action,'intent':'a'*32,'legacy':{'public':'inert value with quote \\" and newline\n'},
                     'contract':{'name':'fixture'},'ssh_port':2222}
            if action in ('migration-prepare-cutover','migration-finalize'):request['cutover']={'receipt':{'public':'fixture'},'provider_version':3 if action=='migration-finalize' else None}
            if extra:request['key_file']='inert concealed decoy'
            inventory={'all':{'hosts':{'fixture':{'ansible_connection':'local','ansible_python_interpreter':sys.executable,
                'solana_native_loader':loader,'solana_native_request':request}}}}
            (root/'inventory.json').write_text(json.dumps(inventory))
            (root/'ansible.cfg').write_text('[defaults]\nretry_files_enabled=False\ninterpreter_python=auto_silent\n[privilege_escalation]\nbecome=False\n')
            locale='en_US.UTF-8' if sys.platform=='darwin' else 'C.UTF-8'
            environment={'PATH':'/usr/bin:/bin','LANG':locale,'LC_ALL':locale,'PYTHONDONTWRITEBYTECODE':'1',
                         'ANSIBLE_CONFIG':str(root/'ansible.cfg'),'ANSIBLE_LOCAL_TEMP':str(root/'ansible-local'),
                         'ANSIBLE_REMOTE_TEMP':str(root/'ansible-remote')}
            result=subprocess.run([sys.executable,'-m','ansible.cli.playbook','-i',str(root/'inventory.json'),str(root/'play.yml')],
                cwd=root,env=environment,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60,check=False)
            observed=json.loads(marker.read_bytes()) if marker.exists() else None
            self.assertNotIn(b'inert concealed decoy',result.stdout+result.stderr)
            return result,observed,request
    def test_every_public_mutation_passes_exact_json_stdin_and_fixed_controller_argv(self):
        for action in ('migration-reserve','migration-retire','migration-copy','migration-promote-data','migration-custody','migration-prepare-cutover','migration-finalize'):
            with self.subTest(action=action):
                result,observed,request=self.execute(action)
                self.assertEqual(result.returncode,0,result.stdout.decode()+result.stderr.decode())
                self.assertEqual(observed['request'],request);self.assertEqual(observed['argv'][1:],['play'])
                self.assertTrue(observed['argv'][0].endswith('/../../node/native_runtime_control.py'))
    def test_direct_confirmation_and_unqualified_secret_or_runtime_actions_never_execute(self):
        for action in ('migration-confirm-manager','migration-status','import-identity','migration-export-original','migration-export','activate-runtime'):
            with self.subTest(action=action):
                result,observed,_=self.execute(action);self.assertNotEqual(result.returncode,0);self.assertIsNone(observed)
                self.assertIn(b'Original public migration request differs from the sealed stage',result.stdout)
        result,observed,_=self.execute('migration-retire',extra=True)
        self.assertNotEqual(result.returncode,0);self.assertIsNone(observed)
        self.assertIn(b'Original public migration request differs from the sealed stage',result.stdout)

if __name__=='__main__':unittest.main()
