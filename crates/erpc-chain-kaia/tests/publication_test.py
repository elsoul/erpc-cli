# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual file/copy ordering with temp paths/UID, inert host calls and no sudo."""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
sys.dont_write_bytecode=True
try:
    import yaml
except ImportError:
    yaml=None
SOURCE=Path(__file__).parents[1]/'templates/node'
ANSIBLE=shutil.which('ansible-playbook')

@unittest.skipUnless(yaml is not None and ANSIBLE,'optional Ansible/PyYAML integration runtime')
class Publication(unittest.TestCase):
    def exercise(self,kind,stage):
        with tempfile.TemporaryDirectory(prefix='kaia-publication-') as directory:
            root=Path(directory);namespace=root/'lib/erpc';namespace.mkdir(parents=True)
            state=root/'state';state.mkdir();operation=root/'operation';operation.mkdir()
            paths={'ROOT':state,'TRUST_ANCHOR':root,'HELPERS':namespace/'kaia','CONF':root/'config',
                   'LAUNCHER':namespace/'kaia-control','PROC':root/'proc','UNIT_DIRECTORY':root/'units','OPERATION_ROOT':operation,'LOCK':root/'lock'}
            catalog=json.loads((SOURCE/'catalog.json').read_text());profile=catalog['networks']['kairos']
            owner={'owner':'fixture','network':'kairos','role':'rpc','platform':'amd64','storage':'full',
                   'snapshot':'genesis','version':catalog['version'],'commit':catalog['commit'],
                   'image':catalog['image'],'genesis':profile['genesis'],
                   'config_id':'a'*64,'phase':'prepared','startup_revoked':True}
            if stage=='begin-install':owner.update(deploy_intent='b'*32,deploy_target={key:owner[key] for key in ('version','commit','image','config_id')})
            path=state/'owner.json'
            if stage!='initial':path.write_text(json.dumps(owner));path.chmod(0o600)
            before=path.read_bytes() if path.exists() else None
            source=(SOURCE/'control.py').read_text()
            for name,value in paths.items():
                source=re.sub(r'^'+name+r'\s*=\s*Path\([^\n]+\)$',name+' = Path('+repr(str(value))+')',source,flags=re.M)
            source=source.replace('ROOT_UID=0','ROOT_UID='+str(os.getuid())).replace('os.geteuid()==0','os.geteuid()==ROOT_UID')
            source=source.replace("if __name__=='__main__':", """def fixture_lookup(name):raise KeyError(name)
pwd.getpwnam=fixture_lookup
grp.getgrnam=fixture_lookup
trusted_imports=lambda path: sys.path.append(str(path))
loaded=lambda: False
check_container=lambda state: None
capacity=lambda state,installation=False: 0
if __name__=='__main__':""")
            (root/'control.py').write_text(source)
            for name in ('bootstrap.py','launcher.py','custody.py','corecell.py','coreaccount.py'):
                shutil.copyfile(SOURCE/name,root/name)
            shutil.copyfile(SOURCE/'catalog.json',root/'catalog.json')
            digest=hashlib.sha256(b''.join((root/name).read_bytes() for name in ('control.py','bootstrap.py','custody.py','corecell.py','coreaccount.py','catalog.json'))).hexdigest()
            if kind=='writable-ancestor':namespace.chmod(0o777)
            if kind=='symlink':
                target=root/'outside';target.mkdir();paths['HELPERS'].symlink_to(target,target_is_directory=True)
            play=copy.deepcopy(yaml.safe_load((SOURCE/'prepare.yml').read_text()))
            tasks=play[0]['tasks'];play[0]['become']=False
            play[0]['tasks']=[tasks[0],*[task for task in tasks if 'ansible.builtin.file' in task or 'ansible.builtin.copy' in task],next(task for task in tasks if task['name']=='Verify publication against the sealed carried source')]
            replacements={'/usr/local/lib/erpc/kaia-control':str(paths['LAUNCHER']),'/usr/local/lib/erpc/kaia':str(paths['HELPERS']),'/usr/local/lib/erpc':str(namespace),'/etc/erpc/kaia':str(paths['CONF'])}
            for task in play[0]['tasks']:
                for module in ('ansible.builtin.file','ansible.builtin.copy'):
                    if module in task:
                        task[module]['owner']=str(os.getuid());task[module]['group']=str(os.getgid())
            serialized=yaml.safe_dump(play)
            for old,new in replacements.items():serialized=serialized.replace(old,new)
            play=yaml.safe_load(serialized)
            if kind=='substitution':
                play[0]['tasks'].insert(-1,{'name':'Inert substituted controller', 'ansible.builtin.copy':{
                    'content':'raise RuntimeError("must not execute")\n','dest':str(paths['HELPERS']/'releases'/digest/'control.py'),'mode':'0644'}})
            (root/'play.yml').write_text(yaml.safe_dump(play))
            variables={'kaia_request':dict(owner,intent='b'*32),'kaia_prepare_action':'begin-install' if stage=='begin-install' else 'prepare','kaia_helper_sha':digest}
            (root/'vars.json').write_text(json.dumps(variables))
            result=subprocess.run([ANSIBLE,'-i','localhost,','-c','local',str(root/'play.yml'),'-e','@'+str(root/'vars.json')],capture_output=True,text=True,timeout=90,check=False)
            if kind=='safe':
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                self.assertEqual((paths['HELPERS']/'current/control.py').read_text(),source)
            else:
                self.assertNotEqual(result.returncode,0,result.stdout+result.stderr)
                if kind!='substitution':
                    self.assertEqual(path.read_bytes() if path.exists() else None,before)
                    if kind=='writable-ancestor':self.assertEqual(namespace.stat().st_mode&0o777,0o777)
                    if kind=='symlink':self.assertTrue(paths['HELPERS'].is_symlink())
                else:self.assertIn('differs from its sealed source',result.stdout)

    def test_initial_retry_and_update_publish_only_through_protected_ancestors(self):
        for stage in ('initial','retry','begin-install'):
            for kind in ('safe','writable-ancestor','symlink'):
                with self.subTest(stage=stage,kind=kind):self.exercise(kind,stage)

    def test_final_carried_guard_rejects_substituted_installed_controller(self):
        self.exercise('substitution','initial')

if __name__=='__main__':unittest.main()
