# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Execute recovery file/copy ordering in temporary fixtures, without sudo/hosts.

Paths and expected root UID are substituted for the current test user. Host
provisioning tasks are omitted and systemd/capacity are inert fixtures; namespace
checks, the actual file/copy tasks and sealed-source publication guards run.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
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
class Recovery(unittest.TestCase):
    def exercise(self,kind,stage="control"):
        with tempfile.TemporaryDirectory(prefix='nitro-recovery-') as directory:
            root=Path(directory);namespace=root/'lib/erpc';namespace.parent.mkdir()
            state=root/'state';state.mkdir();operation=root/'operation';operation.mkdir()
            marker=root/'unexpected-execution'
            spec=importlib.util.spec_from_file_location('controller',SOURCE/'control.py')
            control=importlib.util.module_from_spec(spec);spec.loader.exec_module(control)
            owner={'owner':'fixture','family':'arbitrum','network':'sepolia','platform':'amd64',
                   'version':control.VERSION,'commit':control.COMMIT,'config_id':'a'*64,'phase':'installed'}
            owner['installed']=control.pin(owner)
            if stage=='retry':owner['phase']='prepared';owner.pop('installed')
            if stage=='begin-install':owner.update(deploy_intent='b'*32,deploy_target=control.pin(owner))
            path=state/'owner.json';path.write_text(json.dumps(owner));path.chmod(0o600)
            before=path.read_bytes()
            if stage=='initial':path.unlink();before=None
            source=(SOURCE/'control.py').read_text()
            for name,value in [('ROOT',state),('TRUST_ANCHOR',root),('NAMESPACE',namespace),
                               ('OPERATION_ROOT',operation),('LOCK',root/'lock')]:
                import re
                source=re.sub(r'^'+name+r' = Path\([^\n]+\)$',name+' = Path('+repr(str(value))+')',source,flags=re.M)
            source=source.replace('ROOT_UID = 0','ROOT_UID = '+str(os.getuid()))
            source=source.replace('os.geteuid() == 0','os.geteuid() == ROOT_UID')
            source=source.replace("'/usr/bin/docker'",repr(str(root/'no-docker')))
            source=source.replace("Path('/var/lib/docker/containers')",'Path('+repr(str(root/'no-containers'))+')')
            source=source.replace("if __name__ == '__main__':", """def fixture_command(argv, **kwargs):
    if argv[:2] == ['systemctl', 'show']:return b'not-found'
    if argv[:2] == ['du', '-sx']:return b'0 fixture'
    raise RuntimeError('unexpected native fixture command')
run = fixture_command
shutil.disk_usage = lambda path: type('Capacity', (), {'free': 20_000_000_000_000})()
if __name__ == '__main__':""")
            carried=root/'control.py';carried.write_text(source)
            (root/'upstreams.py').write_text('# inert reviewed transport fixture\n')
            hostile='from pathlib import Path\nPath('+repr(str(marker))+').write_text("unexpected")\n'
            if kind!='missing':
                namespace.mkdir();(namespace/'nitro-control').write_text(hostile)
            if kind=='writable-namespace':namespace.chmod(0o777)
            if kind=='writable-ancestor':namespace.parent.chmod(0o777)
            if kind=='writable-sibling':
                sibling=namespace/'rpc-firewall.py';sibling.write_text(hostile);sibling.chmod(0o666)
            if kind=='sibling-symlink':(namespace/'rpc-firewall.py').symlink_to(carried)
            if kind=='symlink':
                destination=root/'redirect';namespace.rename(destination);namespace.symlink_to(destination,target_is_directory=True)
            if kind=='target-symlink':
                target=namespace/'nitro-control';target.unlink();target.symlink_to(carried)
            play=copy.deepcopy(yaml.safe_load((SOURCE/('control.yml' if stage=='control' else 'prepare.yml')).read_text()))
            if stage!='control':
                tasks=play[0]['tasks']
                directory=next(task for task in tasks if 'ansible.builtin.file' in task)
                directory['loop']=[item for item in directory['loop'] if item['path']=='/usr/local/lib/erpc']
                copied=next(task for task in tasks if 'ansible.builtin.copy' in task)
                play[0]['tasks']=[tasks[0],directory,copied,tasks[-1]]
            play[0]['become']=False
            for task in play[0]['tasks']:
                for module in ('ansible.builtin.file','ansible.builtin.copy'):
                    if module in task:
                        task[module]['owner']=str(os.getuid());task[module]['group']=str(os.getgid())
                        for item in task.get('loop',[]):
                            if isinstance(item,dict) and 'path' in item:item['path']=item['path'].replace('/usr/local/lib/erpc',str(namespace))
                        for field in ('path','dest'):
                            if field in task[module]:task[module][field]=task[module][field].replace('/usr/local/lib/erpc',str(namespace))
            if kind in ('post-copy-substitution','post-copy-proxy-substitution'):
                play[0]['tasks'].insert(-1,{'name':'Inert post-copy content substitution',
                    'ansible.builtin.copy':{'content':hostile,'dest':str(namespace/('nitro-upstreams.py' if kind=='post-copy-proxy-substitution' else 'nitro-control')),'mode':'0644'}})
            (root/'play.yml').write_text(yaml.safe_dump(play))
            request=dict(owner,action='authorize-deploy',generation=0,intent='b'*32)
            variables=root/'vars.json';variables.write_text(json.dumps({'nitro_request':request,'nitro_control_check':'check-authorize','nitro_prepare_action':'begin-install' if stage=='begin-install' else 'prepare'}))
            result=subprocess.run([ANSIBLE,'-i','localhost,','-c','local',str(root/'play.yml'),'-e','@'+str(variables)],
                                  capture_output=True,text=True,timeout=90,check=False)
            self.assertFalse(marker.exists(),result.stdout+result.stderr)
            if kind in ('missing','legacy'):
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                self.assertEqual((namespace/'nitro-control').read_text(),source)
                saved=json.loads(path.read_text())
                expected='installed' if stage=='control' else 'installing' if stage=='begin-install' else 'prepared'
                self.assertEqual(saved['phase'],expected if stage=='retry' else 'v2:'+expected)
                if stage=='control':self.assertEqual(saved['deploy_intent'],'b'*32)
                else:self.assertEqual((namespace/'nitro-upstreams.py').read_text(),(root/'upstreams.py').read_text())
            else:
                self.assertNotEqual(result.returncode,0,result.stdout+result.stderr)
                if kind.startswith('post-copy') and stage!='control':
                    # Reservation/install fencing precedes publication; failed
                    # final verification must never report completion/activation.
                    self.assertNotIn('published from the sealed source',result.stdout)
                elif before is None:self.assertFalse(path.exists())
                else:self.assertEqual(path.read_bytes(),before)
                if kind=='writable-namespace':self.assertEqual(namespace.stat().st_mode&0o777,0o777)
                if kind=='writable-ancestor':self.assertEqual(namespace.parent.stat().st_mode&0o777,0o777)
                if kind=='symlink':self.assertTrue(namespace.is_symlink())

    def test_missing_and_protected_legacy_controller_are_upgraded_without_executing_legacy_code(self):
        for kind in ('missing','legacy'):
            with self.subTest(kind=kind):self.exercise(kind)

    def test_unsafe_existing_namespace_and_ancestors_are_refused_before_file_copy(self):
        for kind in ('writable-namespace','writable-ancestor','writable-sibling','sibling-symlink','symlink','target-symlink'):
            with self.subTest(kind=kind):self.exercise(kind)

    def test_post_copy_substitution_is_not_executed_and_cannot_authorize_an_owner(self):
        self.exercise('post-copy-substitution')

    def test_ordinary_initial_retry_and_begin_install_validate_before_publication(self):
        for stage in ('initial','retry','begin-install'):
            for kind in ('missing','writable-ancestor','symlink'):
                with self.subTest(stage=stage,kind=kind):self.exercise(kind,stage)

    def test_ordinary_prepare_verifies_both_published_files_from_sealed_source(self):
        for kind in ('post-copy-substitution','post-copy-proxy-substitution'):
            with self.subTest(kind=kind):self.exercise(kind,'initial')

if __name__=='__main__':unittest.main()
