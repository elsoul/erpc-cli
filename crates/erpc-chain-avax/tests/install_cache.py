# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual Ansible cache qualification with inert bytes; no binary/network execution."""
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
sys.dont_write_bytecode=True
try:import yaml
except ImportError:yaml=None
ROOT=Path(__file__).resolve().parents[1]

@unittest.skipUnless(yaml and shutil.which('ansible-playbook'),'optional pinned Ansible runtime')
class Cache(unittest.TestCase):
    def test_only_authenticated_matching_bytes_skip_reverification(self):
        source=yaml.safe_load((ROOT/'templates/ansible/avax/tasks/install.yml').read_text())
        stop=next(index for index,task in enumerate(source) if task['name']=='Install a missing verified release')
        for kind,expected in [('qualified',True),('legacy',False),('changed-binary',False),('missing-binary',False)]:
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as directory:
                path=Path(directory);release=path/'v1.15.2';release.mkdir()
                binary=release/'avalanchego';binary.write_bytes(b'authenticated inert bytes')
                digest=hashlib.sha256(binary.read_bytes()).hexdigest()
                (release/'.verified-sha256').write_text('b'*64)
                if kind!='legacy':(release/'.verified-binary-sha256').write_text(digest)
                if kind=='changed-binary':binary.write_bytes(b'changed inert bytes')
                if kind=='missing-binary':binary.unlink()
                tasks=source[:stop]+[{'ansible.builtin.assert':{'that':'avax_reuse_verified == expected_reuse'}}]
                play=[{'hosts':'all','connection':'local','gather_facts':False,'vars':{
                    'ansible_python_interpreter':sys.executable,'avax_release_dir':str(release),'avax_sha256':'b'*64,'expected_reuse':expected},'tasks':tasks}]
                target=path/'cache.yml';target.write_text(yaml.safe_dump(play))
                result=subprocess.run(['ansible-playbook','-i','localhost,',str(target)],capture_output=True,text=True,timeout=60)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)

if __name__=='__main__':unittest.main()
