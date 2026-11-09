# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual Rust bundle, pinned Ansible request rendering and controller dispatch.

Native acquisition, host facts/NSS and service commands are inert fixtures. The
published helper/config/unit/source receipts and operation locks are real files.
"""
import sys
sys.dont_write_bytecode=True
import contextlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
try:
    import yaml
    from ansible.parsing.dataloader import DataLoader
    from ansible.template import Templar
except ImportError:
    print('SKIP: pinned Ansible interpreter is required for actual play rendering')
    sys.exit(0)

payload=json.load(sys.stdin)
TEMP=tempfile.TemporaryDirectory()
bundle=Path(TEMP.name).resolve()/'bundle';bundle.mkdir()
with tarfile.open(sys.argv.pop(1),'r:gz') as archive:
    for member in archive:
        assert member.isfile() and not Path(member.name).is_absolute() and '..' not in Path(member.name).parts
        path=bundle/member.name;path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(archive.extractfile(member).read());path.chmod(0o600)
source=bundle/'node/control.py'
sys.argv.insert(1,str(source))
import lifecycle
c=lifecycle.c


class Play(unittest.TestCase):
    def setUp(self):
        self.fixture=lifecycle.HostTests('runTest');self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.query=self.fixture.request('authorize');self.query['unit']=payload['unit']
        patch.object(c,'account_ensure',side_effect=c.retained_account).start()
        patch.object(c,'prepare_data',return_value=None).start()
        original_run=c.run
        def run(argv,**kwargs):
            if argv[0]=='/usr/bin/findmnt':
                if '--submounts' in argv:return json.dumps({'filesystems':[{'target':'/'}]}).encode()
                return json.dumps({'filesystems':[{'uuid':self.fixture.state['layout']['root']['uuid'],'fstype':'ext4','options':'rw'}]}).encode()
            return original_run(argv,**kwargs)
        patch.object(c,'run',side_effect=run).start()
        (c.ROOT/'data').chmod(0o700)
        self.play=yaml.safe_load((bundle/'node/deploy.yml').read_text())[0]
        self.tasks=[]
        for task in self.play['tasks']:
            self.tasks.extend(task.get('block',[task]))
        self.calls=[task for task in self.tasks if task.get('ansible.builtin.command',{}).get('argv',[])[-1:] == ['{{ playbook_dir }}/control.py']]
        self.variables={'playbook_dir':str(bundle/'node'),'btc_request':self.query,'btc_phase':'deploy'}
        self.templar=Templar(loader=DataLoader(),variables=self.variables)

    def invoke(self,task):
        args=self.templar.template(task['ansible.builtin.command'])
        self.assertEqual(args['argv'],['/usr/bin/python3','-I',str(source)])
        request=args['stdin']
        if not isinstance(request,str):request=json.dumps(request)
        output=io.StringIO()
        with patch.object(c.sys,'stdin',type('Input',(),{'buffer':io.BytesIO(request.encode())})()),patch.object(c.os,'geteuid',return_value=0),contextlib.redirect_stdout(output):
            c.main()
        return json.loads(output.getvalue())

    def test_actual_rendered_deployment_promotes_only_its_sealed_source_and_numeric_unit(self):
        self.assertEqual(len(self.calls),4)
        c.locked(self.query)
        results=[self.invoke(task) for task in self.calls]
        self.assertTrue(results[-2]['activation_pending'])
        self.assertEqual(c.HELPER.read_bytes(),source.read_bytes())
        self.assertEqual(c.UNIT_PATH.read_text(),payload['unit'])
        self.assertEqual(c.read_state()['phase'],'installed')
        self.assertTrue((c.ROOT/'source-floor.json').is_file())
        self.assertFalse(any('ansible.builtin.copy' in task for task in self.tasks))

    def test_actual_late_play_stage_and_helper_publication_are_cancelled(self):
        c.locked(self.query)
        original_unit=c.UNIT_PATH.read_bytes()
        self.invoke(self.calls[0]);self.invoke(self.calls[1])
        c.locked(self.fixture.request('stop'))
        with self.assertRaises(c.Refused):self.invoke(self.calls[2])
        self.assertFalse(c.HELPER.exists());self.assertEqual(c.UNIT_PATH.read_bytes(),original_unit)
        with self.assertRaises(c.Refused):self.invoke(self.calls[0])
        self.assertEqual(self.fixture.service,'inactive')


if __name__=='__main__':
    try:unittest.main()
    finally:TEMP.cleanup()
