# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Production play requests/controller dispatch with modeled package and PID1 effects."""
import json
from pathlib import Path
import sys
import unittest
sys.dont_write_bytecode=True
try:
    import yaml
    from jinja2 import Environment,StrictUndefined
except ImportError:
    yaml=None
sys.path.insert(0,str(Path(__file__).parent))
import gateway as fixtures
import native_gateway as gateway
import native_runtime_control as control


@unittest.skipUnless(yaml,'strict play rendering requires the pinned Ansible Python environment')
class PackagePlay(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.Gateway();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.template=Path(__file__).parents[1]/'templates/ansible/solana-native/initialize.yml'
        self.tasks=yaml.safe_load(self.template.read_text())[0]['tasks']
        self.env=Environment(undefined=StrictUndefined)
        self.env.filters['combine']=lambda left,right:dict(left,**right)
        self.env.filters['to_json']=json.dumps

    def execute(self, damage=None):
        events=[];selected=False
        for task in self.tasks:
            command=task.get('ansible.builtin.command')
            if command and 'gateway-package-' in command.get('stdin',''):
                selected=True
                # Render the actual production stdin, then dispatch the real
                # controller. Only root ownership, NSS and systemctl are modeled
                # by the shared inert fixture. No package or service is executed.
                assert command['argv'][0:3]==['/usr/bin/python3','-I','-c']
                assert command['argv'][-1]=='play'
                request=json.loads(self.env.from_string(command['stdin']).render(
                    solana_native_request={'action':'prepare','contract':self.fixture.contract}))
                events.append(request['action'])
                control.dispatch(self.fixture.state,self.fixture.contract,request,self.fixture.systemctl)
            elif selected and 'ansible.builtin.systemd_service' in task:
                values=task['ansible.builtin.systemd_service']
                if values['name']!='nginx.service':break
                self.assertEqual(values,{'name':'nginx.service','masked':True,'daemon_reload':True})
                mask=gateway.UNITS/'nginx.service'
                if not mask.is_symlink():mask.symlink_to('/dev/null')
                self.fixture.distribution.update(LoadState='masked',UnitFileState='masked',FragmentPath='/dev/null')
                events.append('persistent-mask')
            elif selected and 'ansible.builtin.apt' in task:
                values=task['ansible.builtin.apt'];self.assertEqual(values['name'],['nginx','util-linux'])
                self.assertEqual(values['policy_rc_d'],101)
                gateway.distribution_mask(self.fixture.state,self.fixture.contract)
                events.append('package-hooks')
                # Model the vendor's enable-at-boot hook. A persistent mask must
                # remain the governing authority even when vendor wants links
                # would otherwise enable a default root master.
                if damage=='unmask':
                    (gateway.UNITS/'nginx.service').unlink()
                    self.fixture.distribution.update(LoadState='loaded',UnitFileState='enabled',FragmentPath='/usr/lib/systemd/system/nginx.service')
                if damage=='start':self.fixture.distribution.update(ActiveState='active',MainPID='77')
        self.assertEqual(events,['gateway-package-prepare','persistent-mask','gateway-package-check','package-hooks','gateway-package-check'])
        return events

    def test_fresh_install_retry_and_package_enable_hook_keep_default_daemon_masked(self):
        (gateway.UNITS/'nginx.service').unlink();(self.fixture.directory/'gateway-distribution.json').unlink()
        self.fixture.distribution.update(LoadState='not-found',UnitFileState='',FragmentPath='')
        self.execute();self.execute()
        self.assertTrue((gateway.UNITS/'nginx.service').is_symlink())
        self.assertFalse(any(call[0] in ('start','stop') for call in self.fixture.calls))

    def test_package_unmask_is_rejected_by_the_actual_postinstall_controller_request(self):
        with self.assertRaises(ValueError):self.execute('unmask')

    def test_package_start_is_rejected_by_the_actual_postinstall_controller_request(self):
        with self.assertRaises(ValueError):self.execute('start')

    def test_existing_active_default_service_is_not_stopped_or_adopted(self):
        self.fixture.distribution.update(ActiveState='active',MainPID='77')
        with self.assertRaises(ValueError):self.execute()
        self.assertTrue(all(call[0]=='show' for call in self.fixture.calls))


if __name__=='__main__':unittest.main()
