# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual preparation/credential guards under inert kernel budget drift."""
import importlib.util
import os
from pathlib import Path
import sys
import unittest
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'templates/scripts'))


@unittest.skipUnless(os.name=='posix','runtime resource guard uses Linux kernel-shaped fixtures')
class Resources(unittest.TestCase):
    def setUp(self):
        import host_resources
        self.module=host_resources
        spec=importlib.util.spec_from_file_location('polygon_resources_control_fixture',ROOT/'tests/control.py')
        fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
        self.fixture=fixture.Lifecycle();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.state=self.fixture.state;self.expected=self.fixture.contract
        self.fixture.activate()
    def write(self,name,value):
        path=self.state.path(name);path.parent.mkdir(parents=True,exist_ok=True);path.write_text(value)
    def group(self,name,cpu='max 100000',memory='max'):
        self.write('/sys/fs/cgroup'+name+'/cpu.max',cpu+'\n')
        self.write('/sys/fs/cgroup'+name+'/memory.max',memory+'\n')
        self.write('/sys/fs/cgroup'+name+'/cgroup.subtree_control','cpu memory\n')
    def test_reported_resource_floor_is_checked_again_before_credentials(self):
        result=self.state.resources(self.expected)
        self.assertEqual(result['effective_logical_cpus'],16)
        self.assertEqual(result['minimum_reported_memory_kib'],15000000)
        self.fixture.control.credential_condition(self.expected,'bor')
        self.write('/proc/self/status','Cpus_allowed_list: 0-7\n')
        with self.assertRaises(ValueError):self.fixture.control.credential_condition(self.expected,'bor')
        self.write('/proc/self/status','Cpus_allowed_list: 0-15\n')
        self.write('/proc/meminfo','MemTotal: 8000000 kB\n')
        with self.assertRaises(ValueError):self.fixture.control.runtime(self.expected,'credential')
    def test_parent_cgroup_limits_cannot_hide_behind_an_unlimited_native_child(self):
        self.write('/proc/self/cgroup','0::/system.slice/polygon-bor.service\n')
        self.group('/system.slice');self.group('/system.slice/polygon-bor.service')
        self.state.resources(self.expected)
        for cpu,memory in [('800000 100000','max'),('max 100000',str(8*1024**3))]:
            self.group('/system.slice',cpu,memory)
            with self.assertRaises(ValueError):self.fixture.control.credential_condition(self.expected,'bor')
        self.group('/system.slice');self.state.resources(self.expected)
    def test_failed_prepare_changes_no_intent_but_low_budget_never_blocks_owned_stop(self):
        original=self.state.path('/etc/polygon/intent.json').read_bytes()
        self.write('/proc/self/status','Cpus_allowed_list: 0-1\n')
        with self.assertRaises(ValueError):self.fixture.control.prepare(dict(self.fixture.request,intent='c'*32))
        self.assertEqual(self.state.path('/etc/polygon/intent.json').read_bytes(),original)
        self.assertTrue(self.fixture.control.stop(self.expected)['stopped'])
        self.assertEqual(self.fixture.running,set())
    def test_unknown_kernel_budget_and_os_inputs_fail_closed(self):
        defaults={name:self.state.path(name).read_bytes() for name in
            ('/etc/os-release','/proc/meminfo','/proc/self/status','/proc/self/cgroup','/sys/fs/cgroup/cpu.max')}
        for name,value in [('/etc/os-release','ID=ubuntu\nVERSION_ID="22.04"\n'),
                ('/proc/meminfo','MemTotal: 64000000 kB\nMemTotal: 64000000 kB\n'),
                ('/proc/self/status','Cpus_allowed_list: 0-15,15\n'),
                ('/proc/self/cgroup','0::/../escape\n'),('/sys/fs/cgroup/cpu.max','unknown 100000\n')]:
            self.write(name,value)
            with self.assertRaises(ValueError):self.state.resources(self.expected)
            self.state.path(name).write_bytes(defaults[name])
        source=self.state.path('/sys/fs/cgroup/cpu.max');source.unlink();source.symlink_to(self.state.path('/sys/fs/cgroup/memory.max'))
        with self.assertRaises(ValueError):self.state.resources(self.expected)
    def test_real_hierarchy_root_has_no_max_files_and_disabled_child_inherits_parent(self):
        for name in ('cpu.max','memory.max'):self.state.path('/sys/fs/cgroup/'+name).unlink()
        self.state.resources(self.expected)
        self.write('/proc/self/cgroup','0::/system.slice/child\n')
        self.group('/system.slice');self.group('/system.slice/child')
        self.write('/sys/fs/cgroup/system.slice/cgroup.subtree_control','memory\n')
        self.state.path('/sys/fs/cgroup/system.slice/child/cpu.max').unlink()
        self.state.resources(self.expected)
        self.write('/sys/fs/cgroup/system.slice/cpu.max','800000 100000\n')
        with self.assertRaises(ValueError):self.state.resources(self.expected)

    def test_mainnet_uses_its_own_larger_usable_memory_floor(self):
        self.write('/proc/meminfo','MemTotal: 16000000 kB\n')
        self.state.resources(self.expected)
        with self.assertRaises(ValueError):self.state.resources(dict(self.expected,network='mainnet'))
        self.write('/proc/meminfo','MemTotal: 64000000 kB\n')
        self.assertEqual(self.state.resources(dict(self.expected,network='mainnet'))['minimum_reported_memory_kib'],60000000)


if __name__=='__main__':unittest.main()
