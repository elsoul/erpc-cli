# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Rendered fresh gateway filesystem contract, without running nginx or PID1.

Noble packaging a39215f uses /var/lib/nginx for all five HTTP temp defaults.
nginx 84cd721 ngx_create_paths initializes registered paths even for unused
upstream modules. The fixture models that path selection, then uses real mkdir
under a nonroot-owned temporary sandbox. It is not a native nginx test.
"""
import os
from pathlib import Path
import re
import shlex
import stat
import sys
import tempfile
import unittest
sys.dont_write_bytecode=True

MODULES={'client_body_temp_path':'body','proxy_temp_path':'proxy',
         'fastcgi_temp_path':'fastcgi','scgi_temp_path':'scgi','uwsgi_temp_path':'uwsgi'}
ROOT=Path(__file__).resolve().parents[1]/'templates/jinja'


def module_paths(config):
    result={}
    for directive,leaf in MODULES.items():
        matches=re.findall(r'^\s*'+directive+r'\s+([^;\s]+)\s*;',config,re.MULTILINE)
        if len(matches)>1:raise ValueError('ambiguous temporary path')
        result[directive]=matches[0] if matches else '/var/lib/nginx/'+leaf
    return result


def fresh_cycle(config,unit,explicit=True):
    fields={}
    for line in unit.splitlines():
        if '=' in line:
            name,value=line.split('=',1)
            if name in fields:raise AssertionError('duplicate gateway unit field')
            fields[name]=value
    assert fields['User']=='999' and fields['Group']=='999'
    assert fields['SupplementaryGroups']=='' and fields['DynamicUser']=='no'
    assert fields['ProtectSystem']=='strict' and fields['ReadWritePaths']=='/run/avax-proxy'
    assert fields['RuntimeDirectory']=='avax-proxy' and fields['LimitCORE']=='0'
    assert shlex.split(fields['ExecStartPre'])==['/usr/sbin/nginx','-t','-c','/etc/avalanchego/proxy.conf']
    assert not fields['ExecStartPre'].startswith('+')
    assert shlex.split(fields['ExecStart'])==['/usr/sbin/nginx','-c','/etc/avalanchego/proxy.conf','-g','daemon off;']
    paths=module_paths(config)
    if explicit:
        assert paths=={directive:'/run/avax-proxy/'+leaf for directive,leaf in MODULES.items()}
    with tempfile.TemporaryDirectory() as temporary:
        root=Path(temporary);runtime=root/'run/avax-proxy';runtime.mkdir(parents=True,mode=0o700)
        protected=root/'var/lib/nginx';protected.mkdir(parents=True);protected.chmod(0o500)
        # PID1 RuntimeDirectory ownership and ProtectSystem are represented by
        # a writable runtime and a protected vendor parent, not live NSS/mounts.
        try:
            for value in paths.values():
                path=Path(value)
                assert path.is_absolute() and '..' not in path.parts
                (root/str(path).lstrip('/')).mkdir(mode=0o700,exist_ok=True)
            assert sorted(p.name for p in runtime.iterdir())==sorted(MODULES.values())
            assert not list(protected.iterdir())
            assert stat.S_IMODE(protected.stat().st_mode)==0o500
        finally:protected.chmod(0o700)
    return paths


def rendered():
    from jinja2 import Environment,FileSystemLoader,StrictUndefined
    env=Environment(loader=FileSystemLoader(ROOT),undefined=StrictUndefined)
    unit=env.get_template('avalanche-rpc.service.j2').render(avax_runtime_account={'uid':999,'gid':999},
        avax_control_condition='/usr/bin/python3 -I checked-fixture')
    for rpc,metrics in (([],[]),(['192.0.2.0/24'],[]),([],['198.51.100.0/24']),
                        (['192.0.2.0/24'],['198.51.100.0/24'])):
        yield env.get_template('proxy.conf.j2').render(avax_rpc_allow=rpc,avax_monitoring_allow=metrics),unit


class Startup(unittest.TestCase):
    def setUp(self):
        try:import jinja2
        except ImportError:self.skipTest('strict rendering requires qualified Jinja environment')

    def test_fresh_rendered_gateway_creates_every_module_path_inside_runtime(self):
        for config,unit in rendered():
            with self.subTest(config=config):fresh_cycle(config,unit)

    @unittest.skipIf(os.name!='posix' or os.geteuid()==0,'actual protected-parent denial requires nonroot POSIX')
    def test_each_missing_unused_module_reproduces_fresh_permission_failure(self):
        config,unit=next(rendered())
        for module in ('fastcgi','scgi','uwsgi'):
            without=re.sub(r'^\s*'+module+r'_temp_path[^;]+;\n','',config,flags=re.MULTILINE)
            with self.subTest(module=module),self.assertRaises(PermissionError):
                fresh_cycle(without,unit,explicit=False)

    def test_unknown_writable_scope_is_not_a_workaround(self):
        config,unit=next(rendered())
        for changed in (unit.replace('ProtectSystem=strict','ProtectSystem=false'),
                        unit.replace('ReadWritePaths=/run/avax-proxy','ReadWritePaths=/run/avax-proxy /var/lib/nginx'),
                        unit.replace('User=999','User=0')):
            with self.assertRaises(AssertionError):fresh_cycle(config,changed)


if __name__=='__main__':unittest.main()
