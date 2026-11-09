# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Execute the actual Rust-generated Avalanche external loaders with inert filesystem metadata."""
import json
from pathlib import Path
import shlex
import subprocess
import sys
sys.dont_write_bytecode=True
root=Path(__file__).resolve().parents[1]
canonical=(root.parent/'erpc-ssh/src/python-trust.py').read_text()
controller=(root/'templates/jinja/control.py').read_text()
assert controller.split('# BEGIN ERPC TRUSTED IMPORTS\n',1)[1].split('# END ERPC TRUSTED IMPORTS',1)[0]==canonical
values=json.load(sys.stdin)
fixture=r'''import os,runpy,stat,sys
from types import SimpleNamespace
scenario=sys.argv[1]
os.lstat=lambda path:SimpleNamespace(st_uid=(99 if scenario=='foreign-owner' else 0),st_mode=(stat.S_IFLNK|0o777 if scenario=='symlink-parent' else stat.S_IFDIR|(0o777 if scenario=='writable-parent' else 0o755)))
entry=SimpleNamespace(name='control.py',path='/usr/local/lib/erpc/avax/control.py',stat=lambda **kwargs:SimpleNamespace(st_uid=0,st_mode=stat.S_IFREG|(0o666 if scenario=='writable-file' else 0o644),st_nlink=2 if scenario=='hardlink' else 1))
os.scandir=lambda path:[entry]
def execute(path,run_name):
    print('inert helper reached')
    if scenario=='helper-failure':raise ValueError('inert helper refusal')
    if scenario=='helper-skip':raise SystemExit(1)
runpy.run_path=execute
'''
count=0
for key in ('avax_control_unit','avax_control_condition'):
    command=values[key];args=shlex.split(command)
    assert args[:3]==['/usr/bin/python3','-I','-c'] and len(args)==4
    assert '%' not in command and '$' not in command
    for scenario in ('safe','foreign-owner','symlink-parent','writable-parent','writable-file','hardlink','helper-failure','helper-skip'):
        result=subprocess.run([sys.executable,'-I','-c',fixture+'\n'+args[3],scenario],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        reached=b'inert helper reached' in result.stdout
        assert reached==(scenario in ('safe','helper-failure','helper-skip')),(key,scenario,result.stdout,result.stderr)
        if scenario=='safe':assert result.returncode==0
        elif key=='avax_control_condition':assert result.returncode==255,(scenario,result.returncode)
        else:assert result.returncode!=0
        count+=1
print(str(count)+' actual generated Avalanche entrypoint scenarios passed')
try:
    from jinja2 import Environment,FileSystemLoader,StrictUndefined
except ImportError:
    print('strict renders need the pinned Ansible environment');raise SystemExit(0)
env=Environment(loader=FileSystemLoader(root/'templates/jinja'),undefined=StrictUndefined)
env.filters['to_json']=json.dumps
count=0
for network in ('mainnet','fuji'):
    for kind in ('full','archive'):
        context=dict(values,avax_network=network,avax_type=kind,avax_runtime_account={'uid':999,'gid':999})
        for name in ('avalanchego.service','avalanche-rpc.service','erpc-avax-firewall.service'):
            rendered=env.get_template(name+'.j2').render(context);lines=rendered.splitlines()
            if name!='erpc-avax-firewall.service':
                assert 'User=999' in lines and 'Group=999' in lines
                assert 'SupplementaryGroups=' in lines and 'LimitCORE=0' in lines and 'DynamicUser=no' in lines
                assert 'KillMode=control-group' in lines and 'SendSIGKILL=no' in lines
                assert any(line.startswith('ExecCondition=+'+values['avax_control_condition']) for line in lines)
            else:assert 'ExecStart='+values['avax_control_unit']+' firewall-load' in lines
            if name=='avalanchego.service':assert 'ExecStart=/usr/bin/env -i HOME=/var/lib/avalanchego PATH=/usr/sbin:/usr/bin:/sbin:/bin /opt/avalanchego/current/avalanchego --config-file=/etc/avalanchego/node.json' in lines
            assert '/usr/local/lib/erpc/avax-identity.py' not in rendered
            count+=1
print(str(count)+' actual Avalanche unit renders passed')
import importlib.util
spec=importlib.util.spec_from_file_location('avax_actual_publication',root/'tests/publication.py')
publication=importlib.util.module_from_spec(spec);spec.loader.exec_module(publication)
print(str(publication.exercise(values))+' actual Avalanche publication scenarios passed')
