# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Execute the actual Rust-generated Sui external loaders with inert filesystem metadata."""
import json
from pathlib import Path
import shlex
import subprocess
import sys
sys.dont_write_bytecode=True
root=Path(__file__).resolve().parents[1]
canonical=(root.parent/'erpc-ssh/src/python-trust.py').read_text()
controller=(root/'templates/jinja/erpc-sui-control.py.j2').read_text()
assert controller.split('# BEGIN ERPC TRUSTED IMPORTS\n',1)[1].split('# END ERPC TRUSTED IMPORTS',1)[0]==canonical
values=json.load(sys.stdin)
fixture=r'''import os,runpy,stat,sys
from types import SimpleNamespace
scenario=sys.argv[1]
os.lstat=lambda path:SimpleNamespace(st_uid=(99 if scenario=='foreign-owner' else 0),st_mode=(stat.S_IFLNK|0o777 if scenario=='symlink-parent' else stat.S_IFDIR|(0o777 if scenario=='writable-parent' else 0o755)))
entry=SimpleNamespace(name='erpc-sui-control.py',path='/usr/local/lib/erpc/sui/erpc-sui-control.py',stat=lambda **kwargs:SimpleNamespace(st_uid=0,st_mode=stat.S_IFREG|(0o666 if scenario=='writable-file' else 0o644),st_nlink=2 if scenario=='hardlink' else 1))
os.scandir=lambda path:[entry]
def execute(path,run_name):
    print('inert helper reached')
    if scenario=='helper-failure':raise ValueError('inert helper refusal')
    if scenario=='helper-skip':raise SystemExit(1)
runpy.run_path=execute
'''
count=0
for key in ('sui_service_guard','sui_credential_condition','sui_identity_guard'):
    command=values[key];args=shlex.split(command)
    assert args[:3]==['/usr/bin/python3','-I','-c'] and len(args)==4
    assert '%' not in command and '$' not in command
    for scenario in ('safe','foreign-owner','symlink-parent','writable-parent','writable-file','hardlink','helper-failure','helper-skip'):
        result=subprocess.run([sys.executable,'-I','-c',fixture+'\n'+args[3],scenario],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        reached=b'inert helper reached' in result.stdout
        assert reached==(scenario in ('safe','helper-failure','helper-skip')),(key,scenario,result.stdout,result.stderr)
        if scenario=='safe':assert result.returncode==0
        elif key=='sui_credential_condition':assert result.returncode==255,(scenario,result.returncode)
        else:assert result.returncode!=0
        count+=1
import importlib.machinery,importlib.util
source_loader=importlib.machinery.SourceFileLoader('sui_checked_callback_fixture',str(root/'templates/jinja/erpc-sui-control.py.j2'))
source_spec=importlib.util.spec_from_loader(source_loader.name,source_loader)
source_module=importlib.util.module_from_spec(source_spec);source_loader.exec_module(source_module)
for name in ('control','validator'):
    callback=source_module.Control.checked(name)
    assert callback[:3]==['/usr/bin/python3','-I','-c']
    for scenario in ('safe','foreign-owner','symlink-parent','writable-parent','writable-file','hardlink','helper-failure','helper-skip'):
        result=subprocess.run([sys.executable,'-I','-c',fixture+'\n'+callback[3],scenario],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        assert (b'inert helper reached' in result.stdout)==(scenario in ('safe','helper-failure','helper-skip'))
        assert (result.returncode==0)==(scenario=='safe')
        count+=1
print(str(count)+' actual generated Sui entrypoint scenarios passed')
try:
    from jinja2 import Environment,FileSystemLoader,StrictUndefined
except ImportError:
    print('strict renders require the pinned Ansible environment');raise SystemExit(0)
root=Path(__file__).resolve().parents[1]
environment=Environment(loader=FileSystemLoader(root/'templates/jinja'),undefined=StrictUndefined)
environment.filters['to_json']=json.dumps
rendered=0
for network in ('mainnet','testnet'):
    for role in ('fullnode','validator'):
        context=dict(values,sui_network=network,sui_role=role,sui_genesis_sha256='a'*64,sui_runtime_account={'uid':987,'gid':987})
        for name in ('sui-node.service','sui-bootstrap.service','erpc-sui-firewall.service'):
            text=environment.get_template(name+'.j2').render(context);lines=text.splitlines()
            if name=='sui-node.service':
                condition=[line for line in lines if line.startswith('ExecCondition=')]
                assert len(condition)==1
                expected='ExecCondition=+'+values['sui_credential_condition']+' credential-condition '+network+' '+role+' '+'a'*64
                assert condition==[expected]
                assert 'LoadCredentialEncrypted=' in text
            if name!='erpc-sui-firewall.service':
                assert 'User=987' in lines and 'Group=987' in lines
                assert 'DynamicUser=no' in lines and 'SupplementaryGroups=' in lines and 'LimitCORE=0' in lines
                assert any(line.startswith('ExecStartPre=+'+values['sui_service_guard']) for line in lines)
            else:assert any(line.startswith('ExecStart='+values['sui_service_guard']) for line in lines)
            assert '/usr/local/lib/erpc/erpc-sui-' not in text
            rendered+=1
print(str(rendered)+' strict Sui unit renders passed')

# Exercise the actual command/register/set_fact/template publication tasks with
# an inert account query and temporary destinations. The carried controller's
# real publication/readback gate runs afterward; no NSS/service is changed.
import importlib.util
import os
import shutil
import tempfile
try:
    import yaml
except ImportError:
    print('actual publication requires the pinned Ansible environment');raise SystemExit(0)
if not shutil.which('ansible-playbook'):
    print('actual publication requires ansible-playbook');raise SystemExit(0)
spec=importlib.util.spec_from_file_location('sui_publication_fixture',root/'tests/authority_test.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
test=module.Authority();test.setUp()
try:
    account=test.c.prepare_account(test.expected)
    for folder in ('usr/local/lib/erpc/sui','etc/systemd/system','etc/erpc/sui'):
        (test.root/folder).mkdir(parents=True,exist_ok=True)
    obsolete=test.root/'usr/local/lib/erpc/erpc-sui-control.py'
    obsolete.write_text('inert obsolete public helper')
    play=yaml.safe_load((root/'templates/ansible/sui-node/deploy.yml').read_text())[0]
    wanted={'Read the verified original service UID and GID','Use the verified original service UID and GID',
            'Install readiness and identity helpers','Write systemd units'}
    tasks=[task for task in play['tasks'] if task['name'] in wanted]
    assert len(tasks)==4
    with tempfile.TemporaryDirectory(prefix='sui-publication-') as temporary:
        work=Path(temporary);query=work/'account-query.py'
        query.write_text('import json,sys\nassert sys.argv[1:]=='+repr(['account',test.expected['network'],test.expected['role'],test.expected['genesis']])+'\nprint('+repr(json.dumps(account))+')\n')
        for task in tasks:
            if 'ansible.builtin.command' in task:
                task['ansible.builtin.command']['argv'][2]=str(query)
            if 'ansible.builtin.template' in task:
                template=task['ansible.builtin.template'];template.pop('owner');template.pop('group')
                if template['dest'].startswith('/etc/systemd/system/'):
                    template['dest']=str(test.root/'etc/systemd/system')+'/{{ item }}'
        context=dict(values,sui_jinja=str(root/'templates/jinja'),sui_helpers=str(test.root/'usr/local/lib/erpc/sui'),
            sui_network=test.expected['network'],sui_role=test.expected['role'],sui_genesis_sha256=test.expected['genesis'])
        publication=work/'publication.yml'
        publication.write_text(yaml.safe_dump([{'name':'Inert actual Sui unit publication','hosts':'localhost','gather_facts':False,
            'become':False,'vars':context,'tasks':tasks}]))
        completed=subprocess.run([shutil.which('ansible-playbook'),'-i','localhost,','-c','local',str(publication)],
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,env=dict(os.environ,ANSIBLE_NOCOLOR='1',OBJC_DISABLE_INITIALIZE_FORK_SAFETY='YES'),timeout=120)
        assert completed.returncode==0,completed.stdout.decode()
    for unit in ('sui-node','sui-bootstrap'):
        content=(test.root/('etc/systemd/system/'+unit+'.service')).read_text()
        assert 'User='+str(account['uid'])+'\n' in content and 'Group='+str(account['gid'])+'\n' in content
    node=(test.root/'etc/systemd/system/sui-node.service').read_text()
    assert sum(line.startswith('ExecCondition=') for line in node.splitlines())==1
    installed=test.root/'usr/local/lib/erpc/sui/erpc-sui-control.py'
    original=installed.read_bytes();installed.write_bytes(original+b'\n# inert changed carried bytes\n')
    try:test.c.dispatch('publication',test.expected)
    except ValueError:pass
    else:raise AssertionError('changed installed helper was accepted')
    assert obsolete.exists()
    installed.write_bytes(original);test.c.dispatch('publication',test.expected)
    assert not obsolete.exists()
    print('actual Ansible numeric account publication, two units and complete helper readback passed')
finally:test.doCleanups()
