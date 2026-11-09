# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual carried account query/register/template/copy/readback with inert NSS."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]


def exercise(values):
    try:import yaml
    except ImportError:return 0
    ansible=shutil.which('ansible-playbook')
    if not ansible:return 0
    spec=importlib.util.spec_from_file_location('avax_publication_authority',Path(__file__).with_name('authority.py'))
    a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
    count=0
    for kind in ('safe','writable-parent','changed-publication','nss-drift'):
        test=a.Authority();test.setUp()
        try:
            test.expected['owner']=values['avax_owner']
            test.c.prepare(test.expected)
            for name in ('etc/systemd/system','etc/avalanchego/chains/C','etc/erpc/avax','usr/local/lib/erpc'):
                (test.root/name).mkdir(parents=True,exist_ok=True)
            previous=test.root/'usr/local/lib/erpc/avax-identity.py';previous.write_text('inert previous public helper');previous.chmod(0o644)
            with tempfile.TemporaryDirectory() as directory:
                carry=Path(directory)/'bundle';shutil.copytree(ROOT/'templates',carry)
                shutil.copyfile(ROOT.parent/'erpc-ops/templates/rpc-firewall.py',carry/'rpc-firewall.py')
                code=(carry/'jinja/control.py').read_text()
                code=code.replace("root=pathlib.Path('/')",'root=pathlib.Path('+repr(str(test.root))+')').replace('owner=0):','owner='+str(os.getuid())+'):')
                code=code.replace("if __name__=='__main__':trusted_imports(pathlib.Path(__file__).absolute().parent)","# fixture-owned source; actual external loader is tested independently")
                code=code.replace('if os.geteuid()!=0:', 'if os.geteuid()!='+str(os.getuid())+':')
                uid=2001 if kind=='nss-drift' else 999
                fixture='''
from types import SimpleNamespace
_fixture_user=SimpleNamespace(pw_name='avalanchego',pw_uid=UID,pw_gid=999,pw_dir='/var/lib/avalanchego',pw_shell='/usr/sbin/nologin')
_fixture_group=SimpleNamespace(gr_name='avalanchego',gr_gid=999,gr_mem=[])
def _fixture_lookup(value,expected,result):
    if value!=expected:raise KeyError(value)
    return result
account.pwd.getpwall=lambda:[_fixture_user]
account.pwd.getpwnam=lambda value:_fixture_lookup(value,'avalanchego',_fixture_user)
account.pwd.getpwuid=lambda value:_fixture_lookup(value,UID,_fixture_user)
account.grp.getgrall=lambda:[_fixture_group]
account.grp.getgrnam=lambda value:_fixture_lookup(value,'avalanchego',_fixture_group)
account.grp.getgrgid=lambda value:_fixture_lookup(value,999,_fixture_group)
account.os.getgrouplist=lambda name,gid:[999]
_fixture_lstat=pathlib.Path.lstat
def _fixture_metadata(path,*args,**kwargs):
    info=_fixture_lstat(path,*args,**kwargs)
    if path==pathlib.Path(DATA):
        fields=list(info);fields[4]=999;fields[5]=999;return os.stat_result(fields)
    return info
pathlib.Path.lstat=_fixture_metadata
'''.replace('UID',str(uid)).replace('DATA',repr(str(test.root/'var/lib/avalanchego')))
                code=code.replace("if __name__=='__main__':\n    try:main()",fixture+"\nif __name__=='__main__':\n    try:main()")
                (carry/'jinja/control.py').write_text(code)
                deploy=yaml.safe_load((carry/'ansible/avax/deploy.yml').read_text())[0]['tasks']
                query=copy.deepcopy(next(task for task in deploy if task['name']=='Read original numeric recipients for the new service units'))
                bind=copy.deepcopy(next(task for task in deploy if task['name']=='Use only original numeric recipients'))
                render=copy.deepcopy(next(task for task in deploy if task['name']=='Write client and restricted gateway configuration'))
                publication=yaml.safe_load((carry/'ansible/avax/tasks/publication.yml').read_text())
                # Inline only the production imported guard; all command, copy,
                # template and readback semantics remain actual Ansible tasks.
                publication[0:1]=yaml.safe_load((carry/'ansible/avax/tasks/contract.yml').read_text())
                for task in publication:
                    for key in ('ansible.builtin.file','ansible.builtin.copy'):
                        if key in task:
                            task[key]['owner']=str(os.getuid());task[key]['group']=str(os.getgid())
                            if 'path' in task[key]:task[key]['path']=str(test.root)+task[key]['path']
                            if 'dest' in task[key]:task[key]['dest']=str(test.root)+task[key]['dest']
                render['ansible.builtin.template']['owner']=str(os.getuid());render['ansible.builtin.template']['group']=str(os.getgid())
                for item in render['loop']:item['dest']=str(test.root)+item['dest']
                if kind=='changed-publication':
                    publication.insert(-1,{'ansible.builtin.copy':{'content':'raise RuntimeError("inert substituted code")\n',
                        'dest':str(test.root/'usr/local/lib/erpc/avax/control.py'),'mode':'0644'}})
                if kind=='writable-parent':(test.root/'usr/local/lib/erpc').chmod(0o777)
                variables=dict(values,ansible_python_interpreter=sys.executable,avax_network='fuji',avax_type='full',avax_validator=True,
                               avax_jinja=str(carry/'jinja'),avax_runtime_account={'uid':2001,'gid':2001})
                play=[{'hosts':'all','gather_facts':False,'connection':'local','vars':variables,'vars_files':['vars.yml'],'tasks':[query,bind,*publication,render]}]
                path=carry/'ansible/avax/publication-test.yml';path.write_text(yaml.safe_dump(play))
                result=subprocess.run([ansible,'-i','localhost,',str(path)],capture_output=True,text=True,timeout=90)
                assert (result.returncode==0)==(kind=='safe'),result.stdout+result.stderr
                if kind=='safe':
                    assert not previous.exists()
                    startup_spec=importlib.util.spec_from_file_location('avax_gateway_startup',Path(__file__).with_name('gateway_startup.py'))
                    startup=importlib.util.module_from_spec(startup_spec);startup_spec.loader.exec_module(startup)
                    startup.fresh_cycle((test.root/'etc/avalanchego/proxy.conf').read_text(),
                                        (test.root/'etc/systemd/system/avalanche-rpc.service').read_text())
                    for unit in ('avalanchego','avalanche-rpc'):
                        text=(test.root/('etc/systemd/system/'+unit+'.service')).read_text()
                        assert 'User=999\n' in text and 'Group=999\n' in text and 'User=2001' not in text
                    assert (test.root/'usr/local/lib/erpc/avax/control.py').read_text()==code
                else:
                    assert previous.exists(),'obsolete helpers were retired before complete publication proof'
                    if kind=='writable-parent':assert (test.root/'usr/local/lib/erpc').stat().st_mode&0o777==0o777
                count+=1
        finally:test.doCleanups()
    return count
