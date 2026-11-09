# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Compiled init task -> actual protected public controller handoff, no native work."""
import contextlib
import io
import json
import os
from pathlib import Path
import runpy
import sys
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
sys.dont_write_bytecode=True
raw=sys.stdin.buffer.read()


@contextlib.contextmanager
def entry_owner(entry,anchor):
    # Model only the test UID for canonical source ancestry; production's
    # complete trusted_imports program is executed unchanged.
    previous=sys.getprofile();active=[];lstat,scan=os.lstat,os.scandir
    def metadata(path,value):
        fields=list(value);fields[4]=0
        if Path(path) in anchor.parents:fields[0]&=~0o022
        return os.stat_result(fields)
    class Entries:
        def __init__(self,path):self.values=scan(path)
        def __enter__(self):return self
        def __exit__(self,*args):self.values.close()
        def __iter__(self):return self
        def __next__(self):
            item=next(self.values)
            return SimpleNamespace(name=item.name,path=item.path,stat=lambda **kwargs:metadata(item.path,item.stat(**kwargs)))
    def observe(frame,event,_arg):
        if frame.f_code.co_filename!=str(entry) or frame.f_code.co_name!='trusted_imports':return
        if event=='call':
            active.extend((patch.object(os,'lstat',side_effect=lambda path,*a,**kw:metadata(path,lstat(path,*a,**kw))),patch.object(os,'scandir',side_effect=Entries)))
            for item in active:item.start()
        elif event=='return':
            while active:active.pop().stop()
    sys.setprofile(observe)
    try:yield
    finally:
        sys.setprofile(previous)
        while active:active.pop().stop()


with tempfile.TemporaryDirectory() as temporary:
    root=Path(temporary).resolve();bundle=root/'bundle';bundle.mkdir()
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as archive:
        for member in archive:
            relative=Path(member.name)
            assert member.isfile() and not relative.is_absolute() and '..' not in relative.parts
            destination=bundle/relative;destination.parent.mkdir(parents=True,exist_ok=True)
            destination.write_bytes(archive.extractfile(member).read())
    values=next(iter(json.loads((bundle/'inventory.yml').read_text())['all']['hosts'].values()))
    try:
        import ansible,yaml
        from ansible.parsing.dataloader import DataLoader
        from ansible.template import Templar
    except ImportError:
        assert not os.environ.get('ERPC_REQUIRE_PINNED_ANSIBLE'),'pinned handoff test cannot skip'
        print('optional pinned Ansible unavailable');raise SystemExit(0)
    assert ansible.__version__=='2.18.19'
    play=bundle/'ansible/polygon/init.yml';values['playbook_dir']=str(play.parent)
    settings=yaml.safe_load((play.parent/'vars.yml').read_text())
    values.update(Templar(loader=DataLoader(),variables=values).template(settings))
    tasks=yaml.safe_load(play.read_text())[0]['tasks']
    command=tasks[-1]['ansible.builtin.command']
    actual=Templar(loader=DataLoader(),variables=values).template(command)
    request=json.loads(actual['stdin']);expected=values['polygon_contract']
    assert request['action']=='publish-controller' and request['contract']==expected
    assert actual['argv']==['/usr/bin/python3','-I',str(bundle/'ansible/polygon/../../scripts/control.py'),'within-run']
    scripts=bundle/'scripts';sys.path.insert(0,str(scripts))
    import control,install,state
    sys.path.append(str(Path(__file__).resolve().parents[2]/'erpc-chain-polygon/tests'))
    import volume_fixture
    case=unittest.TestCase('runTest');host=root/'host';host.mkdir()
    for name in ('etc','opt/erpc','var/lib/polygon','usr/local/lib/erpc/polygon/releases'):(host/name).mkdir(parents=True,exist_ok=True)
    calls=[]
    def command(args,**kwargs):
        calls.append(args);raise AssertionError('public handoff must not execute a native program or service mutation')
    proof=SimpleNamespace(initial=lambda:None)
    accounts=SimpleNamespace(preflight=lambda expected:None,verify=lambda expected:{'original':'fixture numeric authority'})
    managed=state.State(host,run=command,owner=os.getuid(),usage=lambda:(6_000_000_000_000,0),proof=proof,account=accounts)
    try:
        volume_fixture.attach(case,managed)
        original=control.Control(managed,scripts);original.reserve(expected)
        before=managed.read('/etc/polygon/contract.json')
        output,error=io.StringIO(),io.StringIO();entry=Path(actual['argv'][2]);status=0
        with managed.locked(),entry_owner(entry,root),patch.object(state,'State',return_value=managed),\
             patch.object(sys,'argv',actual['argv'][2:]),patch.object(sys,'stdin',io.TextIOWrapper(io.BytesIO(actual['stdin'].encode()))),\
             contextlib.redirect_stdout(output),contextlib.redirect_stderr(error):
            try:runpy.run_path(str(entry),run_name='__main__')
            except SystemExit as result:status=result.code
        assert status==0 and not error.getvalue(),(status,error.getvalue())
        assert json.loads(output.getvalue())=={'controller_published':values['polygon_helpers']}
        assert install.helper_digest(managed.path('/usr/local/lib/erpc/polygon/releases/'+values['polygon_helpers']))==values['polygon_helpers']
        assert managed.read('/etc/polygon/contract.json')==before
        selected=managed.read('/etc/polygon/intent.json')
        assert selected['intent'].startswith('qualified:') and selected['profile']['releases']['heimdall']['tag']=='v0.13.2'
        if expected['role']=='validator':assert selected['profile']['validator']['phase']=='observing'
        assert not calls and not managed.path('/etc/polygon/identity.json').exists()
    finally:case.doCleanups()
print('compiled public handoff and non-executable source floor passed')
