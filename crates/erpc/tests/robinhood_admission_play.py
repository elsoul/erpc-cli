# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual compiled public request/bundle -> entry -> observation -> result.

Only original host ownership, credential decryption, provider I/O and outer root
UID are modeled. The carried Python, strict protocol and public publication run
unchanged. No real provider, Docker, key, node or transaction is used.
"""
import contextlib
import csv
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from types import SimpleNamespace
from unittest.mock import patch
sys.dont_write_bytecode=True


@contextlib.contextmanager
def modeled_entry(entry, root, runs):
    previous=sys.getprofile();active=[];original_stat=os.lstat;original_scan=os.scandir
    def metadata(path, info):
        fields=list(info);fields[4]=0
        if Path(path) in root.parents:fields[0]&=~0o022
        return os.stat_result(fields)
    class Entries:
        def __init__(self,path):self.source=original_scan(path)
        def __iter__(self):return self
        def __enter__(self):return self
        def __exit__(self,*_):self.source.close()
        def __next__(self):
            value=next(self.source)
            return SimpleNamespace(name=value.name,path=value.path,
                stat=lambda *,follow_symlinks=False:metadata(value.path,value.stat(follow_symlinks=follow_symlinks)))
    def profile(frame,event,_arg):
        if frame.f_code.co_name=='main' and frame.f_code.co_filename==str(entry.parent/'control.py') and event=='call':
            frame.f_globals['RUNS']=runs
        if frame.f_code.co_name!='trusted_imports' or frame.f_code.co_filename!=str(entry):return
        if event=='call':
            active.extend([patch.object(os,'lstat',side_effect=lambda p,*a,**k:metadata(p,original_stat(p,*a,**k))),
                           patch.object(os,'scandir',side_effect=Entries)])
            for value in active:value.start()
        elif event=='return':
            while active:active.pop().stop()
    sys.setprofile(profile)
    try:yield
    finally:
        sys.setprofile(previous)
        while active:active.pop().stop()


def exercise(raw,scenario):
    with tempfile.TemporaryDirectory() as directory:
        root=Path(directory).resolve();runs=root/'runs';run=runs/'r-robinhood-admission-fixture';bundle=run/'bundle'
        bundle.mkdir(parents=True)
        with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as archive:
            for member in archive.getmembers():
                name=Path(member.name)
                assert member.isfile() and not name.is_absolute() and '..' not in name.parts
                path=bundle/name;path.parent.mkdir(parents=True,exist_ok=True)
                path.write_bytes(archive.extractfile(member).read())
        (run/'bundle.tar.gz').write_bytes(raw)
        source=bundle/'robinhood-admission/node';entry=source/'entry.py'
        sys.path.append(str(source))
        follower=importlib.import_module('follower');storage=importlib.import_module('storage')
        upstreams=importlib.import_module('upstreams');observation=importlib.import_module('observation')
        for module in (follower,storage,upstreams,observation):assert Path(module.__file__).parent==source
        inventory=json.loads((bundle/'inventory.yml').read_bytes());hosts=inventory['all']['hosts'];assert len(hosts)==1
        request=next(iter(hosts.values()))['admission_request'];node=request['rpc_node'];network=node['network']
        play=bundle/'robinhood-admission/control.yml';text=play.read_text()
        line=next(row for row in text.splitlines() if 'argv:' in row).split('[',1)[1].rsplit(']',1)[0]
        argv=[value.strip("'").replace('{{ playbook_dir }}',str(play.parent)) for value in next(csv.reader([line],skipinitialspace=True))]
        assert argv==['/usr/bin/python3','-I',str(entry),'observe']
        assert '{{ admission_request | to_json }}' in text
        try:
            import ansible,yaml
            from ansible.parsing.dataloader import DataLoader
            from ansible.template import Templar
        except ImportError:pass
        else:
            assert ansible.__version__=='2.18.19'
            task=yaml.safe_load(text)[0]['tasks'][0]['ansible.builtin.command']
            rendered=Templar(loader=DataLoader(),variables={'playbook_dir':str(play.parent),'admission_request':request}).template(task)
            assert rendered['argv']==argv and json.loads(rendered['stdin'])==request
        host=root/'original';conf=root/'configuration';host.mkdir(mode=0o700);conf.mkdir(mode=0o700)
        owner=dict(node,phase='v2:installed',lifecycle_schema=2,generation=1)
        if scenario=='foreign-owner':owner['owner']='foreignoriginal'
        owner_path=host/'owner.json';owner_path.write_bytes(storage.encode(owner));owner_path.chmod(0o600)
        credential=conf/'l1-upstreams.cred';credential.write_bytes(b'inert original encrypted provider');credential.chmod(0o600)
        before={owner_path:owner_path.read_bytes(),credential:credential.read_bytes()}
        now=int(time.time());profile=observation.PROFILES[network];wallet=request['validator_address'];decrypts=[];reads=[]
        # Same inert hostname as shared upstream tests; Endpoint.request is modeled below.
        config={'execution':{'url':'https://github.com/execution','headers':{'authorization':'INERT_PRIVATE_MARKER'}},
                'beacon':{'url':'https://github.com/beacon'}}
        if scenario=='plaintext':config['execution']={'url':'http://127.0.0.1','allow_loopback':True}
        if scenario=='private-provider':config['execution']={'url':'https://127.0.0.1'}
        timestamp=request['intent']['snapshot']['block_timestamp'] if request['action']=='validate' else now-600
        def crypto(command,**kwargs):
            assert command==['/usr/bin/systemd-creds','decrypt','--name=l1-upstreams','-','-']
            assert kwargs['input']==before[credential];assert kwargs['env']=={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'}
            decrypts.append(True)
            if scenario=='decrypt-failed':return SimpleNamespace(returncode=1,stdout=b'INERT_PRIVATE_MARKER',stderr=b'INERT_PRIVATE_MARKER')
            return SimpleNamespace(returncode=0,stdout=json.dumps(config).encode(),stderr=b'INERT_PRIVATE_MARKER')
        def provider(endpoint,method,path='',body=None):
            reads.append((method,path))
            if scenario=='changed-owner':owner_path.write_bytes(storage.encode(dict(owner,generation=2)))
            if scenario=='changed-cipher':credential.write_bytes(b'different inert original credential')
            if scenario=='provider-error':raise ValueError('INERT_PRIVATE_MARKER')
            assert set(os.environ)=={'PATH','LC_ALL'}
            if method=='GET':
                assert path=='/eth/v1/beacon/genesis'
                return {'data':{key:value for key,value in upstreams.L1[follower.network(node)[1]].items() if key.startswith('genesis_')}}
            query=json.loads(body);rpc=query['method'];params=query['params'];assert method=='POST'
            if rpc=='eth_chainId':value=hex(profile['parent'])
            elif rpc=='eth_getBlockByNumber':
                value={'hash':profile['genesis']} if params[0]=='0x0' else {
                    'hash':'0x'+('c' if scenario=='reorg' and params[0]!='finalized' else 'b')*64,'number':'0x1234',
                    'timestamp':hex(now-1900 if scenario=='stale' else timestamp)}
            elif rpc=='eth_getCode':value='0x' if params[0]==wallet else '0x01'
            else:
                assert rpc=='eth_call' and params[1]=='0x1234';selector=params[0]['data'][2:10]
                name=next(key for key,selector_value in observation.SELECTORS.items() if selector_value==selector)
                values={'rollup':int(profile['rollup'],16),'chainId':profile['child'],'bridge':int(profile['bridge'],16),
                        'stakeToken':int(profile['stake_asset_address'],16),'validatorWhitelistDisabled':0,'isValidator':0,'paused':0,'baseStake':10**18}
                value='0x'+format(values[name],'064x')
            return {'jsonrpc':'2.0','id':query['id'],'result':value}
        output,error=io.StringIO(),io.StringIO();stdin=io.TextIOWrapper(io.BytesIO(storage.encode(request)));code=0
        with patch.object(follower,'ROOT',host),patch.object(follower,'CONF',conf),patch.object(follower,'ROOT_UID',os.getuid()), \
             patch.object(follower,'TRUST_ANCHOR',root),patch.object(follower,'check_container',return_value=None), \
             patch.object(storage,'ROOT_UID',os.getuid()),patch.object(storage,'TRUST_ANCHOR',root), \
             patch.object(subprocess,'run',side_effect=crypto),patch.object(upstreams.Endpoint,'request',provider), \
             patch.object(os,'geteuid',return_value=0),patch.object(sys,'argv',argv[2:]),patch.object(sys,'stdin',stdin), \
             patch.dict(os.environ,{'SSLKEYLOGFILE':'INERT_PRIVATE_MARKER'},clear=False), \
             contextlib.redirect_stdout(output),contextlib.redirect_stderr(error),modeled_entry(entry,root,runs):
            try:runpy.run_path(str(entry),run_name='__main__')
            except SystemExit as result:code=result.code
        for path,value in before.items():
            if scenario=='changed-owner' and path==owner_path:continue
            if scenario=='changed-cipher' and path==credential:continue
            assert path.read_bytes()==value
        assert 'INERT_PRIVATE_MARKER' not in output.getvalue()+error.getvalue()
        result_path=run/'robinhood-admission-public-result.json'
        if scenario!='safe':
            assert code==1 and not output.getvalue() and not result_path.exists(),(code,output.getvalue(),error.getvalue())
            if scenario=='foreign-owner':assert not decrypts and not reads
            if scenario in ('plaintext','private-provider','decrypt-failed'):assert len(decrypts)==1 and not reads
            return {'refused':True,'originals_preserved':True,'public_result_written':False}
        assert code==0 and not error.getvalue(),(code,output.getvalue(),error.getvalue())
        assert json.loads(output.getvalue())=={'public_result_written':True,'run':run.name}
        assert len(decrypts)==1 and reads
        public=json.loads(result_path.read_bytes())
        assert public['request_sha256']==hashlib.sha256(storage.encode(request)).hexdigest()
        assert public['result']['financial_action_performed'] is False
        if request['action']=='status':assert public['result']['activation_authorized'] is False
        return public


if __name__=='__main__':
    assert sys.flags.isolated
    result=exercise(sys.stdin.buffer.read(),sys.argv[1] if len(sys.argv)>1 else 'safe')
    print(json.dumps(result,separators=(',',':'),sort_keys=True))
