# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Execute only the completed public authorization's exact carried private stage.

The source profile is read through protected descriptors and executed from those
verified bytes. No installed helper or unverified sibling is imported. Wallet
input stays on stdin; it never enters the Ansible inventory or a command argument.
"""
import hashlib
import importlib.abc
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import resource
import stat
import sys


def require(value):
    if not value:raise ValueError('original private custody stage could not be authenticated')


def safe(info,owner,directory=False):
    require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink==1)
            and info.st_uid==owner and not info.st_mode&0o022)


def child(parent,name,owner):
    fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
    try:safe(os.fstat(fd),owner,True)
    except BaseException:os.close(fd);raise
    return fd


def read(parent,name,owner,maximum):
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno());safe(before,owner)
        raw=stream.read(maximum+1);after=os.fstat(stream.fileno())
        require(len(raw)<=maximum and all(getattr(before,key)==getattr(after,key) for key in
                ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')))
        return raw


def verified(run,bundle,helpers,request,root=Path('/'),owner=0,profile='arbitrum'):
    require(profile in ('arbitrum','robinhood-mainnet','robinhood-testnet'))
    schema='erpc-arbitrum-public-result-v1' if profile=='arbitrum' else 'erpc-robinhood-defensive-result-v1'
    require(re.fullmatch('r-[a-z0-9-]{8,40}',run) and all(re.fullmatch('[a-f0-9]{64}',v) for v in (bundle,helpers,request)))
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        safe(os.fstat(fd),owner,True)
        for part in ('opt','erpc','runs',run):
            newer=child(fd,part,owner);os.close(fd);fd=newer
        result=json.loads(read(fd,'result.json',owner,262144))
        require(isinstance(result,dict) and result.get('status')=='ok' and type(result.get('exit_code')) is int
                and result['exit_code']==0 and result.get('play')=='validator/ansible/control.yml')
        sealed=json.loads(read(fd,'sealed.json',owner,262144))
        require(isinstance(sealed,dict) and sealed.get('bundle')==bundle)
        require(hashlib.sha256(read(fd,'bundle.tar.gz',owner,64*1024*1024)).hexdigest()==bundle)
        public=json.loads(read(fd,'validator-public-result.json',owner,262144))
        require(isinstance(public,dict) and set(public)=={'schema','run','bundle_sha256','helpers_sha256','request_sha256','result'}
                and public['schema']==schema and public['run']==run
                and public['bundle_sha256']==bundle and public['helpers_sha256']==helpers
                and public['request_sha256']==request and isinstance(public['result'],dict)
                and public['result'].get('requires_import') is True)
        for part in ('bundle','validator','node'):
            newer=child(fd,part,owner);os.close(fd);fd=newer
        names=sorted(os.listdir(fd));require(1<=len(names)<=64)
        files={};digest=hashlib.sha256();total=0
        for name in names:
            require(re.fullmatch(r'[a-z][a-z0-9_]*\.py',name))
            raw=read(fd,name,owner,8*1024*1024);total+=len(raw);require(total<=16*1024*1024)
            files[name[:-3]]=raw;digest.update(name.encode()+b'\0'+hashlib.sha256(raw).digest())
        require({'control','entry','upstreams','wallet_stage'}<=set(files) and digest.hexdigest()==helpers)
        return root/'opt/erpc/runs'/run/'bundle/validator/node',files,public['result']
    finally:os.close(fd)


class Modules(importlib.abc.MetaPathFinder,importlib.abc.Loader):
    def __init__(self,path,files):self.path,self.files=path,files
    def find_spec(self,fullname,path=None,target=None):
        if fullname in self.files:return importlib.util.spec_from_loader(fullname,self)
        return None
    def create_module(self,spec):return None
    def exec_module(self,module):
        module.__file__=str(self.path/(module.__name__+'.py'))
        exec(compile(self.files[module.__name__],module.__file__,'exec'),module.__dict__)


def execute(run,bundle,helpers,request,profile='arbitrum'):
    path,files,approval=(verified(run,bundle,helpers,request) if profile=='arbitrum' else
                         verified(run,bundle,helpers,request,profile=profile))
    if profile!='arbitrum':
        require(approval.get('contract',{}).get('family')=='robinhood'
                and approval['contract'].get('role')=='defensive-validator'
                and approval['contract'].get('network')==profile.removeprefix('robinhood-'))
    provider=set(approval)=={'contract','intent','requires_import'}
    require(isinstance(approval.get('contract'),dict) and (provider or
            (set(approval)=={'contract','wallet','requires_import','observer_required','intent','restore'}
             and type(approval['restore']) is bool and approval['observer_required'] is False)))
    require(not any(name in sys.modules for name in files))
    modules=Modules(path,files);sys.meta_path.insert(0,modules)
    try:
        import control
        # Recheck original NSS/namespace and current generation before consuming
        # the private stream. main/dispatch repeats it under the operation lock.
        instance=control.Control(approval['contract'])
        if provider:control.provider_stage.check(instance,approval['intent'])
        else:control.wallet_stage.check(instance,approval['intent'],approval['restore'])
        raw=sys.stdin.buffer.read(262145);require(len(raw)<=262144)
        value=json.loads(raw)
        require(isinstance(value,dict) and value.get('action')==('provider-stage-import' if provider else 'wallet-stage-import')
                and value.get('intent')==approval['intent'] and value.get('contract')==approval['contract'])
        if not provider:require(type(value.get('restore')) is bool and value['restore']==approval['restore'])
        sys.argv=[str(path/'control.py')]
        sys.stdin=io.TextIOWrapper(io.BytesIO(raw),encoding='utf-8')
        control.main()
    finally:sys.meta_path.remove(modules)


def main():
    try:
        resource.setrlimit(resource.RLIMIT_CORE,(0,0));os.umask(0o077)
        require(os.geteuid()==0 and sys.flags.isolated and len(sys.argv) in (5,6))
        execute(*sys.argv[1:])
    except BaseException:
        print('Original private custody stage refused',file=sys.stderr)
        raise SystemExit(1) from None


if __name__=='__main__':main()
