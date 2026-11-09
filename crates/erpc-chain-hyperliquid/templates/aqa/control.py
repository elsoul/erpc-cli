#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Dedicated AQA publisher controller; native publishing is a separate explicit role."""
import fcntl
import json
import os
from pathlib import Path
import resource
import sys
# BEGIN ERPC TRUSTED IMPORTS
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
# Embedded verbatim in helpers that need sibling modules. Startup uses -I;
# only this checked directory is added, after the standard-library paths.
def trusted_imports(directory):
    import os
    import stat
    import sys
    path = os.fspath(directory)
    if not os.path.isabs(path):
        raise ValueError('helper directory must be an absolute path')
    current = os.path.sep
    for part in path.split(os.path.sep)[1:]:
        if part in ('', '.'):
            continue
        if part == '..':
            # The component being left was already checked as a real root-only
            # directory. Never normalize away an unchecked symlink ancestor.
            current = os.path.dirname(current)
            continue
        current = os.path.join(current, part)
        info = os.lstat(current)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('helper ancestors must be real root-owned directories')
    path = current
    if path == os.path.sep:
        raise ValueError('the filesystem root is not a helper directory')
    # Do not create root0700 bytecode caches before an unprivileged helper
    # imports the same module. Existing readable caches remain fully checked.
    sys.dont_write_bytecode = True
    pending = [path]
    while pending:
        for child in os.scandir(pending.pop()):
            info = child.stat(follow_symlinks=False)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('helper modules must be writable only by root')
            if stat.S_ISDIR(info.st_mode):
                if (child.name == '__pycache__'
                        and not os.access(child.path, os.X_OK, effective_ids=True)):
                    # No traversal means Python cannot read any cached module
                    # here and must use the checked source. Denied listing alone
                    # (e.g. mode0711) is not sufficient for this exception.
                    continue
                pending.append(child.path)
            elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError('helper modules cannot be links or special files')
    if path not in sys.path:
        sys.path.append(path)
# END ERPC TRUSTED IMPORTS
if __name__=='__main__':trusted_imports(str(Path(__file__).absolute().parent))

from erpc_aqa_common import ROOT,UNIT,Refused,owned_directory,read,require,token,unique_json
from erpc_aqa_state import State
import erpc_aqa_accounts as accounts
import erpc_aqa_custody as custody
import erpc_aqa_host as host


def fields(request,names):
    require(isinstance(request,dict) and set(request)=={'action','contract',*names},'unsupported publisher request fields')


def dispatch(request):
    require(isinstance(request,dict),'publisher request must be an object')
    c=host.contract(request.get('contract'));action=request.get('action')
    if action in ('preflight','reserve','initialize'):
        fields(request,{'target','policy'})
        if action=='preflight':return host.preflight(request)
        state=host.reserve(request)
        if action=='reserve':return {'reserved':True}
        require(not (ROOT/'installed.json').exists() and not (ROOT/'installing.json').exists(),
                'established publisher requires deploy or update')
        host.clock();host.capacity()
        accounts.provision_accounts(state)
        state.cancel(c,False,lambda:host.stop_owned(c))
        host.publish_helpers()
        return {'initialized':True,'agent_imported':False,'publishing_started':False}
    state=host.owned(c)
    if action in ('stop','destroy'):
        fields(request,set());state.cancel(c,action=='destroy',lambda:host.stop_owned(c))
        return {'publisher_stopped':True,'retired':action=='destroy','custody_preserved':True}
    if action=='status':fields(request,set());return host.status(c)
    if action=='import-agent':
        fields(request,{'original','restore','unhosted'})
        require(isinstance(request['original'],str),'original concealed agent object must be text')
        host.protected_paths();host.clock()
        return custody.import_original(state,c,request['original'].encode(),request['restore'],request['unhosted'],lambda:host.stop_owned(c))
    if action=='authorize':
        fields(request,{'intent','target','policy'});_,target,_,_=host.qualified(request,exact=False)
        state.authorize(c,request['intent'],target);return {'authorized':request['intent']}
    if action=='prepare':
        fields(request,{'intent','target','policy'})
        _,target,_,_=host.qualified(request)
        require(state.get('operation.json')=={'intent':token(request['intent']),'target':target}
                and state.get('activation-revoked')=={'intent':request['intent']},
                'stale preparation cannot cancel a newer deployment')
        try:return host.prepare(request)
        except Exception as error:host.reject_runtime(c,error);raise
    if action in ('prepared','firewall-apply','firewall-confirm'):
        fields(request,{'intent'} if action=='prepared' else {'intent','run','bundle'})
        operation=state.current(c,request['intent'])
        require(state.get('installing.json')==operation,'publisher preparation no longer owns this intent')
        host.protected_paths()
        if action!='prepared':host.firewall('apply' if action=='firewall-apply' else 'confirm',request['run'],request['bundle'])
        return {'prepared':True,'action':action}
    if action=='configure':
        fields(request,{'intent','target','policy','run','bundle'})
        _,target,_,_=host.qualified(request)
        require(state.current(c,request['intent'])['target']==target,'configuration target differs')
        try:return host.configure(request)
        except Exception as error:host.reject_runtime(c,error);raise
    if action in ('activate','start','restart'):
        fields(request,{'intent'} if action=='activate' else set())
        state.guard(c,request.get('intent') if action=='activate' else None,
                    manual=action!='activate' and (ROOT/'stopped').exists())
        if action=='restart':state.cancel(c,False,lambda:host.stop_owned(c))
        try:return host.start(c,request.get('intent') if action=='activate' else None)
        except Exception as error:host.reject_runtime(c,error);raise
    if action=='recover-preparation':
        fields(request,set());return state.recover_preparation(c,lambda:host.stop_owned(c))
    raise Refused('unsupported AQA operation')


def recorded_owner(value):
    c=host.contract(State(ROOT).get('owner.json')['contract'])
    require(c['owner']==token(value),'publisher command belongs to another original owner')
    return c


def main():
    resource.setrlimit(resource.RLIMIT_CORE,(0,0));os.umask(0o077)
    args=sys.argv[1:]
    if len(args)==2 and args[0]=='launch':
        host.launch(args[1]);return
    require(sys.platform=='linux' and os.geteuid()==0,'publisher administration requires Linux root')
    host.protected_paths(runtime=False)
    if len(args)==2 and args[0] in ('condition','guard','firewall-load'):
        c=recorded_owner(args[1])
        if args[0]=='firewall-load':host.owned(c);host.firewall('load')
        else:host.guard(c,plaintext=args[0]=='guard')
        return
    if len(args)==4 and args[0]=='logs':
        require(args[2].isdigit() and args[3] in ('once','follow'),'invalid publisher log selector')
        host.logs(recorded_owner(args[1]),int(args[2]),args[3]=='follow');return
    observe=len(args)==2 and args[0]=='observe'
    require(observe or args in ([],['within-run']),'unsupported publisher controller invocation')
    lock=Path('/opt/erpc');owned_directory(lock,True,0o755)
    descriptor=os.open(lock,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        if args!=['within-run']:
            try:fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:
                if observe:print('{"observer":"operation in progress"}');return
                raise Refused('another managed node operation is in progress') from None
        if observe:
            c=recorded_owner(args[1]);action='observe'
            try:
                result=host.observe(c);host.event(action,True)
            except Exception:
                try:host.owned(c);host.event(action,False)
                except Exception:pass
                raise
        else:
            raw=sys.stdin.buffer.read(65537);require(len(raw)<=65536,'publisher request exceeds its bound')
            request=unique_json(raw);action=request.get('action') if isinstance(request,dict) else None
            try:result=dispatch(request)
            except Exception:
                if action in host.EVENT_ACTIONS:
                    try:host.owned(host.contract(request.get('contract')));host.event(action,False)
                    except Exception:pass
                raise
            if action in host.EVENT_ACTIONS:
                try:host.event(action,True)
                except Exception:result['journal_recorded']=False
        print(json.dumps(result,separators=(',',':')))
    finally:os.close(descriptor)


if __name__=='__main__':
    try:main()
    except Exception:
        print('AQA original authority or operation could not be verified; private output withheld',file=sys.stderr)
        sys.exit(255 if sys.argv[1:2]==['condition'] else 1)
