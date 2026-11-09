# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original numeric credential grants on volatile root-controlled runtime paths."""
import os
import fcntl
from pathlib import Path
import re
import secrets
import stat
from eth_files import checked_file,digest,read,require,root_directory,synchronize
import eth_validator_custody as custody
import eth_validator_native as native

DIRECTORIES={'reth':0o711,'beacon':0o711,'validator':0o711,'trust':0o755,'tls-issuance':0o700,'custody':0o711}


def boot():
    value=read(Path('/proc/sys/kernel/random/boot_id'),128).decode().strip()
    require(re.fullmatch('[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}',value),'kernel boot identity unavailable')
    return value


def binding(info):return {'device':info.st_dev,'inode':info.st_ino}


def directory_specs(plan):
    result={name:{'uid':0,'gid':0,'mode':mode} for name,mode in DIRECTORIES.items()}
    engine=plan['users']['ev-reth'];result['engine']={'uid':engine['uid'],'gid':engine['gid'],'mode':0o710}
    return result


def expected(state,contract):
    authority=custody.authority(state,contract)
    return {'authority':authority,'boot':boot()},authority['accounts']


def verify(state,contract):
    wanted,plan=expected(state,contract);record=state.get('runtime.json')
    require(set(record)=={'authority','boot','root','children'} and all(record[key]==value for key,value in wanted.items()),
            'original volatile runtime authority differs')
    native.volatile(native.RUN)
    root=root_directory(native.RUN)
    try:
        info=os.fstat(root)
        require(binding(info)==record['root'] and stat.S_IMODE(info.st_mode)==0o755,'original volatile root changed')
        specs=directory_specs(plan)
        require(set(record['children'])==set(specs),'original runtime children differ')
        for name,spec in specs.items():
            child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=root)
            try:
                info=os.fstat(child)
                require(binding(info)==record['children'][name] and info.st_dev==record['root']['device']
                        and info.st_uid==spec['uid'] and info.st_gid==spec['gid'] and stat.S_IMODE(info.st_mode)==spec['mode'],
                        'original runtime directory ownership or identity changed')
            finally:os.close(child)
    finally:os.close(root)
    synchronize(state.path('runtime.json'));return record,plan


def prepare(state,contract,quiescent):
    custody.authority(state,contract)
    directory=root_directory(state.directory)
    try:fd=os.open('runtime.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=directory)
    finally:os.close(directory)
    with os.fdopen(fd,'rb') as lock:
        checked_file(os.fstat(lock.fileno()),mode=0o600);fcntl.flock(lock,fcntl.LOCK_EX)
        return prepare_locked(state,contract,quiescent)


def prepare_locked(state,contract,quiescent):
    wanted,plan=expected(state,contract)
    if state.exists('runtime.json') and state.get('runtime.json').get('boot')==wanted['boot']:
        return verify(state,contract)[0]
    quiescent()
    parent=root_directory(native.RUN.parent)
    try:
        if state.exists('runtime-intent.json') and state.get('runtime-intent.json').get('boot')==wanted['boot']:
            require(state.get('runtime-intent.json')==wanted,'interrupted runtime belongs to another original authority')
        else:
            if native.RUN.exists() or native.RUN.is_symlink():
                root=os.open(native.RUN.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
                try:
                    info=os.fstat(root);require(info.st_uid==0 and not info.st_mode&0o022 and not os.listdir(root),
                                               'unowned volatile runtime cannot be adopted')
                finally:os.close(root)
            state.put('runtime-intent.json',wanted)
        synchronize(state.path('runtime-intent.json'))
        try:os.mkdir(native.RUN.name,0o700,dir_fd=parent)
        except FileExistsError:pass
        root=os.open(native.RUN.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
        try:
            info=os.fstat(root);require(info.st_uid==0 and not info.st_mode&0o022,'untrusted original runtime root')
            os.fchmod(root,0o755);os.fsync(root);os.fsync(parent);native.volatile(native.RUN)
            specs=directory_specs(plan)
            require(set(os.listdir(root))<=set(specs),'incomplete runtime has unowned material')
            children={}
            for name,spec in specs.items():
                try:os.mkdir(name,0o700,dir_fd=root)
                except FileExistsError:pass
                child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=root)
                try:
                    info=os.fstat(child)
                    require(info.st_dev==os.fstat(root).st_dev and not os.listdir(child)
                            and (info.st_uid,info.st_gid) in ((0,0),(spec['uid'],spec['gid'])) and not info.st_mode&0o022,
                            'unfinished runtime contains an unknown identity or payload')
                    os.fchown(child,spec['uid'],spec['gid']);os.fchmod(child,spec['mode']);os.fsync(child)
                    children[name]=binding(os.fstat(child));os.fsync(root)
                finally:os.close(child)
            record=dict(wanted,root=binding(os.fstat(root)),children=children)
            state.put('runtime.json',record);synchronize(state.path('runtime.json'))
        finally:os.close(root)
    finally:os.close(parent)
    return record


def policy(plan,name):
    policies={
        'reth/jwt':('ev-reth',0o400),'beacon/jwt':('ev-beacon',0o400),
        'beacon/server.key':('ev-beacon',0o400),'beacon/server.crt':(None,0o444),
        'validator/password':('ev-validator',0o400),
        'trust/beacon-ca.pem':(None,0o444),'trust/engine-with-public-ca.pem':(None,0o444),
    }
    require(name in policies,'unknown original credential grant')
    user,mode=policies[name];identity={'uid':0,'gid':0} if user is None else plan['users'][user]
    return dict(identity,mode=mode)


def grant(state,contract,name,raw,quiescent):
    record,plan=verify(state,contract);spec=policy(plan,name)
    require(isinstance(raw,bytes) and 0<len(raw)<=1024*1024,'original runtime input exceeds its bound')
    path=native.RUN/name;directory=root_directory(path.parent)
    desired={'authority':record['authority'],'boot':record['boot'],'root':record['root'],'name':name,'policy':spec,'sha256':digest(raw)}
    receipt='runtime-file-'+name.replace('/','-')+'.json';pending='runtime-pending-'+name.replace('/','-')+'.json'
    try:
        try:
            old=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=directory)
        except FileNotFoundError:old=None
        if old is not None:
            with os.fdopen(old,'rb') as stream:
                info=os.fstat(stream.fileno());checked_file(info,owner=spec['uid'],mode=spec['mode'])
                require(info.st_gid==spec['gid'] and info.st_size<=1024*1024,'original credential grant group or size differs')
                current=stream.read(1024*1024+1);require(len(current)<=1024*1024,'runtime credential grew beyond its bound')
                authorities=[(candidate,state.get(candidate)) for candidate in (receipt,pending) if state.exists(candidate)]
                matches=[candidate for candidate,authority in authorities if authority==dict(desired,sha256=digest(current))]
                require(matches,'existing runtime credential lacks matching original authority')
                if current==raw:
                    os.fsync(stream.fileno())
                    for candidate in matches:synchronize(state.path(candidate))
                    state.put(receipt,desired);synchronize(state.path(receipt));return
            # Changing a valid credential is allowed only under stopped cutover.
            current_operation=state.get('cutover.json')
            require(state.current(contract,current_operation['intent'])==current_operation,'original credential cutover differs')
        elif state.exists(receipt):
            previous=state.get(receipt)
            if previous.get('boot')==record['boot'] and previous.get('sha256')!=desired['sha256']:
                current_operation=state.get('cutover.json')
                require(state.current(contract,current_operation['intent'])==current_operation,'new credential requires its stopped original cutover')
        # The actual controller supplies a selected-original-UID process proof.
        # Merely finding a cutover receipt never proves shutdown succeeded.
        quiescent(name)
        state.put(pending,desired);synchronize(state.path(pending))
        temporary='.credential-'+secrets.token_hex(16)
        descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=directory)
        try:
            with os.fdopen(descriptor,'wb') as output:
                output.write(raw);output.flush();os.fchown(output.fileno(),spec['uid'],spec['gid'])
                os.fchmod(output.fileno(),spec['mode']);os.fsync(output.fileno())
                os.replace(temporary,path.name,src_dir_fd=directory,dst_dir_fd=directory);os.fsync(directory)
            state.put(receipt,desired);synchronize(state.path(receipt))
        finally:
            try:os.unlink(temporary,dir_fd=directory)
            except FileNotFoundError:pass
    finally:os.close(directory)
