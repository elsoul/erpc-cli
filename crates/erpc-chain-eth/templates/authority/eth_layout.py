# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original native data directory bindings; creation uses anchored no-follow descriptors."""
import os
from pathlib import Path
import stat
import re
from eth_files import require,root_directory,synchronize,run,unique

ROOTS={'rpc':Path('/var/lib/ethereum'),'validator':Path('/var/lib/erpc-eth-validator')}
USERS={'rpc':{'reth':'reth','lighthouse':'lighthouse'},
       'validator':{'reth':'ev-reth','beacon':'ev-beacon','vc':'ev-validator'}}
FLAGS=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
MOUNTS=Path('/proc/self/mountinfo')


def binding(info):return {'device':info.st_dev,'inode':info.st_ino}


def filesystem(value):
    require(isinstance(value,dict) and set(value)=={'uuid','type','root'}
            and value['type'] in ('ext4','xfs') and value['root']=='/'
            and isinstance(value['uuid'],str)
            and re.fullmatch('[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',value['uuid'])
            and value['uuid']!='00000000-0000-0000-0000-000000000000',
            'original volume requires an ext4/xfs filesystem UUID and whole-filesystem mount')
    return value


def probe(root,descriptor):
    # util-linux reads the current kernel mount table. Match its device number
    # to the retained no-follow descriptor, never persist that number as identity.
    before=os.fstat(descriptor)
    raw=run(['/usr/bin/findmnt','--kernel','--first-only','--json','--target',str(root),
             '--output','UUID,FSTYPE,MAJ:MIN,FSROOT'],timeout=10)
    require(len(raw)<=16384,'filesystem observation exceeds its bound')
    result=unique(raw)
    require(isinstance(result,dict) and set(result)=={'filesystems'} and isinstance(result['filesystems'],list)
            and len(result['filesystems'])==1,'selected filesystem observation is ambiguous')
    row=result['filesystems'][0]
    require(isinstance(row,dict) and set(row)=={'uuid','fstype','maj:min','fsroot'}
            and row['maj:min']==str(os.major(before.st_dev))+':'+str(os.minor(before.st_dev)),
            'filesystem observation differs from original open directory')
    check=root_directory(root)
    try:require(binding(os.fstat(check))==binding(before)==binding(os.fstat(descriptor)),
                'native root changed during filesystem observation')
    finally:os.close(check)
    return filesystem({'uuid':row['uuid'],'type':row['fstype'],'root':row['fsroot']})


def volume(state,contract,accounts,descriptor):
    require(state.exists('volume.json'),'original stable volume receipt is missing; use the explicit independent-evidence volume upgrade')
    record=state.get('volume.json');wanted=expected(contract,accounts)
    require(isinstance(record,dict) and set(record)=={'schema','original','inode','filesystem'}
            and type(record['schema']) is int and record['schema']==1 and record['original']==wanted
            and type(record['inode']) is int and record['inode']==os.fstat(descriptor).st_ino,
            'original stable volume authority differs; explicit historical upgrade is required')
    require(filesystem(record['filesystem'])==probe(ROOTS[contract['role']],descriptor),
            'original filesystem UUID/type changed')
    synchronize(state.path('volume.json'))
    return record


def publish_volume(state,contract,accounts,descriptor,proof=None):
    wanted=expected(contract,accounts);actual=probe(ROOTS[contract['role']],descriptor)
    if proof is not None:require(filesystem(proof)==actual,'independent original filesystem evidence differs')
    record={'schema':1,'original':wanted,'inode':os.fstat(descriptor).st_ino,'filesystem':actual}
    if state.exists('volume.json'):
        require(state.get('volume.json')==record,'original filesystem authority cannot be replaced')
    else:state.put('volume.json',record)
    synchronize(state.path('volume.json'))
    return record


def upgrade(state,contract,accounts,proof):
    """Caller has fenced and drained original writers; no data/floor receipt rewrite."""
    filesystem(proof);state.check(contract);wanted=expected(contract,accounts)
    complete=state.exists('layout.json')
    record=state.get('layout.json' if complete else 'layout-intent.json')
    fields={'binding','mode','children'} if complete else {'binding'}
    require({key:record.get(key) for key in wanted}==wanted and set(record)==set(wanted)|fields
            and isinstance(record['binding'],dict) and set(record['binding'])=={'device','inode'},
            'original completed or pending native layout is unavailable')
    if not complete:
        require(not any(state.exists(name) for name in ('active.json','snapshot.json','engine-jwt.json',
                    'source-reth.json','source-reth-pending.json','source-lighthouse.json','source-lighthouse-pending.json')),
                'incomplete initial layout cannot replace established native data authority')
    directory=root_directory(ROOTS[contract['role']])
    try:
        info=os.fstat(directory)
        require(info.st_ino==record['binding']['inode'] and stat.S_IMODE(info.st_mode) in
                ((record['mode'],) if complete else (0o700,0o711,0o750,0o755)),
                'original data directory inode or permissions changed')
        require(probe(ROOTS[contract['role']],directory)==filesystem(proof),'independent original filesystem evidence differs')
        topology(contract['role'])
        names=set(os.listdir(directory))
        if not complete:require(names<=set(wanted['layout'])|{'lost+found'},'incomplete native layout contains unowned entries')
        for name,user in wanted['layout'].items():
            if not complete and name not in names:continue
            child=os.open(name,FLAGS,dir_fd=directory)
            try:
                entry=os.fstat(child);identity=accounts['users'][user]
                require(entry.st_dev==info.st_dev and stat.S_IMODE(entry.st_mode)==0o700,
                        'original native child filesystem or permissions changed')
                if complete:
                    require(entry.st_ino==record['children'][name]['inode'] and entry.st_uid==identity['uid']
                            and entry.st_gid==identity['gid'],'original native child authority changed')
                else:
                    require(not os.listdir(child) and (entry.st_uid==0 or (entry.st_uid==identity['uid']
                            and entry.st_gid==identity['gid'])),'incomplete native child is not an empty original preparation')
            finally:os.close(child)
        if not complete and 'lost+found' in names:
            child=os.open('lost+found',FLAGS,dir_fd=directory)
            try:
                entry=os.fstat(child)
                require(entry.st_dev==info.st_dev and entry.st_uid==0 and not entry.st_mode&0o022
                        and not os.listdir(child),'original filesystem recovery directory is not empty/protected')
            finally:os.close(child)
        publish_volume(state,contract,accounts,directory,proof)
    finally:os.close(directory)
    if complete:verify(state,contract,accounts)
    return {'upgraded':True,'started':False,'data_preserved':True,'filesystem':proof,'initialization_pending':not complete}


def clean_volume(descriptor):
    for name in os.listdir(descriptor):
        require(name=='lost+found','unowned data cannot be adopted as an empty native volume')
        child=os.open(name,FLAGS,dir_fd=descriptor)
        try:
            info=os.fstat(child)
            require(info.st_uid==0 and not info.st_mode&0o022 and not os.listdir(child),
                    'filesystem recovery directory must be empty and protected')
        finally:os.close(child)


def expected(contract,accounts):
    require(accounts['role']==contract['role'],'native data account profile differs')
    return {'contract':contract,'accounts':accounts,'root':str(ROOTS[contract['role']]),'layout':USERS[contract['role']]}


def prepare(state,contract,accounts):
    """Caller must establish original-UID quiescence first; no named-path chown."""
    state.check(contract);wanted=expected(contract,accounts)
    if state.exists('layout.json'):
        verify(state,contract,accounts);synchronize(state.path('layout.json'));return
    root=ROOTS[contract['role']];parent=root_directory(root.parent)
    try:
        pending=state.get('layout-intent.json') if state.exists('layout-intent.json') else None
        if pending is None:
            state.put('layout-intent.json',dict(wanted,binding=None));synchronize(state.path('layout-intent.json'))
            try:
                directory=os.open(root.name,FLAGS,dir_fd=parent)
            except FileNotFoundError:
                os.mkdir(root.name,0o700,dir_fd=parent);os.fsync(parent)
                directory=os.open(root.name,FLAGS,dir_fd=parent)
            try:
                info=os.fstat(directory)
                require(info.st_uid==0 and stat.S_IMODE(info.st_mode) in (0o700,0o711,0o750,0o755),
                        'new data volume must have protected root ownership')
                clean_volume(directory)
                publish_volume(state,contract,accounts,directory)
                state.put('layout-intent.json',dict(wanted,binding=binding(info)))
            finally:os.close(directory)
        else:require({key:pending.get(key) for key in wanted}==wanted,'native data preparation belongs to another original profile')
        synchronize(state.path('layout-intent.json'))
        pending=state.get('layout-intent.json')
        # A crash after publishing intent but before mkdir may leave no root.
        try:directory=os.open(root.name,FLAGS,dir_fd=parent)
        except FileNotFoundError:
            require(pending['binding'] is None,'selected data volume vanished')
            os.mkdir(root.name,0o700,dir_fd=parent);os.fsync(parent)
            directory=os.open(root.name,FLAGS,dir_fd=parent)
        try:
            info=os.fstat(directory)
            require(info.st_uid==0 and not info.st_mode&0o022,'native root ownership changed')
            if pending['binding'] is None:
                clean_volume(directory);publish_volume(state,contract,accounts,directory);pending['binding']=binding(info)
                state.put('layout-intent.json',pending);synchronize(state.path('layout-intent.json'))
            volume(state,contract,accounts,directory)
            require(info.st_ino==pending['binding']['inode'],'selected original native directory changed')
            require(set(os.listdir(directory))<=set(wanted['layout'])|{'lost+found'},'incomplete data root contains unowned payload')
            os.fchmod(directory,0o711);os.fsync(directory);os.fsync(parent)
            children={}
            for name,user in wanted['layout'].items():
                identity=accounts['users'][user]
                try:child=os.open(name,FLAGS,dir_fd=directory)
                except FileNotFoundError:
                    os.mkdir(name,0o700,dir_fd=directory)
                    child=os.open(name,FLAGS,dir_fd=directory)
                try:
                    entry=os.fstat(child)
                    require(entry.st_dev==info.st_dev and stat.S_IMODE(entry.st_mode)==0o700 and not os.listdir(child),
                            'unfinished native directory is indirect, mounted, nonprivate or contains data')
                    if entry.st_uid==0:os.fchown(child,identity['uid'],identity['gid'])
                    else:require(entry.st_uid==identity['uid'] and entry.st_gid==identity['gid'],'native directory owner differs')
                    os.fchmod(child,0o700);os.fsync(child);os.fsync(directory)
                    children[name]=binding(os.fstat(child))
                finally:os.close(child)
            state.put('layout.json',dict(wanted,binding=binding(info),mode=0o711,children=children))
            synchronize(state.path('layout.json'))
        finally:os.close(directory)
    finally:os.close(parent)


def open_native(state,contract,accounts,name):
    record=state.get('layout.json');wanted=expected(contract,accounts)
    require({key:record.get(key) for key in wanted}==wanted and set(record)==set(wanted)|{'binding','mode','children'}
            and name in wanted['layout'],'original native layout is unavailable')
    root=ROOTS[contract['role']];directory=root_directory(root)
    try:
        info=os.fstat(directory)
        volume(state,contract,accounts,directory)
        root_device=info.st_dev
        require(info.st_ino==record['binding']['inode'] and stat.S_IMODE(info.st_mode)==record['mode'],
                'original native data root changed')
        child=os.open(name,FLAGS,dir_fd=directory)
    finally:os.close(directory)
    try:
        info=os.fstat(child);identity=accounts['users'][wanted['layout'][name]]
        require(info.st_ino==record['children'][name]['inode'] and info.st_dev==root_device
                and info.st_uid==identity['uid'] and info.st_gid==identity['gid']
                and stat.S_IMODE(info.st_mode)==0o700,'original native directory identity or permissions changed')
        return child
    except BaseException:os.close(child);raise


def verify(state,contract,accounts):
    state.check(contract)
    for name in USERS[contract['role']]:os.close(open_native(state,contract,accounts,name))


def descendant(state,contract,accounts,name,relative):
    require(isinstance(relative,str) and relative and all(part and part not in ('.','..') for part in relative.split('/')),
            'native descendant must remain within its original directory')
    fd=open_native(state,contract,accounts,name);owner=accounts['users'][USERS[contract['role']][name]]
    try:
        root_device=os.fstat(fd).st_dev
        for component in relative.split('/'):
            child=os.open(component,FLAGS,dir_fd=fd)
            try:
                info=os.fstat(child)
                require(info.st_uid==owner['uid'] and info.st_gid==owner['gid'] and info.st_dev==root_device
                        and stat.S_IMODE(info.st_mode)==0o700,'native private descendant authority changed')
            except BaseException:os.close(child);raise
            os.close(fd);fd=child
        return fd
    except BaseException:os.close(fd);raise


def topology(role):
    root=str(ROOTS[role]);raw=MOUNTS.read_bytes()
    require(len(raw)<=8*1024*1024,'mount namespace exceeds its bound')
    for line in raw.decode().splitlines():
        fields=line.split();require(len(fields)>=10 and '-' in fields[6:],'invalid kernel mount record')
        mount=re.sub(r'\\(040|011|012|134)',lambda match:chr(int(match.group(1),8)),fields[4])
        require('\\' not in mount and mount.startswith('/'),'invalid kernel mount path')
        require(not mount.startswith(root+'/'),'nested native database/snapshot mount cannot be adopted')


def allocated(directory,device):
    """Measure allocated blocks through retained descriptors, never du on a named link."""
    seen=set();total=0;pending=[os.dup(directory)];entries=0
    try:
        while pending:
            current=pending.pop()
            try:
                for name in os.listdir(current):
                    entries+=1;require(entries<=5000000,'native database inventory exceeds its bound')
                    try:info=os.stat(name,dir_fd=current,follow_symlinks=False)
                    except FileNotFoundError:continue
                    require(info.st_dev==device,'native database crosses the original filesystem')
                    if stat.S_ISDIR(info.st_mode):
                        try:child=os.open(name,FLAGS,dir_fd=current)
                        except FileNotFoundError:continue
                        if os.fstat(child).st_dev!=device:os.close(child);require(False,'native directory mount changed')
                        pending.append(child)
                    else:
                        require(stat.S_ISREG(info.st_mode),'native data contains an indirect or special entry')
                        key=(info.st_dev,info.st_ino)
                        if key not in seen:total+=info.st_blocks*512;seen.add(key)
            finally:os.close(current)
        return total
    finally:
        for current in pending:os.close(current)


def capacity(state,contract,accounts):
    verify(state,contract,accounts);topology(contract['role'])
    role=contract['role'];require(role in ('rpc','validator'),'original Ethereum capacity role required')
    selected=root_directory(ROOTS[role])
    try:
        info=os.fstat(selected);stats=os.fstatvfs(selected)
        used=0
        for name in USERS[role]:
            child=open_native(state,contract,accounts,name)
            try:used+=allocated(child,info.st_dev)
            finally:os.close(child)
        free=stats.f_bavail*stats.f_frsize
        # ERPC admission/headroom policy, not a claimed fixed upstream DB size.
        initial=(2000 if role=='validator' else 1500 if contract['kind']=='full' else 3500)*10**9
        required=max(200*10**9,initial-used)
        require(free>=required,'original native filesystem lacks remaining-sync/operational free space')
        return {'allocated_bytes':used,'free_bytes':free,'required_free_bytes':required,'device':info.st_dev}
    finally:os.close(selected)
