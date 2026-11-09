# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Package/config preparation under the owning deployment lock."""
import base64
import datetime
import email.utils
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import time
import urllib.request
from erpc_monad_common import (ROOT, CONFIG, RELEASES, HELPERS, ENV, atomic, digest, execute,
                    fsync_dir, json_bytes, owned_directory, read, require, unique_json, seed_data)
import erpc_monad_package as package


DATA_LAYOUT=('data','data/ledger','data/ledger/headers','data/ledger/bodies',
             'data/wal','data/forkpoint','data/validators')


def sync_receipt(path,expected):
    require(unique_json(read(path))==expected,'native data preparation receipt changed')
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    try:os.fsync(descriptor)
    finally:os.close(descriptor)
    fsync_dir(ROOT)


def empty_data_volume(path):
    """Only an empty root-owned filesystem's recovery directory is tolerated."""
    for entry in path.iterdir():
        info=entry.lstat()
        require(entry.name=='lost+found' and stat.S_ISDIR(info.st_mode) and info.st_uid==0
                and not info.st_mode&0o022 and not any(entry.iterdir()),
                'replacement consensus filesystem contains unowned data')


def mounted_rows(*arguments):
    result=execute(['/usr/bin/findmnt','--task','1','--json',*arguments],timeout=30)
    require(0<len(result.stdout)<=8*1024*1024,'consensus mount observation exceeds its bound')
    value=unique_json(result.stdout)
    require(isinstance(value,dict) and set(value)=={'filesystems'} and isinstance(value['filesystems'],list),
            'consensus mount observation is unavailable')
    return value['filesystems']


def filesystem(path):
    """Stable filesystem identity plus repeated live kernel/path correspondence.

    Device numbers and mount IDs are observations, never persisted authority.
    Read PID1 mountinfo so service sandbox bind mounts do not become the host's
    persistent storage identity. Unknown/unidentified volumes are not adopted.
    """
    before=path.lstat()
    require(stat.S_ISDIR(before.st_mode),'consensus data path is redirected')
    mounts=mounted_rows('--list','--output','TARGET')
    require(0<len(mounts)<=100000,'consensus mount topology is unavailable')
    data=ROOT/'data';count=0
    for entry in mounts:
        require(isinstance(entry,dict) and set(entry)=={'target'} and isinstance(entry['target'],str),
                'invalid consensus mount topology')
        target=Path(entry['target'])
        require(target.is_absolute() and os.path.normpath(target)==str(target),'invalid consensus mount path')
        require(not (target!=data and data in target.parents),'nested consensus mounts, including same-device binds, are unsupported')
        if target==data:count+=1
    require(count<=1,'stacked consensus data mounts are unsupported')
    rows=mounted_rows('--target',str(path),'--output','UUID,FSTYPE,FSROOT,MAJ:MIN,OPTIONS')
    require(len(rows)==1 and isinstance(rows[0],dict),'ambiguous consensus filesystem')
    value=rows[0];identifier=value.get('uuid');major_minor=value.get('maj:min')
    require(isinstance(identifier,str) and re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',identifier)
            and any(char not in '0-' for char in identifier)
            and value.get('fstype') in ('ext4','xfs') and value.get('fsroot')=='/'
            and isinstance(value.get('options'),str) and 'rw' in value['options'].split(',')
            and isinstance(major_minor,str) and re.fullmatch('[0-9]+:[0-9]+',major_minor),
            'consensus data requires an identified writable ext4/XFS filesystem root')
    major,minor=map(int,major_minor.split(':'))
    after=path.lstat()
    require(os.makedev(major,minor)==before.st_dev and (before.st_dev,before.st_ino)==(after.st_dev,after.st_ino),
            'consensus mount changed during observation')
    return {'uuid':identifier,'filesystem':value['fstype'],'filesystem_root':value['fsroot']}


def binding(path,info):
    result=filesystem(path)
    after=path.lstat()
    require((info.st_dev,info.st_ino)==(after.st_dev,after.st_ino),'consensus directory changed during identity observation')
    return dict(result,inode=info.st_ino)


def verify_data(state,c,uid,gid,allow_provisional=False):
    """Startup never accepts a replacement or an unfinished filesystem choice."""
    state.check(c);owned_directory(ROOT)
    saved=state.get('data-ready.json')
    expected={'format':2,'contract':c,'uid':uid,'gid':gid,'layout':list(DATA_LAYOUT)}
    require(type(saved.get('format'))is int and saved['format']==2,'legacy consensus receipt lacks original filesystem UUID; reviewed recovery required')
    require(set(saved)==set(expected)|{'binding','final'} and type(saved['final'])is bool
            and (saved['final'] or allow_provisional)
            and {key:saved[key] for key in expected}==expected,'native data is not bound to this deployment')
    descriptors={};flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
    try:
        descriptors['']=os.open(ROOT,flags)
        for relative in DATA_LAYOUT:
            parent,_,name=relative.rpartition('/')
            fd=os.open(name,flags,dir_fd=descriptors[parent]);descriptors[relative]=fd
            info=os.fstat(fd)
            require(info.st_dev==os.fstat(descriptors['data']).st_dev,'nested native data filesystem differs')
            require(info.st_uid==uid and info.st_gid==gid and stat.S_IMODE(info.st_mode)==0o700,
                    'native data directory authority changed')
            if relative=='data':require(binding(ROOT/'data',info)==saved['binding'],
                                        'original native filesystem changed')
        require(binding(ROOT/'data',os.fstat(descriptors['data']))==saved['binding'],
                'original native filesystem changed during startup verification')
    finally:
        for fd in reversed(list(descriptors.values())):os.close(fd)


def unused_layout(uid,gid,retained=None,selection=False):
    """Only the old constructor's empty directory prefix is recoverable."""
    known=retained or {};observed={};descriptors={}
    flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
    try:
        descriptors['']=os.open(ROOT,flags)
        for relative in (*DATA_LAYOUT,*(('data/lost+found',) if selection else ())):
            parent,_,name=relative.rpartition('/')
            if parent not in descriptors:
                require(relative not in known,'original incomplete directory disappeared')
                continue
            try:fd=os.open(name,flags,dir_fd=descriptors[parent])
            except FileNotFoundError:
                require(relative not in known,'original incomplete directory disappeared')
                continue
            descriptors[relative]=fd;info=os.fstat(fd)
            children=[]
            with os.scandir(fd) as entries:
                for entry in entries:
                    children.append(entry.name);require(len(children)<=16,'incomplete layout contains native or unknown payload')
            recovery=relative=='data/lost+found'
            mode=stat.S_IMODE(info.st_mode)
            require(info.st_dev==os.fstat(descriptors['data']).st_dev and info.st_uid in (0,uid)
                    and info.st_gid==(0 if info.st_uid==0 else gid)
                    and (mode==0o700 or selection and relative in ('data','data/lost+found') and info.st_uid==0 and mode==0o755),
                    'incomplete native layout has another device, original owner or mode')
            allowed={entry[len(relative)+1:].split('/')[0] for entry in DATA_LAYOUT if entry.startswith(relative+'/')}
            if selection and relative=='data':allowed.add('lost+found')
            require(set(children)<=allowed and (not recovery or info.st_uid==0 and not children),
                    'incomplete native layout contains unknown or recovered payload')
            if info.st_uid==0:require(set(children)<=({'lost+found'} if selection and relative=='data' else set()),
                                     'unhanded empty staging contains unexpected children')
            original=known.get(relative)
            if original is not None:
                require(set(original)=={'inode','uid','gid','mode'} and type(original['inode'])is int
                        and original['inode']==info.st_ino and original['uid'] in (0,uid)
                        and original['gid']==(0 if original['uid']==0 else gid)
                        and (info.st_uid,info.st_gid) in ((original['uid'],original['gid']),(uid,gid))
                        and not (original['uid']==uid and info.st_uid!=uid),
                        'original incomplete directory inode or numeric authority changed')
                observed[relative]=original
            else:
                require(retained is None or info.st_uid==0 and not children and not recovery,
                        'unrecorded partial construction cannot adopt a native-owned directory')
                observed[relative]={'inode':info.st_ino,'uid':info.st_uid,'gid':info.st_gid,'mode':mode}
        require(set(known)<=set(observed),'original incomplete directory disappeared')
        return observed
    finally:
        for fd in reversed(list(descriptors.values())):os.close(fd)


def recover_unused_layout(state,c,uid,gid,original_uuid):
    """Convert genuine pre-client legacy interruptions without inventing history."""
    journal=ROOT/'data-incomplete-upgrade.json';ready=ROOT/'data-ready.json'
    expected={'contract':c,'uid':uid,'gid':gid,'layout':list(DATA_LAYOUT)}
    if journal.exists():
        record=state.get(journal.name)
        require(isinstance(record,dict) and set(record)=={'format','contract','uid','gid','kind','uuid','filesystem',
                'original_files','directories','upgraded','phase'} and type(record['format'])is int and record['format']==1
                and record['contract']==c and record['uid']==uid and record['gid']==gid and record['uuid']==original_uuid
                and record['kind'] in ('initial','selected') and record['phase'] in ('reserved','complete'),
                'incomplete-layout recovery belongs to another original scope or UUID')
        require(isinstance(record['original_files'],dict)
                and (set(record['original_files'])=={'data-preparing.json'} if record['kind']=='initial' else
                     {'data-ready.json','data-mount-preparing.json'}<=set(record['original_files'])<=
                     {'data-ready.json','data-mount-preparing.json','data-preparing.json'}),
                'incomplete-layout recovery lacks its original source receipts')
        originals={}
        for name,value in record['original_files'].items():
            require(name in ('data-preparing.json','data-ready.json','data-mount-preparing.json')
                    and set(value)=={'bytes','sha256'} and isinstance(value['bytes'],str) and len(value['bytes'])<=65536,
                    'invalid retained incomplete-layout source')
            raw=base64.b64decode(value['bytes'],validate=True)
            require(digest(raw)==value['sha256'],'retained original incomplete-layout bytes changed')
            decoded=unique_json(raw);originals[name]=decoded
            if name=='data-preparing.json':require(decoded==expected,'original incomplete initialization scope changed')
            elif name=='data-ready.json':
                require(isinstance(decoded,dict) and set(decoded)==set(expected)|{'binding','final'}
                        and decoded['final'] is False and {key:decoded[key] for key in expected}==expected,
                        'original provisional source scope changed')
            if name!='data-ready.json':require(read(ROOT/name)==raw,'original incomplete-layout input changed')
        if record['kind']=='selected':
            selected=originals['data-mount-preparing.json']
            require(isinstance(selected,dict) and set(selected)=={'original','binding'}
                    and selected['original']==originals['data-ready.json'] and isinstance(selected['binding'],dict)
                    and set(selected['binding'])=={'device','inode'}
                    and selected['binding']['inode']==record['directories'].get('data',{}).get('inode'),
                    'retained original mount selection differs from its directory')
        if ready.exists() and state.get(ready.name).get('format')==2:
            current=state.get(ready.name);planned=record['upgraded']
            require(isinstance(planned,dict) and dict(current,final=planned['final'])==planned
                    and (current['final'] or not planned['final']),'completed recovered layout differs')
            verify_data(state,c,uid,gid,allow_provisional=True);sync_receipt(ready,current)
            record['phase']='complete';state.put(journal.name,record);sync_receipt(journal,record)
            return {'filesystem_identity_upgraded':True,'stopped':True,'history_preserved':True,'empty_layout_completed':True}
        require(record['phase']=='reserved','completed recovered directory receipt is missing')
        if 'data-ready.json' in record['original_files']:
            require(read(ready)==base64.b64decode(record['original_files']['data-ready.json']['bytes'],validate=True),
                    'original provisional receipt changed')
        else:require(not ready.exists(),'unexpected completed directory receipt')
    else:
        saved=state.get(ready.name) if ready.exists() else None
        selection=ROOT/'data-mount-preparing.json'
        if saved is None:
            require(not selection.exists() and state.get('data-preparing.json')==expected,
                    'original incomplete initialization is missing or ambiguous')
            kind='initial';names=['data-preparing.json']
        else:
            require(set(saved)==set(expected)|{'binding','final'} and saved['final'] is False
                    and {key:saved[key] for key in expected}==expected,'not an unused original provisional layout')
            require(isinstance(saved['binding'],dict) and set(saved['binding'])=={'device','inode'}
                    and all(type(saved['binding'][key])is int and saved['binding'][key]>0 for key in ('device','inode')),
                    'original provisional binding is malformed')
            selected=state.get(selection.name)
            require(set(selected)=={'original','binding'} and selected['original']==saved
                    and isinstance(selected['binding'],dict) and set(selected['binding'])=={'device','inode'}
                    and all(type(selected['binding'][key])is int and selected['binding'][key]>0 for key in ('device','inode'))
                    and selected['binding']!=saved['binding'],'original first mount selection is unavailable')
            require((ROOT/'data').lstat().st_ino==selected['binding']['inode'],'recorded selected mount inode differs')
            kind='selected';names=['data-ready.json','data-mount-preparing.json']
            if (ROOT/'data-preparing.json').exists():
                require(state.get('data-preparing.json')==expected,'original provisional initializer differs')
                names.append('data-preparing.json')
        observed=filesystem(ROOT/'data' if (ROOT/'data').exists() else ROOT)
        require(observed['uuid']==original_uuid,'supplied original UUID does not match the unused original filesystem')
        record={'format':1,'contract':c,'uid':uid,'gid':gid,'kind':kind,'uuid':original_uuid,'filesystem':observed,
                'original_files':{},'directories':unused_layout(uid,gid,selection=kind=='selected'),'upgraded':None,'phase':'reserved'}
        for name in names:
            raw=read(ROOT/name);record['original_files'][name]={'bytes':base64.b64encode(raw).decode(),'sha256':digest(raw)}
    require(not any((ROOT/name).exists() for name in
        ('installed.json','bootstrap-copied','device-initializing.json','device-initialized.json')),
        'used native history cannot be recovered as an empty initial layout')
    require(filesystem(ROOT/'data' if (ROOT/'data').exists() else ROOT)==record['filesystem'],
            'original incomplete filesystem changed')
    record['directories']=unused_layout(uid,gid,record['directories'],record['kind']=='selected')
    state.put(journal.name,record);sync_receipt(journal,record)
    descriptors={};flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
    try:
        descriptors['']=os.open(ROOT,flags)
        for relative in DATA_LAYOUT:
            parent,_,name=relative.rpartition('/');parent_fd=descriptors[parent]
            try:fd=os.open(name,flags,dir_fd=parent_fd)
            except FileNotFoundError:
                require(relative not in record['directories'],'original incomplete directory disappeared')
                os.mkdir(name,0o700,dir_fd=parent_fd);os.fsync(parent_fd)
                fd=os.open(name,flags,dir_fd=parent_fd)
            descriptors[relative]=fd;info=os.fstat(fd)
            require(filesystem(ROOT/'data')==record['filesystem'] and info.st_dev==os.fstat(descriptors['data']).st_dev,
                    'original incomplete filesystem changed during construction')
            if relative not in record['directories']:
                require(info.st_uid==0 and info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o700 and not os.listdir(fd),
                        'new empty directory has unexpected original ownership or payload')
                record['directories'][relative]={'inode':info.st_ino,'uid':0,'gid':0,'mode':0o700}
                state.put(journal.name,record);sync_receipt(journal,record)
            require(info.st_ino==record['directories'][relative]['inode'],'original incomplete directory was replaced')
            if info.st_uid==0:
                os.fchmod(fd,0o700);os.fchown(fd,uid,gid)
            after=os.fstat(fd)
            require(after.st_uid==uid and after.st_gid==gid and stat.S_IMODE(after.st_mode)==0o700,
                    'completed empty directory differs from original account')
            os.fsync(fd);os.fsync(parent_fd)
        unused_layout(uid,gid,record['directories'],record['kind']=='selected')
        observed=binding(ROOT/'data',os.fstat(descriptors['data']))
        upgraded=dict(expected,format=2,binding=observed,final=record['kind']=='selected')
        require(record['upgraded'] is None or record['upgraded']==upgraded,'recovered empty layout changed')
        record['upgraded']=upgraded;state.put(journal.name,record);sync_receipt(journal,record)
        require((ROOT/'stopped').exists() and state.get('operation.json').get('intent') is None,
                'empty-layout recovery was superseded')
        state.put(ready.name,upgraded)
        record['phase']='complete';state.put(journal.name,record);sync_receipt(journal,record)
        return {'filesystem_identity_upgraded':True,'stopped':True,'history_preserved':True,'empty_layout_completed':True}
    finally:
        for fd in reversed(list(descriptors.values())):os.close(fd)


def upgrade_data_identity(state,c,uid,gid,original_uuid):
    """Explicit stopped upgrade from an independently retained filesystem UUID.

    Preserve the exact prior receipt before switching the identity format. No
    native directory, byte, permission, signing history or raw-device floor is
    written for a complete layout. An interrupted unused construction can complete
    only its original empty directories. Lost acknowledgements retry the same record.
    """
    state.check(c);owned_directory(ROOT)
    require(isinstance(original_uuid,str) and re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',original_uuid)
            and any(char not in '0-' for char in original_uuid),'independently recorded original filesystem UUID is required')
    require((ROOT/'stopped').exists() and state.get('operation.json').get('intent') is None,
            'explicit durable stop is required before filesystem identity recovery')
    existing=state.get('data-ready.json') if (ROOT/'data-ready.json').exists() else None
    if ((ROOT/'data-incomplete-upgrade.json').exists() or existing is None
            or existing.get('format') is None and existing.get('final') is False and (ROOT/'data-mount-preparing.json').exists()):
        return recover_unused_layout(state,c,uid,gid,original_uuid)
    ready=ROOT/'data-ready.json';record=ROOT/'data-identity-upgrade.json'
    raw=read(ready);saved=unique_json(raw)
    retained=state.get(record.name) if record.exists() else None
    if retained is not None:
        require(isinstance(retained,dict) and set(retained)=={'format','contract','original_sha256','original_receipt','upgraded'}
                and type(retained['format'])is int and retained['format']==1 and retained['contract']==c
                and isinstance(retained['original_receipt'],str) and len(retained['original_receipt'])<=1048576,
                'original filesystem upgrade receipt is invalid')
        original=base64.b64decode(retained['original_receipt'],validate=True)
        require(digest(original)==retained['original_sha256'] and unique_json(original).get('contract')==c,
                'retained original filesystem receipt was changed')
    if saved.get('format')==2:
        require(isinstance(retained,dict) and retained.get('contract')==c and retained.get('upgraded')==saved
                and saved.get('binding',{}).get('uuid')==original_uuid,
                'completed filesystem recovery differs from its original migration')
        verify_data(state,c,uid,gid,allow_provisional=True);sync_receipt(ready,saved);sync_receipt(record,retained)
        return {'filesystem_identity_upgraded':True,'stopped':True,'history_preserved':True}
    expected={'contract':c,'uid':uid,'gid':gid,'layout':list(DATA_LAYOUT)}
    require(set(saved)==set(expected)|{'binding','final'} and type(saved['final'])is bool
            and {key:saved[key] for key in expected}==expected and isinstance(saved['binding'],dict)
            and set(saved['binding'])=={'device','inode'} and type(saved['binding']['device'])is int
            and type(saved['binding']['inode'])is int and saved['binding']['inode']>0,
            'legacy consensus receipt is not the original complete layout')
    flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC;descriptors={}
    try:
        descriptors['']=os.open(ROOT,flags)
        for relative in DATA_LAYOUT:
            parent,_,name=relative.rpartition('/')
            fd=os.open(name,flags,dir_fd=descriptors[parent]);descriptors[relative]=fd
            info=os.fstat(fd);data=os.fstat(descriptors['data'])
            require(info.st_dev==data.st_dev and info.st_uid==uid and info.st_gid==gid
                    and stat.S_IMODE(info.st_mode)==0o700,'original consensus directory authority differs during recovery')
            require(data.st_ino==saved['binding']['inode'],'original consensus inode changed; recovery cannot adopt replacement history')
        observed=binding(ROOT/'data',os.fstat(descriptors['data']))
        require(observed['uuid']==original_uuid,'supplied original UUID does not match the retained consensus filesystem')
        upgraded=dict(expected,format=2,binding=observed,final=saved['final'])
        value={'format':1,'contract':c,'original_sha256':digest(raw),
               'original_receipt':base64.b64encode(raw).decode(),'upgraded':upgraded}
        if retained is not None:require(retained==value,'incomplete filesystem recovery belongs to another original receipt or UUID')
        else:state.put(record.name,value)
        sync_receipt(record,value)
        require(read(ready)==raw and binding(ROOT/'data',os.fstat(descriptors['data']))==observed,
                'original receipt or filesystem changed before recovery publication')
        require((ROOT/'stopped').exists() and state.get('operation.json').get('intent') is None,
                'filesystem recovery was superseded')
        state.put(ready.name,upgraded)
        return {'filesystem_identity_upgraded':True,'stopped':True,'history_preserved':True}
    finally:
        for fd in reversed(list(descriptors.values())):os.close(fd)


def prepare_data(state,c,uid,gid,final=True):
    """Drain original UIDs before entry. All native writes use no-follow FDs.

    Init creates a provisional empty layout. Before the first deployment only,
    the operator may mount a clean filesystem over it. That selection is bound
    durably before changing permissions; subsequent deployments cannot replace
    its original filesystem UUID/inode or recreate missing history directories.
    """
    state.check(c)
    owned_directory(ROOT)
    expected={'format':2,'contract':c,'uid':uid,'gid':gid,'layout':list(DATA_LAYOUT)}
    ready=ROOT/'data-ready.json';intent=ROOT/'data-preparing.json'
    established=ready.exists();replacement=None
    if established:
        saved=state.get('data-ready.json')
        require(type(saved.get('format'))is int and saved['format']==2,'legacy consensus receipt lacks original filesystem UUID; reviewed recovery required')
        require(set(saved)==set(expected)|{'binding','final'} and type(saved['final'])is bool
                and {key:saved[key] for key in expected}==expected,'native data ownership receipt differs')
        current=(ROOT/'data').lstat();observed=binding(ROOT/'data',current)
        require(stat.S_ISDIR(current.st_mode),'native data root is redirected')
        if observed!=saved['binding']:
            require(final and not saved['final'] and not any((ROOT/name).exists() for name in
                    ('installed.json','bootstrap-copied','device-initializing.json','device-initialized.json')),
                    'established native filesystem changed; automatic adoption refused')
            replacement={'original':saved,'binding':observed}
            mount_intent=ROOT/'data-mount-preparing.json'
            if mount_intent.exists():require(state.get('data-mount-preparing.json')==replacement,
                                            'incomplete filesystem selection belongs to another original mount')
            else:
                require(current.st_uid==0 and stat.S_IMODE(current.st_mode) in (0o700,0o755),
                        'new consensus mount must be a protected root-owned directory')
                empty_data_volume(ROOT/'data')
                state.put('data-mount-preparing.json',replacement)
            sync_receipt(mount_intent,replacement)
            established=False
        else:sync_receipt(ready,saved)
    else:
        initial=dict(expected,filesystem=filesystem(ROOT/'data' if (ROOT/'data').exists() else ROOT))
        if intent.exists():require(state.get('data-preparing.json')==initial,'native data preparation belongs to another owner or original filesystem')
        else:
            require(not (ROOT/'data').exists() and not (ROOT/'data').is_symlink(),
                    'unreceipted native data cannot be adopted')
            state.put('data-preparing.json',initial)
        sync_receipt(intent,initial)
    descriptors={}
    flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
    try:
        descriptors['']=os.open(ROOT,flags)
        for relative in DATA_LAYOUT:
            parent,_,name=relative.rpartition('/')
            parent_fd=descriptors[parent]
            created=False
            try:fd=os.open(name,flags,dir_fd=parent_fd)
            except FileNotFoundError:
                require(not established,'established native data directory is missing; automatic recreation refused')
                os.mkdir(name,0o700,dir_fd=parent_fd)
                created=True
                fd=os.open(name,flags,dir_fd=parent_fd)
            descriptors[relative]=fd
            info=os.fstat(fd)
            require(info.st_dev==os.fstat(descriptors['data']).st_dev,'nested native data filesystem differs')
            if relative=='data':
                observed=binding(ROOT/'data',info)
                if established:require(observed==saved['binding'],'original consensus filesystem changed before preparation')
                elif replacement is None:require({key:observed[key] for key in initial['filesystem']}==initial['filesystem'],
                                               'initial consensus filesystem changed before ownership mutation')
            mount_root=replacement is not None and relative=='data'
            require(stat.S_ISDIR(info.st_mode) and (stat.S_IMODE(info.st_mode)==0o700
                    or (mount_root and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o755)),
                    'native data directory has unexpected permissions')
            if mount_root:require(binding(ROOT/'data',info)==replacement['binding'],
                                  'selected consensus filesystem changed before provisioning')
            if not established and info.st_uid==0:
                if mount_root:empty_data_volume(ROOT/'data')
                else:require(not os.listdir(fd),'unowned data cannot be adopted from interrupted preparation')
                os.fchmod(fd,0o700);os.fchown(fd,uid,gid)
            else:
                require(info.st_uid==uid and info.st_gid==gid,'native data directory differs from its original account')
            if created:os.fchmod(fd,0o700)
            if not established:
                children={entry[len(relative)+1:].split('/')[0] for entry in DATA_LAYOUT
                          if entry.startswith(relative+'/')}
                if mount_root:children.add('lost+found')
                require(set(os.listdir(fd))<=children,'incomplete native layout contains unowned payload')
            os.fsync(fd);os.fsync(parent_fd)
        data=os.fstat(descriptors['data'])
        observed=binding(ROOT/'data',data)
        if established:require(observed==saved['binding'],'original consensus filesystem changed during preparation')
        elif replacement is None:require({key:observed[key] for key in initial['filesystem']}==initial['filesystem'],
                                       'initial consensus filesystem changed during preparation')
        else:require(observed==replacement['binding'],'selected consensus filesystem changed during preparation')
        record=dict(expected,binding=observed,
                    final=final or (saved['final'] if ready.exists() else False))
        if not established or record!=saved:state.put('data-ready.json',record)
    finally:
        for fd in reversed(list(descriptors.values())):os.close(fd)


def toml_document(text):
    # The supported Ubuntu 24.04 host supplies Python 3.12. Lazy import lets
    # pure state/custody failure fixtures also execute on older development Pythons.
    import tomllib
    return tomllib.loads(text)


def fetch(url, maximum, expected=None, fresh=False):
    require(url.startswith('https://bucket.monadinfra.com/'), 'unqualified bootstrap origin')
    request = urllib.request.Request(url, headers={'User-Agent': 'erpc-node-controller'})
    with urllib.request.build_opener(package.NoRedirect).open(request, timeout=45) as response:
        require(response.status == 200 and response.geturl() == url, 'bootstrap origin changed')
        data = response.read(maximum + 1)
        require(0 < len(data) <= maximum, 'bootstrap file exceeds bounds')
        if fresh:
            stamp = email.utils.parsedate_to_datetime(response.headers.get('Last-Modified', ''))
            age = time.time() - stamp.timestamp()
            require(-300 <= age <= 86400, 'official bootstrap checkpoint is stale')
    if expected is not None:
        require(digest(data) == expected, 'official configuration changed; update the reviewed catalog')
    return data


def install_package(catalog):
    destination = RELEASES / catalog['version']
    qualified = {key: catalog[key] for key in ('version', 'consensus_commit', 'execution_commit')}
    qualified['package_sha256'] = catalog['package']['sha256']
    if (destination / 'receipt.json').exists():
        recorded = unique_json(read(destination / 'receipt.json'))
        require(recorded.get('release') == qualified, 'installed same-version source/package identity differs')
        package.check(destination, recorded)
        return
    stage = RELEASES / (catalog['version'] + '.partial')
    require(not destination.exists(), 'release directory exists without a receipt')
    if stage.exists():
        require(stage.is_dir() and not stage.is_symlink() and stage.stat().st_uid == 0,
                'unowned package staging directory')
        # Only a root-owned stage under this already-reserved host is retryable.
        shutil.rmtree(stage)
    require(shutil.disk_usage(RELEASES).free >= catalog['package']['size'] + 6_000_000_000,
            'release filesystem lacks space for the authenticated package and bounded extraction')
    # Staging stays private; extraction sets explicit reader modes on the
    # payload tree before it is published outside this directory.
    stage.mkdir(mode=0o700)
    archive = stage / 'package.deb'
    pin = catalog['package']
    package.download(pin['url'], archive, pin['sha256'], pin['size'])
    payload = stage / 'payload'
    payload.mkdir(mode=0o755)
    package.extract(archive, payload)
    atomic(payload / 'receipt.json', json_bytes(dict(package.receipt(payload), release=qualified)))
    os.rename(payload, destination)
    fsync_dir(RELEASES)
    shutil.rmtree(stage)
    fsync_dir(RELEASES)


def bootstrap(catalog, c):
    directory = ROOT / 'bootstrap'
    owned_directory(directory, True)
    marker = directory / 'receipt.json'
    profile = catalog['networks'][c['network']]
    pin = profile['config'][c['role']]
    if marker.exists():
        record = unique_json(read(marker))
        require((ROOT / 'bootstrap-copied').exists() or record['config_sha256'] == pin['sha256'],
                'interrupted bootstrap belongs to a different config')
        for name, checksum in record['files'].items():
            require(digest(read(directory / name, 2 * 1024 * 1024)) == checksum, 'cached bootstrap changed')
        return
    config = fetch(pin['url'], 65536, pin['sha256'])
    # Fetch the pair again if publication crossed an epoch boundary. No fallback
    # to guessed peers, another host, or a mixed-network checkpoint is allowed.
    for _ in range(3):
        forkpoint = fetch(profile['forkpoint_url'], 2 * 1024 * 1024, fresh=True)
        validators = fetch(profile['validators_url'], 2 * 1024 * 1024, fresh=True)
        fork = toml_document(forkpoint.decode())
        val = toml_document(validators.decode())
        epoch = fork['high_certificate']['Qc']['info']['epoch']
        available = {v['epoch'] for v in val['validator_sets']}
        if type(epoch) is int and epoch > 0 and epoch in available:
            break
    else:
        raise ValueError('official forkpoint and validator epochs differ')
    node = toml_document(config.decode())
    require(node['network_name'] == c['network'] and node['chain_id'] == profile['chain_id']
            and node['bootstrap']['peers'] and node['statesync']['init_peers'], 'configuration network or bootstrap peers differ')
    files = {'node.toml': config, 'forkpoint.toml': forkpoint, 'validators.toml': validators}
    for name, data in files.items():
        atomic(directory / name, data)
    atomic(marker, json_bytes({'config_sha256': pin['sha256'], 'epoch': epoch,
                              'files': {name: digest(data) for name, data in files.items()}}))


def admitted_keys(catalog, c):
    """Conservatively recognize either reserved key in official retained epoch sets."""
    profile = catalog['networks'][c['network']]
    data = fetch(profile['validators_url'], 2 * 1024 * 1024, fresh=True)
    parsed = toml_document(data.decode())
    sets = parsed.get('validator_sets')
    require(isinstance(sets, list) and 1 <= len(sets) <= 16, 'invalid official validator-set observation')
    found, count = False, 0
    for entry in sets:
        require(isinstance(entry, dict) and type(entry.get('epoch')) is int and entry['epoch'] >= 0,
                'invalid official epoch identity')
        validators = entry.get('validators', [])
        require(isinstance(validators, list) and len(validators) <= 200, 'oversized validator epoch set')
        count += len(validators)
        for member in validators:
            require(isinstance(member, dict) and re.fullmatch('0x[0-9a-f]{66}', member.get('node_id', ''))
                    and re.fullmatch('0x[0-9a-f]{96}', member.get('cert_pubkey', '')), 'malformed official consensus key')
            found |= member['node_id'][2:] == c['secp'] or member['cert_pubkey'][2:] == c['bls']
    require(count > 0, 'official epoch sets did not establish any membership')
    return found


def sign_name(c, original, binary, uid, gid, legacy):
    fd = os.memfd_create('erpc-monad-name-record', os.MFD_CLOEXEC)
    try:
        os.write(fd, original)
        os.lseek(fd, 0, os.SEEK_SET)
        args = [str(binary), '--keystore-path', '/proc/self/fd/' + str(fd), '--password', '',
                '--self-record-seq-num', str(c['name_record_sequence']), '--authenticated-udp-port', '8001']
        args += ['--address', c['public_ip'] + ':8000'] if legacy else [
            '--ip', c['public_ip'], '--tcp-port', '8000', '--direct-udp-port', '8002']
        result = subprocess.run(args, pass_fds=(fd,), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=dict(ENV, HOME='/nonexistent', LD_LIBRARY_PATH=str(binary.parent.parent / 'lib')),
            user=uid, group=gid, extra_groups=[], timeout=90, check=False)
        require(result.returncode == 0 and len(result.stdout) <= 8192, 'native name-record signing failed')
        record = toml_document(result.stdout.decode())
        fields = {'self_address', 'self_record_seq_num', 'self_name_record_sig', 'self_auth_port'}
        if not legacy:
            fields |= {'self_tcp_port', 'self_direct_udp_auth_port'}
        require(set(record) == fields and record['self_record_seq_num'] == c['name_record_sequence']
                and record['self_address'] == (c['public_ip'] + ':8000' if legacy else c['public_ip'])
                and record['self_auth_port'] == 8001
                and re.fullmatch('[a-f0-9]{130}', record['self_name_record_sig']), 'native name record differs')
        if not legacy:
            require(record['self_tcp_port'] == 8000 and record['self_direct_udp_auth_port'] == 8002,
                    'native peer ports differ')
        return record
    finally:
        os.close(fd)


def configure_node(catalog, c, original, uid, gid):
    bootstrap(catalog, c)
    binary = RELEASES / catalog['version'] / 'bin/monad-sign-name-record'
    profile = catalog['networks'][c['network']]
    record_file = CONFIG / 'name-record.json'
    if record_file.exists():
        record = unique_json(read(record_file))
        require(record['contract'] == c, 'retained peer record differs from immutable contract')
        record = record['record']
    else:
        record = sign_name(c, original, binary, uid, gid, profile['legacy_name_record'])
        atomic(record_file, json_bytes({'contract': c, 'record': record}))
    pin = profile['config'][c['role']]
    original_config = read(ROOT / 'bootstrap/node.toml')
    text = (original_config if digest(original_config) == pin['sha256']
            else fetch(pin['url'], 65536, pin['sha256'])).decode()
    text, count = re.subn(r'(?m)^beneficiary = .*$', 'beneficiary = ' + json.dumps(c['beneficiary']), text)
    require(count == 1, 'beneficiary field is ambiguous')
    text, count = re.subn(r'(?m)^node_name = .*$', 'node_name = ' + json.dumps('erpc-' + c['owner'][:12]), text)
    require(count == 1, 'node name field is ambiguous')
    for key, value in record.items():
        text, count = re.subn(r'(?m)^' + key + r' = .*$', key + ' = ' + json.dumps(value), text)
        require(count == 1, 'peer record field differs from the reviewed template')
    require('[metrics]' not in text, 'unexpected metrics section')
    text += '\n[metrics]\nenabled = true\nlisten_addr = "127.0.0.1:9143"\n'
    parsed = toml_document(text)
    require(parsed['fullnode_raptorcast']['enable_client'] is True and parsed['statesync']['expand_to_group'] is True,
            'public follower bootstrap is disabled')
    atomic(CONFIG / 'node.toml', text.encode(), 0o644)
    marker = ROOT / 'bootstrap-copied'
    if not marker.exists():
        # Never replace the client's newer locally persisted checkpoint.
        for kind in ('forkpoint', 'validators'):
            path = ROOT / 'data' / kind / (kind + '.toml')
            seed_data(path, read(ROOT / 'bootstrap' / (kind + '.toml'), 2 * 1024 * 1024), uid, gid)
        atomic(marker, b'complete\n')
