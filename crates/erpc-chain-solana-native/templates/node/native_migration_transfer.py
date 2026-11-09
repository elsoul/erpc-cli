# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Copy authenticated stopped original volumes into private separate staging.

No native UID receives these bytes and no runtime is installed or started here.
The original volume, key, ledger and Tower bytes remain in place throughout.
"""
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
from native_files import atomic, encoded, json_value, read, require, root_directory, sync_directory, sync_file
import native_migration_copy as copying
import native_migration_retire as retirement
import native_migration_inspect as legacy
import native_mounts as mounts

ROOT_UID=0
ROOT_GID=0
PARENT=Path('/mnt')


def stable(info):
    return {'inode':info.st_ino,'uid':info.st_uid,'gid':info.st_gid,'mode':info.st_mode&0o7777}


class Transfer:
    def __init__(self,operation):
        self.operation=operation;self.scope=operation.binding
        self.directory=retirement.STORE/'transfer'
        self.binding=hashlib.sha256(encoded(self.scope)).hexdigest()
    def get(self,name):
        value=json_value(read(self.directory/name,1048576,ROOT_UID))
        sync_file(self.directory/name,ROOT_UID);sync_directory(self.directory)
        return value
    def put(self,name,value):atomic(self.directory/name,encoded(value))
    def confirmed(self):
        observed=self.operation.saved()['observation']
        fence=self.operation.fence(observed)
        require(fence.saved()['phase']=='retired' and fence.unit()=='masked','original service has not been retired')
        require(self.operation.revoker(observed).verify()['phase']=='revoked','original runtime login is not retired')
        marker=retirement.STORE/'manager-confirmed.json'
        require(json_value(read(marker,65536,ROOT_UID))=={'binding_sha256':self.binding,'manager_uid':self.operation.manager_uid},
                'separate original manager has not reauthenticated')
        sync_file(marker,ROOT_UID);sync_directory(retirement.STORE)
        return observed
    def gate(self):
        # The outer original host lock remains held. Check the retained root
        # receipt, persistent mask and whole original UID before every copied
        # chunk/publication. Never signal an untracked process to make progress.
        observed=self.operation.saved()['observation'];fence=self.operation.fence(observed)
        require(fence.unit()=='masked','original source restart fence changed')
        require(json_value(read(retirement.STORE/'manager-confirmed.json',65536,ROOT_UID))==
                {'binding_sha256':self.binding,'manager_uid':self.operation.manager_uid},'migration confirmation was revoked')
        retirement.original_quiescent(self.scope['legacy']['historical']['uid'])
    def parent(self):
        root_directory(PARENT.parent)
        info=PARENT.lstat();old=self.scope['legacy']['historical']
        require(stat.S_ISDIR(info.st_mode) and not info.st_mode&0o022,'original data ancestor is unsafe')
        path=self.directory/'parent.json'
        if not path.exists():
            require((info.st_uid,info.st_gid) in ((ROOT_UID,ROOT_GID),(old['uid'],old['gid'])),
                    'original data ancestor has another owner')
            self.put(path.name,{'binding':self.binding,'original':stable(info)})
        record=self.get(path.name);before=record.get('original',{})
        require(set(record)=={'binding','original'} and record['binding']==self.binding and set(before)=={'inode','uid','gid','mode'}
                and before['inode']==info.st_ino and (before['uid'],before['gid']) in ((ROOT_UID,ROOT_GID),(old['uid'],old['gid']))
                and type(before['mode'])is int and not before['mode']&0o022,'original ancestor handoff receipt differs')
        current=stable(info);target=dict(before,uid=ROOT_UID,gid=ROOT_GID,mode=0o755)
        # chown and chmod are separate syscalls; each intermediate state belongs
        # to this already durable original inode reservation, not to a new path.
        require(current['inode']==before['inode'] and (current['uid'],current['gid']) in
                ((before['uid'],before['gid']),(ROOT_UID,ROOT_GID)) and current['mode'] in (before['mode'],0o755),
                'original ancestor changed during handoff')
        fd=os.open(PARENT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            require(stable(os.fstat(fd))==current,'original ancestor changed while opening')
            self.gate();os.fchown(fd,ROOT_UID,ROOT_GID);os.fchmod(fd,0o755);os.fsync(fd)
            require(stable(os.fstat(fd))==target,'original ancestor handoff did not persist')
        finally:os.close(fd)
        sync_directory(PARENT.parent);root_directory(PARENT)
    def target_observations(self,original):
        observed=mounts.inspect_volumes(self.scope['contract']['volumes'])
        result={}
        for kind,entry in observed.items():
            path=mounts.MOUNTS[kind];root_directory(path);info=path.lstat()
            expected=original['copy_preflight']['targets'][kind]
            require(info.st_ino==expected['inode'] and entry['uuid']==expected['uuid'] and entry['fs']==expected['fs'],
                    'original copy target filesystem or root inode changed')
            result[kind]={'uuid':entry['uuid'],'inode':info.st_ino,'fs':entry['fs']}
        return result
    def staging(self,kind,volume):
        mount=mounts.MOUNTS[kind];stage=mount/('.erpc-migration-'+self.scope['intent']);path=self.directory/(kind+'.json')
        expected={'binding':self.binding,'kind':kind,'volume':volume}
        if not path.exists():
            names=list(mount.iterdir())
            for entry in names:
                info=entry.lstat()
                require(entry.name=='lost+found' and stat.S_ISDIR(info.st_mode) and info.st_uid==ROOT_UID
                        and not info.st_mode&0o022 and info.st_dev==mount.lstat().st_dev and not any(entry.iterdir()),
                        'copy target contains unowned data or staging')
            self.put(path.name,dict(expected,stage=None,children={}))
        record=self.get(path.name)
        require(set(record)=={*expected,'stage','children'} and all(record.get(key)==value for key,value in expected.items())
                and isinstance(record['children'],dict) and set(record['children'])<={'payload','scratch','journal'},
                'copy staging belongs to another original volume')
        if not stage.exists():
            require(record['stage'] is None and not record['children'],'original copy staging disappeared')
            self.gate();stage.mkdir(mode=0o700)
        root_directory(stage);info=stage.lstat()
        require(info.st_mode&0o7777==0o700 and (record['stage'] is None or info.st_ino==record['stage'])
                and (record['stage'] is not None or not any(stage.iterdir())),'original private staging was replaced')
        sync_directory(stage);sync_directory(mount)
        if record['stage'] is None:
            record['stage']=info.st_ino;self.put(path.name,record);record=self.get(path.name)
        require(all(entry.name in ('payload','scratch','journal') for entry in stage.iterdir()),'private copy staging contains unknown entries')
        for name in ('payload','scratch','journal'):
            child=stage/name
            if not child.exists():
                require(name not in record['children'],'original private copy root disappeared')
                self.gate();child.mkdir(mode=0o700)
            root_directory(child);child_info=child.lstat()
            require(child_info.st_mode&0o7777==0o700 and child_info.st_dev==info.st_dev
                    and (child_info.st_ino==record['children'][name] if name in record['children'] else not any(child.iterdir())),
                    'original private copy root was replaced or already used')
            sync_directory(child);sync_directory(stage)
            if name not in record['children']:
                record['children'][name]=child_info.st_ino;self.put(path.name,record);record=self.get(path.name)
        return stage,record
    def capacity(self,kind,stage):
        source=legacy.ROOT/legacy.DATA_PATHS[kind].lstrip('/')
        original=self.operation.run(['/usr/bin/du','-sx','--apparent-size','--block-size=1','--count-links',str(source)])
        allocation=self.operation.run(['/usr/bin/du','--one-file-system','--summarize','--block-size=1','--',str(stage)])
        def size(raw,path):
            words=raw.strip().split(maxsplit=1)
            require(len(words)==2 and re.fullmatch('[0-9]{1,20}',words[0]) and words[1]==str(path),'migration volume capacity is unavailable')
            return int(words[0])
        required=size(original,source)+legacy.COPY_HEADROOM;allocated=size(allocation,stage)
        usage=shutil.disk_usage(mounts.MOUNTS[kind])
        require(usage.free>=legacy.COPY_HEADROOM and usage.free+allocated>=required,'copy target lacks original payload and operating reserve')
    def copy(self):
        original=self.confirmed();root_directory(self.directory,create=True,mode=0o700)
        require(self.directory.lstat().st_mode&0o7777==0o700,'migration transfer journal is not private')
        for path in self.directory.iterdir():
            require(path.name in ('parent.json','accounts.json','ledger.json','snapshots.json','complete.json')
                    or re.fullmatch(r'\.erpc-[a-f0-9]{32}',path.name),'unknown migration transfer state')
            read(path,1048576,ROOT_UID)
        self.parent();volumes=self.target_observations(original);result={}
        for kind in ('accounts','ledger','snapshots'):
            stage,record=self.staging(kind,volumes[kind]);self.capacity(kind,stage)
            old=original['storage'][kind];identity=self.scope['legacy']['historical']
            binding={'intent':self.scope['intent'],'source_uuid':old['uuid'],'source_inode':old['inode'],
                'source_uid':identity['uid'],'source_gid':identity['gid'],'target_uuid':volumes[kind]['uuid'],
                'payload_inode':record['children']['payload'],'scratch_inode':record['children']['scratch'],
                'history_sha256':hashlib.sha256(encoded(self.scope['legacy']['source_history'])).hexdigest()}
            copier=copying.Copy(legacy.ROOT/legacy.DATA_PATHS[kind].lstrip('/'),stage/'payload',stage/'scratch',stage/'journal',binding,self.gate)
            result[kind]=copier.run()
            require(self.target_observations(original)==volumes,'copy target volume authority changed')
        self.confirmed();self.gate()
        complete={'binding':self.binding,'volumes':volumes,'results':result}
        path=self.directory/'complete.json'
        if path.exists():require(self.get(path.name)==complete,'completed copy receipt differs')
        else:self.put(path.name,complete)
        self.get(path.name)
        return {'copied':True,'source_retained':True,'runtime_started':False,'native_data_promoted':False}
