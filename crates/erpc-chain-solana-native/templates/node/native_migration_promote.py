# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Promote only verified copied inodes; leave ordinary native startup fenced.

Original source volumes are read-only inputs. Private copied payload ownership
moves to newly reserved native accounts, retaining original bytes, timestamps,
Tower files and the independently supplied highest-used source/compiler floor.
The migration marker remains preparing until custody and inventory cutover are
separately completed. This module does not start a node or generate any key.
"""
import hashlib
import os
from pathlib import Path
import re
import stat
from native_files import atomic, encoded, json_value, read, require, root_directory, sync_directory, sync_file
from native_state import State
import native_accounts as accounts
import native_host as host
import native_migration_copy as copying
import native_migration_transfer as transfer
import native_source_floor as floor
import native_migration_settings as settings
import native_process as process

ROOT_UID=0
ROOT_GID=0
FLAGS=os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC


class Tree:
    def __init__(self,copier,node,gate):
        self.copier,self.node,self.gate=copier,node,gate;self.count=0
    def receipt(self,parts):
        key=hashlib.sha256(encoded(list(parts))).hexdigest()
        path=self.copier.journal/('entries-'+key[:2])/(key+'.json')
        root_directory(path.parent);value=json_value(read(path,1048576,ROOT_UID))
        require(value.get('schema')==1 and value.get('phase')=='complete' and value.get('parts')==list(parts),
                'copied entry has no original completed receipt')
        sync_file(path,ROOT_UID);sync_directory(path.parent)
        return value
    def target(self,info,receipt,directory,device):
        require(info.st_dev==device and info.st_ino==receipt['inode']
                and (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink==1)
                and info.st_mode&0o7777==(0o700 if directory else 0o600)
                and (info.st_uid,info.st_gid) in ((ROOT_UID,ROOT_GID),(self.node['uid'],self.node['gid'])),
                'copied inode, permissions or original recipient changed')
    def checksum(self,fd,size):
        require(type(size)is int and size>=0,'copied content size is invalid')
        digest=hashlib.sha256();count=0;os.lseek(fd,0,os.SEEK_SET)
        while True:
            self.gate();part=os.read(fd,copying.CHUNK)
            if not part:break
            count+=len(part);require(count<=size,'copied content grew during handoff');digest.update(part)
        require(count==size,'copied content is incomplete');return digest.hexdigest()
    def handoff(self,fd,mtime):
        self.gate();os.fchown(fd,self.node['uid'],self.node['gid'])
        os.utime(fd,ns=(mtime,mtime));os.fsync(fd)
    def file(self,parts,source_parent,target_parent,source_device,target_device):
        receipt=self.receipt(parts)
        require(set(receipt)=={'schema','parts','kind','original','phase','inode','sha256'} and receipt['kind']=='file'
                and isinstance(receipt['sha256'],str) and re.fullmatch('[a-f0-9]{64}',receipt['sha256']),
                'original copied file receipt differs')
        source=os.open(parts[-1],FLAGS,dir_fd=source_parent)
        try:
            original=self.copier.source_info(os.fstat(source),source_device)
            require(original==receipt['original'],'original source file changed before handoff')
            target=os.open(parts[-1],FLAGS,dir_fd=target_parent)
            try:
                before=os.fstat(target);self.target(before,receipt,False,target_device)
                require(before.st_size==original['size'] and self.checksum(source,original['size'])==receipt['sha256']
                        and self.checksum(target,original['size'])==receipt['sha256'],'original or copied file bytes changed')
                self.target(os.fstat(target),receipt,False,target_device)
                require(copying.fingerprint(os.fstat(source))==original,'original source changed during handoff')
                self.handoff(target,original['mtime_ns']);self.target(os.fstat(target),receipt,False,target_device)
                os.fsync(target_parent)
                return {'sha256':receipt['sha256'],'bytes':original['size']}
            finally:os.close(target)
        finally:os.close(source)
    def directory(self,parts,source,target,source_device,target_device):
        require(len(parts)<=copying.MAX_DEPTH,'original handoff tree exceeds its depth bound');self.gate()
        receipt=self.receipt(parts)
        require(set(receipt)=={'schema','parts','kind','original','listing_sha256','inode','phase','tree_sha256'}
                and receipt['kind']=='directory','original copied directory receipt differs')
        original=self.copier.source_info(os.fstat(source),source_device);self.target(os.fstat(target),receipt,True,target_device)
        names,listing=self.copier.listing(source,parts)
        require(original==receipt['original'] and listing==receipt['listing_sha256'] and sorted(os.listdir(target))==names,
                'original or copied directory entries changed before handoff')
        self.count+=len(names);require(self.count<=copying.MAX_ENTRIES,'original handoff exceeds its entry bound')
        checksum=hashlib.sha256();total=0
        for name in names:
            self.gate();info=copying.at(source,name);self.copier.source_info(info,source_device)
            if stat.S_ISDIR(info.st_mode):
                left=os.open(name,FLAGS|os.O_DIRECTORY,dir_fd=source)
                try:
                    right=os.open(name,FLAGS|os.O_DIRECTORY,dir_fd=target)
                    try:result=self.directory((*parts,name),left,right,source_device,target_device)
                    finally:os.close(right)
                finally:os.close(left)
            else:result=self.file((*parts,name),source,target,source_device,target_device)
            checksum.update(encoded([name,result['sha256']]));total+=result['bytes']
        require(checksum.hexdigest()==receipt['tree_sha256'] and copying.fingerprint(os.fstat(source))==original
                and self.copier.listing(source,parts)[1]==listing and sorted(os.listdir(target))==names,
                'original copied tree checksum changed during handoff')
        self.handoff(target,original['mtime_ns']);self.target(os.fstat(target),receipt,True,target_device)
        return {'sha256':checksum.hexdigest(),'bytes':total}
    def run(self):
        source=copying.root_fd(self.copier.source,self.copier.binding['source_uid'])
        try:
            # Payload may already carry the original new UID after a partial
            # handoff. Every ancestor remains root-owned and non-writable.
            root_directory(self.copier.payload.parent)
            target=os.open(self.copier.payload,FLAGS|os.O_DIRECTORY)
            try:
                require(os.fstat(source).st_ino==self.copier.binding['source_inode']
                        and os.fstat(target).st_ino==self.copier.binding['payload_inode'],'original handoff root was replaced')
                result=self.directory((),source,target,os.fstat(source).st_dev,os.fstat(target).st_dev)
                self.gate();return dict(result,entries=self.count,source_retained=True,runtime_started=False)
            finally:os.close(target)
        finally:os.close(source)


class Promotion:
    def __init__(self,operation):
        self.operation=operation;self.copy=transfer.Transfer(operation);self.scope=operation.binding
        self.contract=self.scope['contract'];self.owner={'intent':self.scope['intent'],'source_sha256':self.scope['legacy']['source_sha256']}
        self.state=State(host.STATE,self.owner)
    def preparation(self):
        original=self.copy.confirmed();complete=self.copy.get('complete.json')
        require(set(complete)=={'binding','volumes','results'} and complete['binding']==self.copy.binding
                and set(complete['results'])==set(transfer.mounts.MOUNTS)
                and self.copy.target_observations(original)==complete['volumes'],'original completed copy belongs to another target')
        root_directory(host.HOME.parent)
        if not (host.STATE/'migration.json').exists():
            for path in (host.HOME,*[Path(home) for role,(_,home) in accounts.SPECS.items() if role!='node']):
                if path.exists() or path.is_symlink():
                    root_directory(path);entries=list(path.iterdir())
                    if path==host.HOME and entries==[host.STATE]:
                        root_directory(host.STATE)
                        for pending in host.STATE.iterdir():
                            require(re.fullmatch(r'\.erpc-[a-f0-9]{32}',pending.name),'native lifecycle already has unowned state')
                            # A killed atomic writer may leave unpublished bytes;
                            # retain them as inert data, never as authorization.
                            read(pending,1048576,ROOT_UID)
                    else:require(not entries,'migration cannot adopt another native home')
            root_directory(host.HOME,create=True,mode=0o755)
            require(host.HOME.lstat().st_mode&0o005==0o005,'native home is not traversable')
            root_directory(host.STATE,create=True,mode=0o700)
            self.state.put('migration.json',{'contract':self.contract,'scope':self.owner,'phase':'preparing'})
        root_directory(host.HOME);root_directory(host.STATE)
        require(host.HOME.lstat().st_mode&0o005==0o005 and host.STATE.lstat().st_mode&0o7777==0o700,'native migration namespaces changed')
        require(self.state.get('migration.json')=={'contract':self.contract,'scope':self.owner,'phase':'preparing'},
                'completed migration cannot repeat an original data handoff')
        self.state.reserve(self.contract);plan=accounts.ensure(self.state,self.contract)
        self.gate(plan['node']);return original,complete,plan
    def gate(self,node):
        self.copy.gate();self.state.owner(self.contract)
        require(accounts.verify(self.state,self.contract)['node']==node,'new native account reservation changed')
        process.assert_quiescent(node['uid'])
    def volume(self,kind,original,complete,node):
        record=self.copy.get(kind+'.json');mount=transfer.mounts.MOUNTS[kind]
        require(record['binding']==self.copy.binding and record['volume']==complete['volumes'][kind],
                'original target staging ownership differs')
        stage=mount/('.erpc-migration-'+self.scope['intent']);root_directory(stage)
        require(stage.lstat().st_ino==record['stage'],'original target stage was replaced')
        expected={'binding':self.copy.binding,'volume':record['volume'],'payload_inode':record['children']['payload'],
                  'account':{key:node[key] for key in ('uid','gid')},'source':original['storage'][kind],
                  'copy':complete['results'][kind]}
        name='promote-'+kind+'.json';path=self.copy.directory/name
        if path.exists():require(self.copy.get(name)==expected,'original data handoff reservation differs')
        else:
            require(not (mount/'data').exists() and not (mount/'data').is_symlink(),'unowned native data cannot be replaced')
            self.copy.put(name,expected)
        self.copy.get(name);self.gate(node)
        payload=stage/'payload';final=mount/'data'
        if not payload.exists():
            require(not payload.is_symlink() and final.exists(),'original copied payload disappeared');payload=final
        else:require(not final.exists() and not final.is_symlink(),'two native payload roots cannot be adopted')
        old=self.scope['legacy']['historical']
        binding={'intent':self.scope['intent'],'source_uuid':original['storage'][kind]['uuid'],
            'source_inode':original['storage'][kind]['inode'],'source_uid':old['uid'],'source_gid':old['gid'],
            'target_uuid':record['volume']['uuid'],'payload_inode':record['children']['payload'],
            'scratch_inode':record['children']['scratch'],'history_sha256':hashlib.sha256(encoded(self.scope['legacy']['source_history'])).hexdigest()}
        copier=copying.Copy(transfer.legacy.ROOT/transfer.legacy.DATA_PATHS[kind].lstrip('/'),payload,stage/'scratch',stage/'journal',binding,lambda:self.gate(node))
        require(not any((stage/'scratch').iterdir()),'copy still has unpublished file content')
        result=Tree(copier,node,lambda:self.gate(node)).run()
        require(result==complete['results'][kind],'promoted tree differs from the original complete copy')
        self.gate(node)
        root_directory(mount);fd=os.open(mount,FLAGS|os.O_DIRECTORY)
        try:
            require(os.fstat(fd).st_ino==record['volume']['inode'],'original target mount root changed')
            os.fchmod(fd,0o755);os.fsync(fd)
        finally:os.close(fd)
        if payload!=final:
            # Both parents are root-owned and the host-operation lock is held;
            # no native user can create a competing data directory here.
            require(not final.exists() and not final.is_symlink(),'native data appeared during copied-inode publication')
            os.rename(payload,final)
        require(final.lstat().st_ino==record['children']['payload'],'promoted copied inode changed')
        sync_directory(final);sync_directory(stage);sync_directory(mount)
        require(self.copy.target_observations(original)==complete['volumes'],'original target volume changed during publication')
    def prepare_data(self):
        original,complete,plan=self.preparation();node=plan['node']
        settings.record(self.state,self.contract,self.owner,original['startup'])
        for kind in ('accounts','ledger','snapshots'):self.volume(kind,original,complete,node)
        self.gate(node);expected={'contract':self.contract,'uid':node['uid'],'gid':node['gid']}
        path=self.state.directory/'data.json'
        if path.exists():require(self.state.get(path.name)==expected,'native data ownership receipt differs')
        else:self.state.put(path.name,expected)
        sync_file(path,ROOT_UID);sync_directory(self.state.directory)
        # This floor binds the actual copied inodes, never temporary empty data.
        historical=self.scope['legacy']['artifact_evidence']['source']
        floor.compatible(historical,self.scope['legacy']['source_history']['highest'])
        floor.initialize(self.state,self.contract,historical)
        require(floor.highest(floor.records(self.state,self.contract))==floor.source(historical),'original copied source history was not retained')
        self.gate(node)
        return {'native_data_promoted':True,'original_source_retained':True,'runtime_started':False,
                'migration_complete':False,'custody_and_inventory_cutover_required':True}
