# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Recorded migration progress without installed helper code or write authority."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import sys

STORE=Path('/var/lib/erpc-solana-migration')
STATE=Path('/var/lib/erpc-solana/state')
ROOT_UID=0


def require(condition,message):
    if not condition:raise ValueError(message)


def unique(raw):
    def pairs(rows):
        result={}
        for name,value in rows:
            require(name not in result,'duplicate original progress field');result[name]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs)


def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def read(path,maximum=1048576):
    for parent in reversed(path.parents):
        info=parent.lstat();require(stat.S_ISDIR(info.st_mode) and info.st_uid==ROOT_UID and not info.st_mode&0o022,'untrusted original progress directory')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        info=os.fstat(fd);require(stat.S_ISREG(info.st_mode) and info.st_uid==ROOT_UID and info.st_nlink==1
            and not info.st_mode&0o022 and info.st_size<=maximum,'untrusted original progress record')
        raw=bytearray()
        while len(raw)<=maximum:
            chunk=os.read(fd,maximum+1-len(raw))
            if not chunk:break
            raw.extend(chunk)
        require(len(raw)<=maximum,'original progress record exceeds its bound');return bytes(raw)
    finally:os.close(fd)


def present(path):
    try:info=path.lstat()
    except FileNotFoundError:return False
    require(not stat.S_ISLNK(info.st_mode),'original progress cannot follow a symlink')
    return True


def directory(path):
    for item in [*reversed(path.parents),path]:
        try:info=item.lstat()
        except FileNotFoundError:return
        require(stat.S_ISDIR(info.st_mode) and info.st_uid==ROOT_UID and not info.st_mode&0o022,
                'untrusted original progress directory')


def progress(binding,manager,store=STORE,state=STATE,reader=read,namespace=directory):
    require(isinstance(binding,dict) and set(binding)=={'intent','contract','legacy','ssh_port'},'invalid original progress scope')
    namespace(store);namespace(state)
    contract=binding['contract'];original=binding['legacy'];scope={'intent':binding['intent'],'source_sha256':original['source_sha256']}
    digest=hashlib.sha256(encoded(binding)).hexdigest()
    result={'intent':binding['intent'],'migration_reserved':False,'recorded_phase':'unreserved','helper_revision':None,
        'copy_recorded_complete':False,'data_recorded_promoted':False,'migration_complete':False,'runtime_inspected':False,'ready':None,'cutover':None}
    if not present(store/'original.json'):
        require(not any(present(state/name) for name in ('owner.json','migration.json','migration-cutover.json','migration-complete.json')), 'original migration owner is missing')
        if present(store):
            for path in store.iterdir():
                require(re.fullmatch(r'\.erpc-[a-f0-9]{32}',path.name),'unowned original migration state exists');reader(path)
        return result
    saved=unique(reader(store/'original.json'))
    require(set(saved)=={'schema','binding','observation','manager_uid'} and type(saved['schema'])is int and saved['schema']==1
            and saved['binding']==binding and saved['manager_uid']==manager,'original progress belongs to another owner or manager')
    result['migration_reserved']=True;result['recorded_phase']='reserved'
    if present(store/'helper-revision.json'):
        helper=unique(reader(store/'helper-revision.json'))
        require(set(helper)=={'binding_sha256','revision'} and helper['binding_sha256']==digest
                and isinstance(helper['revision'],str) and re.fullmatch('[a-f0-9]{64}',helper['revision']),'original helper receipt differs')
        result['helper_revision']=helper['revision']
    if present(store/'retirement/retirement.json'):
        value=unique(reader(store/'retirement/retirement.json'));observed=saved['observation'];old=original['historical']
        expected={'intent':binding['intent'],'source_sha256':original['source_sha256'],'machine_id_sha256':old['machine_id_sha256'],
            'uid':old['uid'],'gid':old['gid'],'unit_sha256':observed['unit_sha256'],
            'commands_sha256':observed['service']['commands_sha256'],'execution_policy_sha256':observed['service']['execution_policy_sha256']}
        require(set(value)=={'schema','binding','phase'} and value['schema']==1 and value['binding']==expected
                and value['phase'] in ('reserved','masked','retired'),'original retirement progress differs')
        result['recorded_phase']=value['phase']
    if present(store/'transfer/complete.json'):
        value=unique(reader(store/'transfer/complete.json'))
        require(set(value)=={'binding','volumes','results'} and value['binding']==digest
                and set(value['volumes'])==set(value['results'])=={'accounts','ledger','snapshots'},'original copy completion differs')
        result['copy_recorded_complete']=True;result['recorded_phase']='copied'
    marker=state/'migration.json'
    if present(marker):
        value=unique(reader(marker))
        require(value in ({'contract':contract,'scope':scope,'phase':'preparing'},{'contract':contract,'scope':scope,'phase':'complete'}), 'original native marker differs')
        result['recorded_phase']='promoting' if value['phase']=='preparing' else 'complete';result['migration_complete']=value['phase']=='complete'
    if present(state/'data.json'):
        value=unique(reader(state/'data.json'))
        require(set(value)=={'contract','uid','gid'} and value['contract']==contract
                and all(type(value[key])is int and value[key]>0 for key in ('uid','gid')),'original copied data receipt differs')
        result['data_recorded_promoted']=True
    for name,phase in [('migration-cutover.json','prepared'),('migration-complete.json','complete')]:
        if not present(state/name):continue
        value=unique(reader(state/name));fields={'contract','scope','receipt'}|({'provider_version'} if phase=='complete' else set())
        require(set(value)==fields and value['contract']==contract and value['scope']==scope,'original cutover progress differs')
        receipt=value['receipt'];expected_fields={'schema','intent','inventory_id','reserved_version','source_sha256','contract_sha256','config_sha256','custody_sha256'}
        require(isinstance(receipt,dict) and set(receipt)==expected_fields and type(receipt['schema'])is int and receipt['schema']==1
                and receipt['intent']==scope['intent'] and receipt['source_sha256']==scope['source_sha256']
                and receipt['inventory_id']==contract['inventory_id'] and type(receipt['reserved_version'])is int and 0<receipt['reserved_version']<2**64
                and receipt['contract_sha256']==hashlib.sha256(encoded(contract)).hexdigest()
                and all(isinstance(receipt[key],str) and re.fullmatch('[a-f0-9]{64}',receipt[key]) for key in ('source_sha256','contract_sha256','config_sha256','custody_sha256')),
                'original cutover receipt differs')
        version=value.get('provider_version')
        require(phase!='complete' or type(version)is int and receipt['reserved_version']<version<2**64,'original provider completion version differs')
        result['cutover']={'phase':phase,'receipt':receipt,'provider_version':version}
    if result['cutover'] is not None and result['cutover']['phase']=='complete' and not result['migration_complete']:result['recorded_phase']='finalizing'
    if result['migration_complete']:
        require(result['cutover'] is not None and result['cutover']['phase']=='complete','original completion acknowledgment is missing')
        owner=unique(reader(state/'owner.json'))
        require(set(owner)=={'contract','initial_halt','initialized','migration'} and owner['contract']==contract
                and owner['migration']==scope and owner['initialized'] is True,'original native owner is missing')
    return result


def main():
    require(os.geteuid()==0,'original progress requires root observation')
    raw=sys.stdin.buffer.read(65537);require(len(raw)<=65536,'original progress request exceeds its bound')
    request=unique(raw);require(isinstance(request,dict) and set(request)=={'action','intent','contract','legacy','ssh_port'}
                              and request['action']=='migration-status','read-only original status required')
    user=request['legacy']['management_user'];account=pwd.getpwnam(user)
    require(account.pw_uid>0 and user not in ('root','solv') and os.environ.get('SUDO_USER')==user
            and os.environ.get('SUDO_UID')==str(account.pw_uid),'original separate manager is required')
    print(json.dumps(progress({k:v for k,v in request.items() if k!='action'},account.pw_uid),separators=(',',':')))


if __name__=='__main__':
    try:main()
    except Exception:
        print('Original migration progress could not be verified',file=sys.stderr);raise SystemExit(1)
