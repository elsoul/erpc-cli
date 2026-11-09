#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Host-bound core-cell custody; imported only from a protected helper revision.

No account is funded or unlocked. The BLS derivation matches the pinned native
blst KeyGen API, independently checked against the existing Rust blst library.
"""
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat

SECP_ORDER=int('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',16)
BLS_ORDER=int('73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001',16)
MACHINE_ID=Path('/etc/machine-id')


def derive_bls(ikm):
    if len(ikm)!=32:raise ValueError('invalid Kaia key material length')
    salt=b'BLS-SIG-KEYGEN-SALT-';scalar=0
    while scalar==0:
        salt=hashlib.sha256(salt).digest()
        prk=hmac.new(salt,ikm+b'\0',hashlib.sha256).digest()
        first=hmac.new(prk,b'\0\x30\x01',hashlib.sha256).digest()
        second=hmac.new(prk,first+b'\0\x30\x02',hashlib.sha256).digest()
        scalar=int.from_bytes((first+second)[:48],'big')%BLS_ORDER
    return scalar.to_bytes(32,'big')


def binding(c,state):
    raw=MACHINE_ID.read_bytes().strip()
    c.require(re.fullmatch(b'[a-f0-9]{32}',raw),'stable host identity is unavailable')
    return hashlib.sha256(raw+b'\0'+state['owner'].encode()+b'\0'+state['network'].encode()+b'\0'+state['node_kind'].encode()).hexdigest()


def paths(c):
    directory=c.ROOT/'identity'
    c.require(not directory.is_symlink(),'unsafe Kaia custody directory')
    if directory.exists():
        info=directory.stat()
        c.require(directory.is_dir() and info.st_uid==c.ROOT_UID and info.st_mode&0o077==0,'Kaia custody directory must remain private')
    return directory,directory/'corecell.cred',directory/'corecell.pending'


def private_file(c,path):
    c.require(not path.is_symlink() and path.is_file(),'Kaia custody file is missing or unsafe')
    info=path.stat()
    c.require(info.st_uid==c.ROOT_UID and info.st_mode&0o077==0 and info.st_nlink==1 and 0<info.st_size<=32768,
              'Kaia custody file permissions or length differ')


def sync(directory):
    fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:os.fsync(fd)
    finally:os.close(fd)


def sync_private(c,path):
    private_file(c,path)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        c.require(stat.S_ISREG(info.st_mode) and info.st_uid==c.ROOT_UID and info.st_nlink==1 and info.st_mode&0o077==0,
                  'Kaia custody descriptor authority changed')
        os.fsync(fd)
    finally:os.close(fd)


def sync_owner(c,state):
    path=c.ROOT/'owner.json';c.protected_file(path,private=True,missing=False)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        c.require(stat.S_ISREG(info.st_mode) and info.st_uid==c.ROOT_UID and info.st_nlink==1 and info.st_mode&0o077==0,
                  'Kaia ownership descriptor authority changed')
        raw=stream.read(65537)
        c.require(len(raw)<=65536,'Kaia custody owner receipt exceeds its bound')
        saved=json.loads(raw)
        # Runtime preflight deliberately checks a candidate lifecycle/config
        # before publishing it. Custody and original account authority may not
        # differ, even when phase/target/startup fields are such a candidate.
        fields=('owner','network','role','node_kind','service_uid','service_gid',
                'custody_digest','custody_cipher','custody_public','backup_confirmed')
        c.require(isinstance(saved,dict) and all(saved.get(key)==state.get(key) for key in fields),
                  'Kaia custody owner receipt changed')
        named=path.lstat()
        c.require((named.st_dev,named.st_ino)==(info.st_dev,info.st_ino),'Kaia custody owner receipt was replaced')
        os.fsync(stream.fileno())
    for directory in (c.ROOT,*c.ROOT.parents):
        c.protected_directory(directory);sync(directory)
        if directory==c.TRUST_ANCHOR:break


def decode(c,state,path):
    private_file(c,path)
    raw=c.run(['systemd-creds','decrypt','--name=kaia-corecell',str(path),'-'])
    c.require(0<len(raw)<=16384,'concealed Kaia custody payload exceeds its bound')
    return decode_payload(c,state,raw)


def decode_payload(c,state,raw):
    c.require(isinstance(raw,bytes) and 0<len(raw)<=16384,'concealed Kaia custody payload exceeds its bound')
    try:value=json.loads(raw)
    except Exception:raise c.Refused('invalid concealed Kaia custody payload') from None
    c.require(isinstance(value,dict) and set(value)=={'schema','owner','network','node_kind','binding','nodekey','bls_nodekey'},'unsupported Kaia custody format')
    c.require(type(value['schema'])is int and value['schema']==1 and
              all(value[key]==state[key] for key in ('owner','network','node_kind')) and value['binding']==binding(c,state),
              'Kaia custody belongs to a different owner, host, network or kind')
    c.require(all(isinstance(value[key],str) and re.fullmatch('[a-f0-9]{64}',value[key]) for key in ('nodekey','bls_nodekey')),
              'invalid Kaia custody scalar encoding')
    c.require(0<int(value['nodekey'],16)<SECP_ORDER and
              derive_bls(bytes.fromhex(value['nodekey'])).hex()==value['bls_nodekey'],
              'Kaia BLS identity differs from its original consensus identity')
    return raw,value


def create(c,state):
    c.require(state.get('role')=='validator' and state.get('node_kind') in ('cn','pn'),'core-cell custody requires its dedicated role')
    directory,path,pending=paths(c)
    if 'custody_digest' not in state:
        c.require(state['phase']=='prepared' and not state.get('custody_public'),'custody creation is only allowed for a fresh reserved owner')
        c.require(not path.exists(),'unreceipted published custody cannot be adopted')
        if not state.get('custody_creating'):
            c.require(not directory.exists(),'unowned custody staging cannot be adopted')
            state['custody_creating']=True;c.save(state)
        directory.mkdir(mode=0o700,exist_ok=True)
        sync(c.ROOT)
        if not pending.exists():
            scalar=0
            while not 0<scalar<SECP_ORDER:scalar=int.from_bytes(secrets.token_bytes(32),'big')
            node=scalar.to_bytes(32,'big')
            value={'schema':1,'owner':state['owner'],'network':state['network'],'node_kind':state['node_kind'],
                   'binding':binding(c,state),'nodekey':node.hex(),'bls_nodekey':derive_bls(node).hex()}
            raw=json.dumps(value,separators=(',',':'),sort_keys=True).encode()
            c.run(['systemd-creds','encrypt','--with-key=host','--name=kaia-corecell','-',str(pending)],input=raw)
            private_file(c,pending)
            with pending.open('rb')as stream:os.fsync(stream.fileno())
            sync(directory)
        raw,_=decode(c,state,pending)
        state.update(custody_digest=hashlib.sha256(raw).hexdigest(),custody_cipher=hashlib.sha256(pending.read_bytes()).hexdigest())
        c.save(state)
    # A visible receipt after a failed rename/directory sync is not durable
    # authority. Every retry re-establishes it before publication or export.
    if pending.exists():sync_private(c,pending);sync(directory)
    sync_owner(c,state)
    if not path.exists() and pending.exists():
        private_file(c,pending)
        c.require(hashlib.sha256(pending.read_bytes()).hexdigest()==state['custody_cipher'],'pending Kaia custody differs from its receipt')
        os.replace(pending,path);sync(directory)
    raw,_=read(c,state)
    return raw


def read(c,state):
    directory,path,_=paths(c);private_file(c,path)
    sync_owner(c,state);sync_private(c,path);sync(directory)
    c.require(hashlib.sha256(path.read_bytes()).hexdigest()==state.get('custody_cipher'),'established Kaia custody is missing or changed')
    raw,value=decode(c,state,path)
    c.require(hashlib.sha256(raw).hexdigest()==state.get('custody_digest'),'concealed Kaia custody differs from its original receipt')
    return raw,value


def acknowledge(c,state,request):
    read(c,state)
    c.require(request.get('backup_digest')==state['custody_digest'],'concealed backup read-back differs')
    public=request.get('public')
    formats={'address':'0x[a-f0-9]{40}','peer_key':'[a-f0-9]{128}','bls_key':'[a-f0-9]{96}','bls_pop':'[a-f0-9]{192}'}
    c.require(isinstance(public,dict) and set(public)==set(formats) and
              all(isinstance(public[key],str) and re.fullmatch(pattern,public[key]) for key,pattern in formats.items()),
              'invalid independently verified Kaia public identity')
    c.require(not state.get('custody_public') or state['custody_public']==public,'established Kaia public identity cannot change')
    state.update(custody_public=public,backup_confirmed=True);state.pop('custody_creating',None);c.save(state)
    return {'backup_confirmed':True,'public':public}


def restore(c,state,raw):
    """Restore the exact original backup on its original stopped host only.

    The immutable plaintext receipt, host binding and independent public
    acknowledgment remain required. This never adopts another owner's key or
    changes the original identity, even when ciphertext must be regenerated.
    """
    c.require(state.get('phase') in ('prepared','installing','installed','retired') and state.get('startup_revoked') is True and state.get('backup_confirmed') is True
              and isinstance(state.get('custody_public'),dict),'stop the original owner before custody recovery')
    decode_payload(c,state,raw)
    c.require(hashlib.sha256(raw).hexdigest()==state.get('custody_digest'),'backup differs from the original custody receipt')
    directory,path,_=paths(c)
    c.require(directory.exists(),'original custody directory is unavailable')
    if path.exists():
        read(c,state)
        return {'restored':False,'identity_preserved':True}
    staged=directory/'corecell.recovery'
    c.require(not staged.is_symlink(),'unsafe recovery staging')
    if staged.exists():
        existing,_=decode(c,state,staged)
        c.require(existing==raw,'pending recovery differs from the original backup')
    else:
        c.run(['systemd-creds','encrypt','--with-key=host','--name=kaia-corecell','-',str(staged)],input=raw)
        private_file(c,staged)
        with staged.open('rb') as stream:os.fsync(stream.fileno())
        sync(directory)
    # Authoritative receipt is durable before publishing new ciphertext. A
    # crash between these two operations can be resumed with the same backup.
    sync_private(c,staged);sync(directory)
    state['custody_cipher']=hashlib.sha256(staged.read_bytes()).hexdigest()
    c.save(state);sync_owner(c,state)
    os.replace(staged,path);sync(directory)
    read(c,state)
    return {'restored':True,'identity_preserved':True}


def materialize(c,state,directory,gid):
    """Publish only the sealed original scalars for a read-only container bind.

    Caller first establishes immutable owner/network, stopped writers, protected
    runtime ancestry, the dedicated group and backup acknowledgment. This helper
    never creates keys on startup or writes to the persistent native database.
    """
    c.require(state.get('backup_confirmed') is True and isinstance(state.get('custody_public'),dict),
              'verified concealed backup is required before native startup')
    uid=state.get('service_uid')
    c.require(type(uid) is int and type(gid) is int and 0<uid<2**31 and 0<gid<2**31,'invalid dedicated runtime identity')
    raw,value=read(c,state)
    del raw
    c.protected_directory(directory)
    directory.mkdir(mode=0o750,exist_ok=True)
    c.require(set(x.name for x in directory.iterdir()) <= {'nodekey','bls-nodekey'},'unexpected runtime custody artifacts')
    for name,key in (('nodekey','nodekey'),('bls-nodekey','bls_nodekey')):
        target=directory/name
        if target.exists() or target.is_symlink():
            private_runtime(c,target,uid,gid)
            c.require(target.read_bytes()==value[key].encode(),'runtime identity differs from the original receipt')
        else:
            fd=os.open(target,os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_WRONLY,0o400)
            with os.fdopen(fd,'wb') as stream:
                os.fchown(stream.fileno(),uid,gid)
                os.fchmod(stream.fileno(),0o400)
                stream.write(value[key].encode());stream.flush();os.fsync(stream.fileno())
    sync(directory)
    os.chown(directory,c.ROOT_UID,gid)
    os.chmod(directory,0o750)
    sync(directory)
    return {'identity_preserved':True}


def private_runtime(c,path,uid,gid):
    c.require(not path.is_symlink() and path.is_file(),'unsafe runtime key path')
    info=path.stat()
    c.require(info.st_uid==uid and info.st_gid==gid and info.st_mode&0o777==0o400 and
              info.st_nlink==1 and info.st_size==64,'runtime key ownership or size differs')
