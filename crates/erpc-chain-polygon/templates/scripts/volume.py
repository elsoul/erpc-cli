# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original ext4/XFS data authority, independent of account names or free space.

Initial storage can contain only an empty root-owned lost+found. Runtime checks
use kernel mount metadata and the root-owned udev UUID link; they never open a
block device from a service's device-limited cgroup. Stop remains independent.
"""
import json
import os
from pathlib import Path
import re
import stat
import host

DATA='/var/lib/polygon'
RECEIPT='/etc/polygon/storage.json'


def require(value,message):
    if not value:raise ValueError(message)


def original(path):
    info=path.lstat()
    return {'device':info.st_dev,'inode':info.st_ino}


def recovery(state,descriptor):
    if 'lost+found' in os.listdir(descriptor):
        handle=os.open('lost+found',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=descriptor)
        try:
            item=os.fstat(handle)
            require(item.st_uid==state.owner and not item.st_mode&0o022 and not os.listdir(handle),
                    'filesystem recovery content must be preserved for explicit recovery')
            require(os.stat('lost+found',dir_fd=descriptor,follow_symlinks=False).st_ino==item.st_ino,
                    'filesystem recovery directory changed')
        finally:os.close(handle)


def empty(state):
    path=state.protected(DATA,missing=True)
    if not path.exists():return None
    descriptor=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        value=os.fstat(descriptor)
        require(value.st_uid==state.owner and not value.st_mode&0o022,'prepared Polygon volume is not root protected')
        require(set(os.listdir(descriptor))<={'lost+found'},'unowned Polygon data cannot be adopted')
        recovery(state,descriptor)
        require(original(path)=={'device':value.st_dev,'inode':value.st_ino},'prepared Polygon volume changed')
        return {'device':value.st_dev,'inode':value.st_ino}
    finally:os.close(descriptor)


def rows(state,*arguments):
    result=state.command('/usr/bin/findmnt','--task','1','--json',*arguments,timeout=30)
    require(0<len(result.stdout)<=8*1024*1024,'host mount observation exceeds its bound')
    value=json.loads(result.stdout)
    require(isinstance(value,dict) and set(value)=={'filesystems'} and isinstance(value['filesystems'],list),
            'host mount topology is unavailable')
    return value['filesystems']


def topology(state):
    data=state.path(DATA);count=0
    mounts=rows(state,'--list','--output','TARGET')
    require(0<len(mounts)<=100000,'host mount topology is unavailable or excessive')
    for entry in mounts:
        require(isinstance(entry,dict) and set(entry)=={'target'} and isinstance(entry['target'],str),
                'invalid host mount entry')
        path=Path(entry['target'])
        require(path.is_absolute() and os.path.normpath(path)==str(path),'invalid mounted target')
        require(not (path!=data and data in path.parents),'nested Polygon data mounts, including same-device binds, are unsupported')
        if path==data:count+=1
    require(count<=1,'stacked Polygon data mounts are unsupported')


def uuid_device(state,identifier):
    require(isinstance(identifier,str) and re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',identifier)
            and any(char not in '0-' for char in identifier),'invalid original data filesystem UUID')
    parent=state.protected('/dev/disk/by-uuid')
    link=parent/identifier;metadata=link.lstat()
    require(stat.S_ISLNK(metadata.st_mode) and metadata.st_uid==state.owner,'original udev filesystem selector is unavailable')
    target=os.readlink(link)
    require(re.fullmatch(r'\.\./\.\./[A-Za-z0-9._-]+',target),'udev filesystem selector leaves its fixed device namespace')
    device=state.path('/dev/'+target.removeprefix('../../'))
    info=device.lstat()
    require(stat.S_ISBLK(info.st_mode) and info.st_uid==state.owner,'original filesystem selector does not identify a root-owned block device')
    require(link.lstat().st_ino==metadata.st_ino and os.readlink(link)==target,'udev filesystem selector changed')
    return info.st_rdev


def probe(state,identifier=None):
    topology(state)
    path=state.path(DATA)
    while not path.exists() and not path.is_symlink():path=path.parent
    state.protected('/'+str(path.relative_to(state.root)))
    before=original(path)
    fields='FSTYPE,OPTIONS,MAJ:MIN' if identifier is not None else 'UUID,FSTYPE,OPTIONS,MAJ:MIN'
    values=rows(state,'--target',str(path),'--output',fields)
    require(len(values)==1 and isinstance(values[0],dict),'ambiguous Polygon data filesystem')
    value=values[0]
    require(value.get('fstype') in ('ext4','xfs') and isinstance(value.get('options'),str)
            and 'rw' in value['options'].split(',') and isinstance(value.get('maj:min'),str)
            and re.fullmatch('[0-9]+:[0-9]+',value['maj:min']),'Polygon requires an identified writable ext4/XFS volume')
    major,minor=map(int,value['maj:min'].split(':'))
    require(os.makedev(major,minor)==before['device'],'mount table and original path device differ')
    identifier=identifier if identifier is not None else value.get('uuid')
    require(uuid_device(state,identifier)==before['device'],'the original UUID is mounted on another data device')
    require(original(path)==before,'Polygon volume changed during mount inspection')
    return {'uuid':identifier,'filesystem':value['fstype'],'inode':before['inode']}


def reserve(state,expected):
    state.ownership(expected)
    path=state.protected(RECEIPT,missing=True)
    if path.exists():return verify(state,expected)
    retained=('/etc/polygon/runtime-accounts.json','/etc/polygon/runtime-accounts.reserved',
        '/etc/polygon/installed.json','/etc/polygon/identity.json','/etc/polygon/history.json',
        '/etc/polygon/activation.json','/etc/credstore.encrypted/polygon/original')
    require(not any(state.path(name).exists() or state.path(name).is_symlink() for name in retained),
            'retained Polygon authority has no original storage receipt; explicit recovery required')
    empty(state)
    probe(state)
    data=state.protected(DATA,missing=True)
    data.mkdir(mode=0o755,exist_ok=True);host.sync_parents(data,state.root)
    identity=empty(state);observed=probe(state)
    require(identity['inode']==observed['inode'],'prepared data changed before reservation')
    state.write(RECEIPT,dict(observed,contract=expected))
    return verify(state,expected)


def verify(state,expected):
    saved=state.read(RECEIPT)
    require(isinstance(saved,dict) and set(saved)=={'contract','uuid','filesystem','inode'} and saved['contract']==expected,
            'Polygon storage belongs to another original owner')
    observed=probe(state,saved['uuid'])
    require(saved==dict(observed,contract=expected),'the original Polygon data filesystem or directory was replaced')
    path=state.protected(DATA);descriptor=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        require(os.fstat(descriptor).st_ino==saved['inode'],'original data directory changed')
        recovery(state,descriptor)
        require(path.lstat().st_ino==saved['inode'],'original data directory changed')
    finally:os.close(descriptor)
    host.sync_file(state.protected(RECEIPT));host.sync_parents(state.path('/etc/polygon'),state.root)
    return saved
