# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original broker directory reservation on the immutable Polygon data volume."""
import os
import stat
import broker
import host
import volume

RECEIPT='/etc/polygon/broker-data.json'


def require(value,message):
    if not value:raise ValueError(message)


def original(state,expected,account):
    volume.verify(state,expected)
    state.protected(volume.DATA)
    path=state.path(broker.DATA);info=path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_nlink>=1 and stat.S_IMODE(info.st_mode)==0o700
            and info.st_uid==account['uid'] and info.st_gid==account['gid'],
            'broker data owner, permissions or type differ from the original account')
    record=state.read(RECEIPT)
    wanted={'format':1,'contract':expected,'account':account,'state':'established',
        'volume':state.read(volume.RECEIPT)['uuid'],'inode':info.st_ino}
    require(type(record.get('format')) is int and record==wanted,'broker data inode or original volume changed')
    return record


def reserve(state,expected,intent,profile,helpers):
    require(expected.get('role')=='validator','broker storage requires validator ownership')
    state.phase(expected,intent,profile,helpers);state.stopped()
    account=state.accounts.verify(expected)['broker']
    state.protected(volume.DATA);path=state.path(broker.DATA)
    recorded=state.path(RECEIPT).exists()
    if not recorded:
        require(not any(state.path(name).exists() or state.path(name).is_symlink() for name in
            ('/etc/polygon/broker-container.json','/etc/polygon/broker-container.pending','/etc/polygon/broker-custody.json',
             '/etc/credstore.encrypted/polygon/broker-original','/etc/credstore.encrypted/polygon/broker-original.pending')),
            'broker original storage receipt is missing with retained custody')
        if not path.exists() and not path.is_symlink():
            path.mkdir(mode=0o700);host.sync_parents(path,state.root)
        info=path.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid==state.owner and not info.st_mode&0o077
                and not any(path.iterdir()),'unknown broker data cannot be adopted')
        record={'format':1,'contract':expected,'account':account,'state':'reserved',
            'volume':state.read(volume.RECEIPT)['uuid'],'inode':info.st_ino}
        state.write(RECEIPT,record)  # Persist original IDs/inode before ownership changes.
    record=state.read(RECEIPT)
    if record.get('state')=='established':return original(state,expected,account)
    info=path.lstat()
    wanted={'format':1,'contract':expected,'account':account,'state':'reserved',
        'volume':state.read(volume.RECEIPT)['uuid'],'inode':info.st_ino}
    require(type(record.get('format')) is int and record==wanted and stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode)==0o700
            and (info.st_uid,info.st_gid) in ((state.owner,info.st_gid),(account['uid'],account['gid']))
            and not any(path.iterdir()),'interrupted broker data reservation no longer has its original empty directory')
    descriptor=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        before=os.fstat(descriptor)
        require((before.st_dev,before.st_ino)==(info.st_dev,info.st_ino),'broker directory changed before numeric handoff')
        os.fchown(descriptor,account['uid'],account['gid']);os.fchmod(descriptor,0o700);os.fsync(descriptor)
        after=path.lstat()
        require((after.st_dev,after.st_ino)==(before.st_dev,before.st_ino),'broker directory changed during numeric handoff')
    finally:os.close(descriptor)
    host.sync_parents(path.parent,state.root)
    state.phase(expected,intent,profile,helpers);state.stopped()
    record['state']='established';state.write(RECEIPT,record)
    return original(state,expected,account)
