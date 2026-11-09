# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Root publisher for a short-lived original Reth IPC peer proof.

The non-root transport still checks SO_PEERCRED on every connected socket before
sending bytes. This receipt associates that kernel peer with the reviewed native
process image/arguments/cgroup. It does not trust a loopback port or unit name.
"""
import os
from pathlib import Path
import re
import stat
import time
from eth_files import atomic,digest,encoded,require,root_directory
import eth_process as processes
import eth_validator_runtime as runtime
import eth_validator_native as native

PROC=Path('/proc')
UNIT='erpc-eth-execution.service'


class Unavailable(Exception):pass


def properties(run):
    raw=run(['/usr/bin/systemctl','show',UNIT,'--property=ActiveState,SubState,MainPID,Result'])
    values={}
    for line in raw.decode().splitlines():
        name,separator,value=line.partition('=');require(separator and name not in values,'ambiguous original execution service state');values[name]=value
    if values.get('ActiveState') in ('inactive','failed','activating','deactivating'):
        raise Unavailable('original execution service is transitioning')
    require(values.get('ActiveState')=='active' and values.get('SubState')=='running' and values.get('Result')=='success'
            and values.get('MainPID','').isdigit() and int(values['MainPID'])>1,'original execution service is not running')
    return int(values['MainPID'])


def listening_inode(path):
    raw=(PROC/'net/unix').read_bytes();require(len(raw)<=8*1024*1024,'kernel IPC namespace exceeds its bound')
    found=[]
    for line in raw.decode().splitlines()[1:]:
        fields=line.split(maxsplit=7)
        if len(fields)==8 and fields[7]==str(path):
            require(fields[3]=='00010000' and fields[4]=='0001' and fields[6].isdigit(),
                    'original IPC pathname is not a listening stream socket')
            found.append(int(fields[6]))
    if not found:raise Unavailable('original IPC listener has not opened yet')
    require(len(found)==1,'original IPC listener is ambiguous');return found[0]


def owns_socket(pid,inode):
    directory=PROC/str(pid)/'fd';count=0;found=False
    for path in directory.iterdir():
        count+=1;require(count<=100000,'original process descriptor namespace exceeds its bound')
        if not path.name.isdigit():continue
        try:link=os.readlink(path)
        except FileNotFoundError:continue
        if link=='socket:['+str(inode)+']':found=True
    require(found,'original native process does not own its IPC listener')


def revoke():
    directory=root_directory(native.RUN)
    try:
        path=native.RUN/'engine-peer.json'
        if path.exists() or path.is_symlink():
            from eth_files import read
            read(path,16384,mode=0o644);os.unlink(path.name,dir_fd=directory)
        os.fsync(directory)
    finally:os.close(directory)


def publish(state,expected,plan,approved,run):
    runtime.verify(state,expected);path=native.RUN/'engine'/'engine.ipc';proof=native.RUN/'engine-peer.json'
    # A failed refresh cannot leave an old grant until its expiration. The root
    # observer separately handles refusal/owned shutdown without self-stop.
    revoke()
    try:value=qualified_peer(expected,plan,approved,run,path)
    except (FileNotFoundError,ProcessLookupError):raise Unavailable('original native IPC peer exited') from None
    atomic(proof,encoded(value),0o644)
    return {'original_engine_peer':True,'expires_in_seconds':60}


def qualified_peer(expected,plan,approved,run,path):
    pid=properties(run);account=plan['users']['ev-reth']
    start=processes.prove(pid,dict(account,groups=[plan['groups']['ev-engine']]),approved,unit=UNIT)
    require(start is not None,'original execution process has exited')
    info=path.lstat()
    require(stat.S_ISSOCK(info.st_mode) and info.st_uid==account['uid'] and info.st_gid==account['gid']
            and stat.S_IMODE(info.st_mode)==0o660,'original engine IPC ownership or access differs')
    inode=listening_inode(path);owns_socket(pid,inode)
    require(processes.prove(pid,dict(account,groups=[plan['groups']['ev-engine']]),approved,unit=UNIT)==start,
            'original execution process changed during IPC publication')
    after=path.lstat();require((info.st_dev,info.st_ino)==(after.st_dev,after.st_ino),'original IPC pathname changed during publication')
    value={'contract':digest(encoded(expected)),'boot_id':runtime.boot(),'pid':pid,'uid':account['uid'],'gid':account['gid'],
           'start':start,'socket':{'device':info.st_dev,'inode':info.st_ino,'path':str(path)},'expires':time.monotonic()+60}
    return value
