# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Owned publisher process proofs without reading private process environments."""
import hashlib
import os
from pathlib import Path
import signal
import time
from erpc_aqa_common import UNIT,require

PROC=Path('/proc')


def bounded(path,limit):
    with path.open('rb') as stream:value=stream.read(limit+1)
    require(len(value)<=limit,'process metadata exceeds its bound')
    return value


def generation(path):
    raw=bounded(path/'stat',8192).decode();suffix=raw[raw.rfind(')')+2:].split()
    require(len(suffix)>19 and suffix[19].isdigit(),'process generation is unavailable')
    return suffix[19],suffix[0]


def identity(path):
    rows={}
    for line in bounded(path/'status',16384).decode().splitlines():
        key,separator,value=line.partition(':')
        if separator and key in ('Uid','Gid','Groups'):
            require(key not in rows and all(item.isdecimal() for item in value.split()),'ambiguous process identity')
            rows[key]=list(map(int,value.split()))
    require(len(rows.get('Uid',[]))==4 and len(rows.get('Gid',[]))==4,'process credentials unavailable')
    return rows


def prove(pid,account,approved):
    path=PROC/str(pid);start,state=generation(path)
    if state in ('Z','X'):return None
    who=identity(path)
    require(who['Uid']==[account['uid']]*4 and who['Gid']==[account['gid']]*4
            and set(who.get('Groups',[]))<={account['gid']},'process is not the original isolated identity')
    cgroup=bounded(path/'cgroup',4096).decode().splitlines()
    require(cgroup==['0::/system.slice/'+UNIT],'publisher process is outside its owned service cgroup')
    executable=os.readlink(path/'exe').removesuffix(' (deleted)')
    require(executable in approved,'unknown executable holds the original publisher identity')
    candidates=approved[executable] if isinstance(approved[executable],list) else [approved[executable]]
    require(1<=len(candidates)<=8,'ambiguous original executable authority')
    argv=bounded(path/'cmdline',65536).split(b'\0')
    matching=[entry for entry in candidates if argv[:-1]==[part.encode() for part in entry['argv']]]
    require(argv[-1:]==[b''] and matching,
            'publisher invocation differs from its original runtime')
    # /proc/PID/exe deliberately accesses the kernel's open executable handle,
    # including a deleted inode; never follow a node-provided filesystem link.
    hashes=hashlib.sha256();count=0
    with (path/'exe').open('rb') as source:
        for block in iter(lambda:source.read(1048576),b''):
            count+=len(block);require(count<=32*1024*1024,'publisher process image exceeds its bound');hashes.update(block)
    require(any(hashes.hexdigest()==entry['sha256'] for entry in matching) and generation(path)[0]==start
            and identity(path)==who,'publisher process changed during authority inspection')
    return start


def scan(account,approved):
    found={};unknown=False;count=0
    for path in PROC.iterdir():
        if not path.name.isdecimal():continue
        count+=1;require(count<=1000000,'process inventory exceeds its bound')
        try:
            who=identity(path)
            if account['uid'] not in who['Uid']:continue
            start=prove(int(path.name),account,approved)
            if start is not None:found[int(path.name)]=start
        except (FileNotFoundError,ProcessLookupError):continue
        except Exception:unknown=True
    return found,unknown


def quiescent(account,approved):
    found,unknown=scan(account,approved)
    require(not found and not unknown,'original publisher identity still has a writer or unproved process')


def stop(account,approved,unit_stop):
    failures=[]
    try:unit_stop()
    except Exception:failures.append('unit stop/disable')
    found,unknown=scan(account,approved)
    if unknown:failures.append('unknown original-UID process')
    for pid,start in found.items():
        descriptor=None
        try:
            descriptor=os.pidfd_open(pid)
            require(prove(pid,account,approved)==start,'publisher PID generation changed before shutdown')
            signal.pidfd_send_signal(descriptor,signal.SIGTERM)
        except (FileNotFoundError,ProcessLookupError):pass
        except Exception:failures.append('owned process stop')
        finally:
            if descriptor is not None:os.close(descriptor)
    deadline=time.monotonic()+120
    while True:
        remaining,unknown=scan(account,approved)
        if not remaining or time.monotonic()>=deadline:break
        time.sleep(0.2)
    require(not failures and not remaining and not unknown,
            'owned publisher shutdown is incomplete; custody and filtering retained')
