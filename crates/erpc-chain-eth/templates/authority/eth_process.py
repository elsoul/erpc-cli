# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Retained numeric/cgroup/image authority, independent of current NSS and unit files."""
import hashlib
import os
from pathlib import Path
import signal
import re
import time
from eth_files import require

PROC=Path('/proc')


def bounded(path,maximum):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as stream:value=stream.read(maximum+1)
    require(len(value)<=maximum,'kernel process metadata exceeds its bound')
    return value


def generation(path):
    raw=bounded(path/'stat',16384);prefix,separator,suffix=raw.rpartition(b') ');values=suffix.split()
    require(separator and prefix.split(b' (',1)[0]==path.name.encode() and len(values)>=20
            and values[19].isdigit(),'process generation is unavailable')
    return int(values[19]),values[0]


def credentials(path):
    fields={}
    for line in bounded(path/'status',65536).decode().splitlines():
        key,separator,value=line.partition(':')
        if separator and key in ('Uid','Gid','Groups'):
            require(key not in fields and all(part.isdecimal() for part in value.split()),'ambiguous process credentials')
            fields[key]=tuple(map(int,value.split()))
        elif separator and key in ('CapInh','CapPrm','CapEff','CapAmb','NoNewPrivs'):
            value=value.strip();require(key not in fields and re.fullmatch('[a-fA-F0-9]{1,16}',value),'ambiguous process privileges')
            fields[key]=int(value,10 if key=='NoNewPrivs' else 16)
    require(len(fields.get('Uid',()))==4 and len(fields.get('Gid',()))==4,'kernel process credentials missing')
    return fields


def prove(pid,account,approved,unit=None):
    path=PROC/str(pid);start,state=generation(path)
    if state in (b'Z',b'X'):return None
    who=credentials(path)
    require(who['Uid']==(account['uid'],)*4 and who['Gid']==(account['gid'],)*4
            and set(who.get('Groups',()))<={account['gid']}|set(account.get('groups',())) and who.get('NoNewPrivs')==1
            and all(who.get(key)==0 for key in ('CapInh','CapPrm','CapEff','CapAmb')),
            'native process is not the original isolated identity')
    name=os.readlink(path/'exe').removesuffix(' (deleted)')
    require(name in approved,'original account has an unqualified executable')
    candidates=approved[name]
    require(isinstance(candidates,list) and 1<=len(candidates)<=4096,'invalid retained process authority')
    argv=bounded(path/'cmdline',131072).split(b'\0')
    group=bounded(path/'cgroup',16384)
    matching=[entry for entry in candidates if entry['uid']==account['uid'] and entry['gid']==account['gid']
              and (unit is None or entry['unit']==unit)
              and group==('0::/system.slice/'+entry['unit']+'\n').encode()
              and argv[-1:]==[b''] and argv[:-1]==[part.encode() for part in entry['argv']]]
    require(matching,'native executable arguments or original unit cgroup differ')
    digest=hashlib.sha256();count=0
    # The kernel's executable handle is intentional, including an unlinked image.
    with (path/'exe').open('rb') as stream:
        for block in iter(lambda:stream.read(1048576),b''):
            count+=len(block);require(count<=1024**3,'native executable exceeds its bound');digest.update(block)
    require(any(digest.hexdigest()==entry['sha256'] for entry in matching)
            and generation(path)[0]==start and credentials(path)==who,'native process changed while being authenticated')
    return start


def scan(accounts,approved):
    by_uid={value['uid']:value for value in accounts['users'].values()}
    found={};unknown=False;count=0
    for path in PROC.iterdir():
        if not path.name.isdecimal():continue
        count+=1;require(count<=1000000 and not path.is_symlink(),'untrusted or oversized process namespace')
        try:
            who=credentials(path);matching=set(who['Uid'])&set(by_uid)
            if not matching:continue
            require(len(matching)==1,'process combines multiple original identities')
            generation_id=prove(int(path.name),by_uid[next(iter(matching))],approved)
            if generation_id is not None:found[int(path.name)]=(generation_id,next(iter(matching)))
        except (FileNotFoundError,ProcessLookupError):continue
        except Exception:unknown=True
    return found,unknown


def quiescent(accounts,approved):
    found,unknown=scan(accounts,approved)
    require(not found and not unknown,'original Ethereum identities retain a writer or unproved process')


def stop(accounts,approved,unit_stop):
    failures=[]
    try:unit_stop()
    except Exception:failures.append('owned units')
    by_uid={value['uid']:value for value in accounts['users'].values()}
    found,unknown=scan(accounts,approved)
    if unknown:failures.append('unproved original-UID process')
    for pid,(start,uid) in found.items():
        fd=None
        try:
            fd=os.pidfd_open(pid)
            require(prove(pid,by_uid[uid],approved)==start,'PID changed before owned shutdown')
            signal.pidfd_send_signal(fd,signal.SIGINT)
        except (FileNotFoundError,ProcessLookupError):pass
        except Exception:failures.append('owned process shutdown')
        finally:
            if fd is not None:os.close(fd)
    deadline=time.monotonic()+600
    while True:
        remaining,unknown=scan(accounts,approved)
        if not remaining or time.monotonic()>=deadline:break
        time.sleep(0.2)
    require(not failures and not remaining and not unknown,'owned Ethereum shutdown incomplete; original files retained')
