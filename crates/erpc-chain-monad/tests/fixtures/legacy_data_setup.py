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


def verify_data(state,c,uid,gid):
    """Startup never accepts a replacement or an unfinished filesystem choice."""
    state.check(c);owned_directory(ROOT)
    saved=state.get('data-ready.json')
    expected={'contract':c,'uid':uid,'gid':gid,'layout':list(DATA_LAYOUT)}
    require(set(saved)==set(expected)|{'binding','final'} and saved['final'] is True
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
            if relative=='data':require({'device':info.st_dev,'inode':info.st_ino}==saved['binding'],
                                        'original native filesystem changed')
    finally:
        for fd in reversed(list(descriptors.values())):os.close(fd)


def prepare_data(state,c,uid,gid,final=True):
    """Drain original UIDs before entry. All native writes use no-follow FDs.

    Init creates a provisional empty layout. Before the first deployment only,
    the operator may mount a clean filesystem over it. That selection is bound
    durably before changing permissions; subsequent deployments cannot replace
    its root inode/device or recreate missing history directories.
    """
    state.check(c)
    owned_directory(ROOT)
    expected={'contract':c,'uid':uid,'gid':gid,'layout':list(DATA_LAYOUT)}
    ready=ROOT/'data-ready.json';intent=ROOT/'data-preparing.json'
    established=ready.exists();replacement=None
    if established:
        saved=state.get('data-ready.json')
        require(set(saved)==set(expected)|{'binding','final'} and type(saved['final'])is bool
                and {key:saved[key] for key in expected}==expected,'native data ownership receipt differs')
        current=(ROOT/'data').lstat();binding={'device':current.st_dev,'inode':current.st_ino}
        require(stat.S_ISDIR(current.st_mode),'native data root is redirected')
        if binding!=saved['binding']:
            require(final and not saved['final'] and not any((ROOT/name).exists() for name in
                    ('installed.json','bootstrap-copied','device-initializing.json','device-initialized.json')),
                    'established native filesystem changed; automatic adoption refused')
            replacement={'original':saved,'binding':binding}
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
        if intent.exists():require(state.get('data-preparing.json')==expected,'native data preparation belongs to another owner')
        else:
            require(not (ROOT/'data').exists() and not (ROOT/'data').is_symlink(),
                    'unreceipted native data cannot be adopted')
            state.put('data-preparing.json',expected)
        sync_receipt(intent,expected)
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
            mount_root=replacement is not None and relative=='data'
            require(stat.S_ISDIR(info.st_mode) and (stat.S_IMODE(info.st_mode)==0o700
                    or (mount_root and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o755)),
                    'native data directory has unexpected permissions')
            if mount_root:require({'device':info.st_dev,'inode':info.st_ino}==replacement['binding'],
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
        record=dict(expected,binding={'device':data.st_dev,'inode':data.st_ino},
                    final=final or (saved['final'] if ready.exists() else False))
        if not established or record!=saved:state.put('data-ready.json',record)
    finally:
        for fd in reversed(list(descriptors.values())):os.close(fd)

