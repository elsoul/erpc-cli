# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Bounded native helper effects and volatile private staging for the validator."""
import ctypes
import errno
import os
from pathlib import Path
import re
import signal
import resource
import stat
import subprocess
import threading
from eth_files import ENV,checked_file,require,root_directory

RUN=Path('/run/erpc-eth-validator')
MOUNTS=Path('/proc/self/mountinfo')


def volatile(path):
    """Authenticate a real tmpfs before materializing plaintext credentials."""
    descriptor=root_directory(path)
    try:device=os.fstat(descriptor).st_dev
    finally:os.close(descriptor)
    raw=MOUNTS.read_bytes();require(len(raw)<=8*1024*1024,'runtime mount namespace exceeds its bound')
    matches=[]
    for line in raw.decode().splitlines():
        fields=line.split();require(len(fields)>=10 and '-' in fields[6:],'invalid kernel runtime mount record')
        separator=fields.index('-',6);require(separator+3<len(fields),'invalid kernel runtime filesystem record')
        mount=re.sub(r'\\(040|011|012|134)',lambda match:chr(int(match.group(1),8)),fields[4])
        require('\\' not in mount and mount.startswith('/'),'invalid runtime mount path')
        if str(path)==mount or str(path).startswith(mount.rstrip('/')+'/'):
            matches.append((len(mount),fields[2],fields[separator+1]))
    require(matches,'runtime mount authority is unavailable')
    _,number,kind=max(matches)
    require(number==str(os.major(device))+':'+str(os.minor(device)) and kind=='tmpfs',
            'plaintext validator runtime must be on an authenticated volatile tmpfs')
    return device


def scratch(parent):
    import secrets
    volatile(parent)
    directory=root_directory(parent)
    try:
        name='attempt-'+secrets.token_hex(16)
        os.mkdir(name,0o700,dir_fd=directory)
        child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=directory)
        try:os.fchmod(child,0o700);os.fsync(child)
        finally:os.close(child)
        os.fsync(directory)
    finally:os.close(directory)
    # Never reuse an old scratch pathname after interrupted native execution.
    # Its old child may still be exiting after PR_SET_PDEATHSIG delivery.
    return parent/name


def worker(argv,input_data=None,timeout=120,identity=None):
    """Standalone single-threaded root controller only; no private diagnostics.

    Native children inherit a parent-death kill and no-new-privileges before
    execution. The caller selects a closed command/profile, not arbitrary user
    input. A failed operation retains its private volatile scratch for diagnosis.
    """
    require(threading.active_count()==1 and argv and Path(argv[0]).is_absolute(),
            'native validator worker requires a standalone controller and absolute executable')
    executable=Path(argv[0]);directory=root_directory(executable.parent)
    try:
        descriptor=os.open(executable.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=directory)
        try:
            info=os.fstat(descriptor);checked_file(info)
            require(info.st_mode&0o111,'native worker executable is not executable')
            try:attributes=os.getxattr(descriptor,'security.capability')
            except OSError as error:
                require(error.errno in (errno.ENODATA,errno.ENOTSUP),'cannot qualify native worker capabilities');attributes=b''
            require(not attributes,'native worker cannot have file capabilities')
        finally:os.close(descriptor)
    finally:os.close(directory)
    if identity is not None:
        require(os.geteuid()==0 and isinstance(identity,dict) and set(identity)=={'uid','gid'}
                and all(type(value)is int and 100<=value<=999 for value in identity.values()),'original private worker identity required')
    parent=os.getpid();libc=ctypes.CDLL(None,use_errno=True)
    def before_exec():
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        if identity is not None:
            os.setgroups([]);os.setgid(identity['gid']);os.setuid(identity['uid'])
        # Credential changes clear PDEATHSIG, so establish it only after the
        # original numeric UID/GID transition and recheck the controlling parent.
        if libc.prctl(38,1,0,0,0)!=0 or libc.prctl(1,signal.SIGKILL,0,0,0)!=0 or os.getppid()!=parent:os._exit(255)
    io={'stdin':subprocess.DEVNULL} if input_data is None else {'input':input_data}
    result=subprocess.run([str(arg) for arg in argv],capture_output=True,check=False,
                          timeout=timeout,env=ENV,close_fds=True,preexec_fn=before_exec,umask=0o077,**io)
    require(result.returncode==0,'native validator operation failed; private diagnostics withheld')
    require(len(result.stdout)<=1024*1024,'native validator output exceeds its bound')
    return result.stdout


def remove_scratch(path,names):
    volatile(path);directory=root_directory(path)
    try:
        require(set(os.listdir(directory))<=set(names),'private scratch contains an unowned entry')
        for name in os.listdir(directory):
            require(name in names,'unknown scratch member')
            descriptor=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=directory)
            try:checked_file(os.fstat(descriptor),mode=0o600)
            finally:os.close(descriptor)
            os.unlink(name,dir_fd=directory)
        os.fsync(directory)
    finally:os.close(directory)
    parent=root_directory(path.parent)
    try:os.rmdir(path.name,dir_fd=parent);os.fsync(parent)
    finally:os.close(parent)
