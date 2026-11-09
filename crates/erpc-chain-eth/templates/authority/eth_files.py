#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Descriptor-based private authority IO; paths are never adopted by chmod/chown."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess

ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/root','LANG':'C.UTF-8','LC_ALL':'C.UTF-8'}


class Refused(ValueError):pass


def require(condition,message):
    if not condition:raise Refused(message)


def root_directory(path,create=False,mode=0o700):
    require(path.is_absolute() and str(path)==os.path.normpath(path),'normalized absolute authority path required')
    descriptor=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        for component in path.parts[1:]:
            created=False
            try:child=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=descriptor)
            except FileNotFoundError:
                require(create,'required authority directory is missing')
                os.mkdir(component,0o700,dir_fd=descriptor);created=True
                child=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=descriptor)
            try:
                info=os.fstat(child)
                require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022,
                        'authority ancestor must be an original root-owned nonwritable real directory')
                if created:os.fchmod(child,mode);os.fsync(child);os.fsync(descriptor)
            except BaseException:os.close(child);raise
            os.close(descriptor);descriptor=child
        return descriptor
    except BaseException:os.close(descriptor);raise


def parent(path):return root_directory(path.parent)


def checked_file(info,owner=0,mode=None):
    require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==owner
            and not info.st_mode&0o6022 and (mode is None or stat.S_IMODE(info.st_mode)==mode),
            'managed file is indirect, shared, foreign or has unsafe permissions')


def read(path,limit=16*1024*1024,owner=0,mode=None):
    directory=parent(path)
    try:descriptor=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=directory)
    finally:os.close(directory)
    with os.fdopen(descriptor,'rb') as stream:
        info=os.fstat(stream.fileno());checked_file(info,owner,mode)
        require(info.st_size<=limit,'managed input exceeds its bound')
        value=stream.read(limit+1);require(len(value)<=limit,'managed input changed or exceeds its bound');return value


def file_digest(path,limit=1024**3):
    directory=parent(path)
    try:descriptor=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=directory)
    finally:os.close(directory)
    result=hashlib.sha256();count=0
    with os.fdopen(descriptor,'rb') as stream:
        before=os.fstat(stream.fileno());checked_file(before)
        require(before.st_size<=limit,'native artifact exceeds its bound')
        for block in iter(lambda:stream.read(1048576),b''):
            count+=len(block);require(count<=limit,'native artifact grew beyond its bound');result.update(block)
        after=os.fstat(stream.fileno())
        require((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
                (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),
                'native artifact changed while being checked')
    return result.hexdigest()


def atomic(path,value,mode=0o600,group=None):
    directory=parent(path);temporary='.erpc-'+secrets.token_hex(16)
    try:
        try:checked_file(os.stat(path.name,dir_fd=directory,follow_symlinks=False),mode=mode)
        except FileNotFoundError:pass
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=directory)
        with os.fdopen(fd,'wb') as stream:
            stream.write(value);stream.flush()
            if group is not None:
                require(type(group)is int and 100<=group<=999,'original private group identity required')
                os.fchown(stream.fileno(),0,group)
            os.fchmod(stream.fileno(),mode);os.fsync(stream.fileno())
        os.replace(temporary,path.name,src_dir_fd=directory,dst_dir_fd=directory);os.fsync(directory)
    finally:
        try:os.unlink(temporary,dir_fd=directory)
        except FileNotFoundError:pass
        os.close(directory)


def synchronize(path):
    directory=parent(path)
    try:fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=directory)
    finally:os.close(directory)
    try:checked_file(os.fstat(fd));os.fsync(fd)
    finally:os.close(fd)
    for path in path.parents:
        fd=root_directory(path)
        try:os.fsync(fd)
        finally:os.close(fd)


def unique(raw):
    def pairs(rows):
        result={}
        for key,value in rows:
            require(key not in result,'duplicate authority field');result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(Refused('invalid JSON number')))


def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(value):return hashlib.sha256(value).hexdigest()


def run(argv,input_data=None,timeout=120,allowed=(0,)):
    require(argv and Path(argv[0]).is_absolute(),'absolute native executable required')
    result=subprocess.run([str(item) for item in argv],input=input_data,capture_output=True,env=ENV,
                          timeout=timeout,check=False,close_fds=True)
    require(result.returncode in allowed,'native operation failed; private diagnostics withheld')
    return result.stdout
