# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Extract one verified regular native binary without invoking an archive shell."""
import hashlib
import os
from pathlib import Path,PurePosixPath
import re
import tarfile
from eth_files import checked_file,require,root_directory
import eth_namespace as namespace


def extract(state,contract,operation,names):
    selected=state.current(contract,operation);spec=selected['target']
    require(isinstance(names,dict) and set(names)=={'reth','lighthouse'},'both original native archives required')
    base=namespace.PROFILES[contract['role']]['opt'];directory=base/(spec['pair']+'.pending-'+operation)
    parent=root_directory(base);os.close(parent)
    stage=root_directory(directory,create=True,mode=0o755)
    try:
        require(set(os.listdir(stage))<={'reth','lighthouse','.reth.extract','.lighthouse.extract'},'original extraction staging contains unknown material')
        for client,filename in names.items():
            require(isinstance(filename,str) and re.fullmatch('[A-Za-z0-9_.-]{1,200}\\.tar\\.gz',filename)
                    and '..' not in filename,'original archive must be a plain gzip filename')
            parent=root_directory(base)
            try:descriptor=os.open(filename,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
            finally:os.close(parent)
            with os.fdopen(descriptor,'rb') as source:
                before=os.fstat(source.fileno());checked_file(before);require(before.st_size<=1024**3,'native archive exceeds its bound')
                digest=hashlib.sha256()
                for block in iter(lambda:source.read(131072),b''):digest.update(block)
                require(digest.hexdigest()==spec[client+'_archive'],'native archive differs from the original release request')
                source.seek(0);found=False;entries=0;documentation=0
                with tarfile.open(fileobj=source,mode='r|gz') as archive:
                    for member in archive:
                        entries+=1;require(entries<=1024,'native archive has too many entries')
                        name=member.name.removeprefix('./').rstrip('/')
                        require(name and not PurePosixPath(name).is_absolute() and '..' not in PurePosixPath(name).parts
                                and member.type in (tarfile.REGTYPE,tarfile.AREGTYPE,tarfile.DIRTYPE)
                                and 0<=member.size<=1024**3 and not member.issparse(),'native archive contains an indirect or unsupported entry')
                        if name!=client:
                            require(client=='reth' and (name=='README.md' or name=='LICENSES' or name.startswith('LICENSES/'))
                                    and (member.isdir() or member.size<=16*1024*1024),'unexpected native archive member')
                            documentation+=member.size;require(documentation<=32*1024*1024,'archive documentation exceeds its bound')
                            continue
                        require(not found and member.isfile() and 0<member.size<=1024**3,'native binary is missing, duplicated or oversized')
                        found=True;payload=archive.extractfile(member);require(payload is not None,'native binary has no regular payload')
                        temporary='.'+client+'.extract'
                        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=stage)
                        try:
                            checked_file(os.fstat(fd),mode=0o600);os.ftruncate(fd,0);written=0
                            while True:
                                block=payload.read(131072)
                                if not block:break
                                written+=len(block);require(written<=member.size,'native binary exceeds its signed size')
                                view=memoryview(block)
                                while view:
                                    count=os.write(fd,view);require(count>0,'native extraction write stalled');view=view[count:]
                            require(written==member.size,'native binary is truncated');os.fsync(fd)
                            try:checked_file(os.stat(client,dir_fd=stage,follow_symlinks=False))
                            except FileNotFoundError:pass
                            os.replace(temporary,client,src_dir_fd=stage,dst_dir_fd=stage)
                            os.fchmod(fd,0o555);os.fsync(fd);os.fsync(stage)
                        finally:os.close(fd)
                require(found,'native archive does not contain its selected binary')
                after=os.fstat(source.fileno())
                require((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
                        (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'signed archive changed while extracting')
            state.current(contract,operation)
    finally:os.close(stage)
    return {'extracted':True,'intent':operation}
