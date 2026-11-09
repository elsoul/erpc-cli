# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Same-source keygen bytes, sealed before any original private input.

Only standard OS-exposed memfd/seal constants are used. Normal execve must work
under the existing kernel policy; no loader trick, policy edit or disk fallback.
This performs public derivation, never key generation or transaction submission.
"""
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import native_migration_inspect as legacy
import native_platform

if 'ORIGINAL_SOURCES' not in globals():
    ORIGINAL_SOURCES = json.loads(Path(__file__).with_name('migration-sources.json').read_bytes())
MAXIMUM = 128 * 1024 * 1024
require = legacy.require


def qualified_source(network, source):
    require(isinstance(ORIGINAL_SOURCES,dict) and set(ORIGINAL_SOURCES)=={'schema','sources','git_sources'}
            and type(ORIGINAL_SOURCES['schema']) is int and ORIGINAL_SOURCES['schema']==1 and network in ('mainnet','testnet'), 'original source catalog differs')
    require(isinstance(source,dict) and set(source)=={'version','commit','cargo_lock_sha256','rust','rust_manifest_sha256'}
            and source in ORIGINAL_SOURCES['sources'].get(network,[])
            and ORIGINAL_SOURCES['git_sources'].get(source['commit']), 'original source/compiler is not qualified')


def evidence(request):
    value=request.get('keygen_evidence')
    require(isinstance(value,dict) and set(value)=={'document_sha256','network','source','executable_sha256','executable_bytes'}
            and value['network']==request['network'] and value['source']==request['artifact_evidence']['source']
            and type(value['executable_bytes']) is int and 64<=value['executable_bytes']<=MAXIMUM,
            'independent same-source keygen artifact is required')
    qualified_source(request['network'],value['source'])
    for field in ('document_sha256','executable_sha256'):
        require(isinstance(value[field],str) and len(value[field])==64 and all(c in '0123456789abcdef' for c in value[field])
                and any(c!='0' for c in value[field]), 'invalid original keygen evidence')
    return value


def platform(request):
    def directory(path):
        for parent in reversed([path,*path.parents]):
            info=parent.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022,'untrusted platform metadata ancestor')
    def operating_system():
        return native_platform.operating_system(legacy.ROOT/'etc/os-release',legacy.ROOT/'usr/lib/os-release',
            lambda path,maximum:legacy.read_public(str(path.relative_to(legacy.ROOT)),maximum=maximum),directory)
    native_platform.platform_facts(request['role'],request['network'],legacy.command,operating_system,legacy.ROOT/'proc/cpuinfo')
    require(sys.platform=='linux' and hasattr(os,'memfd_create') and os.uname().machine=='x86_64', 'original public proof requires Linux memfd support')
    for module,names in ((os,('MFD_CLOEXEC','MFD_ALLOW_SEALING')),
                        (fcntl,('F_ADD_SEALS','F_GET_SEALS','F_SEAL_WRITE','F_SEAL_GROW','F_SEAL_SHRINK','F_SEAL_SEAL'))):
        require(all(type(getattr(module,name,None)) is int for name in names), 'required kernel seals are unavailable')


def seal(fd):
    flags=fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL
    fcntl.fcntl(fd,fcntl.F_ADD_SEALS,flags)
    require(fcntl.fcntl(fd,fcntl.F_GET_SEALS)&flags==flags, 'original proof descriptor is not completely sealed')
    os.lseek(fd,0,os.SEEK_SET)


def elf(fd,size):
    """Refuse user-library search paths in a privately executed native tool."""
    header=os.pread(fd,64,0)
    require(len(header)==64 and header[:7]==b'\x7fELF\x02\x01\x01'
            and struct.unpack_from('<H',header,16)[0] in (2,3)
            and struct.unpack_from('<H',header,18)[0]==62, 'qualified x86_64 Linux ELF required')
    offset=struct.unpack_from('<Q',header,32)[0];width,count=struct.unpack_from('<HH',header,54)
    require(width==56 and 1<=count<=128 and 64<=offset and offset+width*count<=size, 'invalid original ELF program headers')
    interpreter=False;loads=[];dynamic=[]
    for index in range(count):
        record=os.pread(fd,56,offset+index*56);kind,_,position,virtual,_,length,_,_=struct.unpack('<IIQQQQQQ',record)
        require(position+length<=size, 'original ELF segment is out of bounds')
        if kind==1:loads.append((virtual,position,length))
        if kind==3:
            require(not interpreter and 0<length<=256
                    and os.pread(fd,length,position)==b'/lib64/ld-linux-x86-64.so.2\0','unqualified original ELF interpreter')
            interpreter=True
        if kind==2:
            require(length%16==0 and length<=65536,'invalid original ELF dynamic section')
            for entry in range(0,length,16):
                tag,value=struct.unpack('<qQ',os.pread(fd,16,position+entry))
                # Only ordinary dynamic-link metadata used by the qualified
                # native build is accepted; custom audit/filter/config tags
                # are not a route to executing user-controlled libraries.
                require(tag in set(range(0,38))|{0x6ffffef5,0x6ffffff0,0x6ffffff9,0x6ffffffa,0x6ffffffb,0x6ffffffc,0x6ffffffd,0x6ffffffe,0x6fffffff}
                        and tag not in (15,29),'original keygen has unqualified dynamic loader metadata')
                dynamic.append((tag,value))
    require(interpreter,'original dynamic Linux keygen interpreter is missing')
    needed=[value for tag,value in dynamic if tag==1]
    if needed:
        addresses=[value for tag,value in dynamic if tag==5];sizes=[value for tag,value in dynamic if tag==10]
        require(len(addresses)==len(sizes)==1 and 0<sizes[0]<=1024*1024,'original ELF dependency names are ambiguous')
        locations=[position+addresses[0]-virtual for virtual,position,length in loads
                   if virtual<=addresses[0] and addresses[0]+sizes[0]<=virtual+length]
        require(len(locations)==1,'original ELF dependency table is out of bounds')
        table=os.pread(fd,sizes[0],locations[0]);require(len(table)==sizes[0],'original ELF dependency table is incomplete')
        allowed={'libc.so.6','libm.so.6','libgcc_s.so.1','libpthread.so.0','librt.so.1','libdl.so.2',
                 'libudev.so.1','libusb-1.0.so.0','libssl.so.3','libcrypto.so.3','libz.so.1','libzstd.so.1','libstdc++.so.6'}
        for offset in needed:
            require(offset<len(table) and b'\0' in table[offset:],'original ELF dependency name is malformed')
            name=table[offset:].split(b'\0',1)[0].decode('ascii')
            require(name in allowed,'original keygen requires a non-system runtime dependency')


def original_path(request):
    # The carried build recipe installs target/release binaries and symlinks
    # active_release/bin to these real files. Never execute through that pointer.
    path=legacy.ROOT/'home/solv/agave/target/release/solana-keygen'
    uid=request['historical']['uid']
    for parent in reversed(path.parents):
        info=parent.lstat();allowed=(0,uid) if parent==legacy.ROOT/'home/solv' or legacy.ROOT/'home/solv' in parent.parents else (0,)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid in allowed and not info.st_mode&0o022,
                'original keygen ancestor is not qualified')
    info=path.lstat()
    # Code may have Cargo hardlinks; its exact sealed bytes are authenticated.
    # Private identity files separately require a single link.
    require(stat.S_ISREG(info.st_mode) and info.st_uid in (0,uid) and info.st_nlink>=1
            and info.st_mode&0o111 and not info.st_mode&0o6022, 'original keygen file authority differs')
    return path,info


def invoke(image,args,private_fd=None):
    require(type(image) is int and image>=3 and
            (private_fd is None and args==['--version'] or type(private_fd) is int and private_fd>=3
             and private_fd!=image and args==['bls_pubkey','/proc/self/fd/'+str(private_fd)]),
            'unqualified keygen operation or descriptor')
    descriptors=(image,) if private_fd is None else (image,private_fd)
    command=['/usr/bin/unshare','--net','--','/usr/bin/setpriv','--no-new-privs','--bounding-set=-all',
             '--inh-caps=-all','--ambient-caps=-all','--clear-groups','--','/proc/self/fd/'+str(image),*args]
    result=subprocess.run(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        pass_fds=descriptors,cwd='/',timeout=15,check=False,
        env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LANG':'C.UTF-8','LC_ALL':'C.UTF-8'})
    require(result.returncode==0 and not result.stderr and len(result.stdout)<=512,'qualified public keygen operation failed')
    return result.stdout


@contextlib.contextmanager
def artifact(request):
    platform(request);record=evidence(request);path,before=original_path(request)
    require(before.st_size==record['executable_bytes'],'original keygen size differs from independent evidence')
    source=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    image=None
    try:
        opened=os.fstat(source);require((opened.st_dev,opened.st_ino)==(before.st_dev,before.st_ino),'original keygen inode changed')
        image=os.memfd_create('erpc-original-keygen',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
        os.fchmod(image,0o500)  # Failure under noexec policy is a preflight refusal.
        checksum=hashlib.sha256();count=0
        while True:
            block=os.read(source,65536)
            if not block:break
            count+=len(block);require(count<=record['executable_bytes'],'original keygen grew during qualification')
            checksum.update(block);view=memoryview(block)
            while view:
                written=os.write(image,view);require(written>0,'original proof artifact copy failed');view=view[written:]
        after=os.fstat(source);current=path.lstat()
        require(count==record['executable_bytes'] and checksum.hexdigest()==record['executable_sha256']
                and (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
                    (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
                and (current.st_dev,current.st_ino)==(before.st_dev,before.st_ino), 'original keygen bytes changed or lack independent evidence')
        elf(image,count);seal(image)
        sealed_hash=hashlib.sha256()
        for position in range(0,count,65536):
            sealed_hash.update(os.pread(image,min(65536,count-position),position))
        require(os.fstat(image).st_size==count and sealed_hash.hexdigest()==record['executable_sha256'],
                'sealed original keygen content differs from its independent evidence')
        require(os.fstat(image).st_mode&0o7777==0o500,'original executable memory policy differs')
        version=invoke(image,['--version']).decode('ascii').strip()
        require(version.startswith('solana-keygen '+record['source']['version']+' ')
                or version=='solana-keygen '+record['source']['version'], 'original keygen capability/version differs')
        yield image
    finally:
        os.close(source)
        if image is not None:os.close(image)


def derive(image,material):
    require(isinstance(material,bytearray) and len(material)==64,'validated original key material required')
    descriptor=os.memfd_create('erpc-original-identity',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
    raw=bytearray(json.dumps(list(material),separators=(',',':')).encode())
    try:
        os.fchmod(descriptor,0o400)
        view=memoryview(raw)
        while view:
            written=os.write(descriptor,view);require(written>0,'original identity descriptor write failed');view=view[written:]
        seal(descriptor)
        value=invoke(image,['bls_pubkey','/proc/self/fd/'+str(descriptor)],descriptor).decode('ascii').strip()
        alphabet='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';number=0
        require(1<=len(value)<=66 and all(c in alphabet for c in value),'invalid original BLS public output')
        for c in value:number=number*58+alphabet.index(c)
        require(number>0 and len(value)-len(value.lstrip('1'))+(number.bit_length()+7)//8==48,'original BLS public output width differs')
        return value
    finally:
        raw[:]=bytes(len(raw));os.close(descriptor)
