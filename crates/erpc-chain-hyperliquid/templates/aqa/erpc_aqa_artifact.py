# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Authenticate the signed native publisher archive without executing it."""
import base64
import hashlib
import os
from pathlib import Path
import secrets
import stat
import tarfile
import urllib.parse
import urllib.request
from erpc_aqa_common import RELEASES,atomic,digest,execute,fsync_dir,json_bytes,owned_directory,read,require,unique_json


def origin(url):
    parsed=urllib.parse.urlsplit(url)
    require(parsed.scheme=='https' and parsed.hostname in
            ('github.com','release-assets.githubusercontent.com','objects.githubusercontent.com')
            and parsed.port in (None,443) and parsed.username is None and parsed.password is None,
            'publisher artifact left its qualified public origins')


class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,request,fp,code,msg,headers,newurl):
        origin(newurl)
        return super().redirect_request(request,fp,code,msg,headers,newurl)


def download(pin,path):
    origin(pin['url'])
    request=urllib.request.Request(pin['url'],headers={'User-Agent':'erpc-aqa-controller'})
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),Redirect)
    count=0;hashes=hashlib.sha256()
    with opener.open(request,timeout=60) as response:
        origin(response.geturl());require(response.status==200,'publisher artifact HTTP status differs')
        fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as target:
            while True:
                block=response.read(min(1048576,pin['size']-count+1))
                if not block:break
                count+=len(block);require(count<=pin['size'],'publisher archive exceeds qualified size')
                hashes.update(block);target.write(block)
            target.flush();os.fsync(target.fileno())
    require(count==pin['size'] and hashes.hexdigest()==pin['sha256'],'publisher archive differs from its original digest')


def verify_signature(catalog,directory):
    pin=catalog['artifact'];key=base64.b64decode(pin['keyring_base64'],validate=True)
    signature=pin['signature'].encode()
    require(digest(key)==pin['keyring_sha256'] and digest(signature)==pin['signature_sha256'],
            'embedded publisher signature material differs')
    atomic(directory/'publisher.gpg',key)
    atomic(directory/'publisher.asc',signature)
    result=execute(['/usr/bin/gpgv','--status-fd','1','--keyring',directory/'publisher.gpg',
                    directory/'publisher.asc',directory/'archive.tar.gz'])
    require(len(result.stdout)<=65536,'signature verification output exceeds its bound')
    valid=[line.split() for line in result.stdout.decode('ascii').splitlines() if line.startswith('[GNUPG:] VALIDSIG ')]
    require(len(valid)==1 and len(valid[0])>=5 and valid[0][2]==pin['signer']
            and valid[0][4].isdigit() and int(valid[0][4])==pin['signed_at'],
            'publisher signature does not match the original release key and time')


def unpack(catalog,directory):
    pin=catalog['artifact'];seen=set()
    with tarfile.open(directory/'archive.tar.gz','r:gz') as archive:
        for member in archive:
            require(member.name in ('publish_daemon','._publish_daemon') and member.name not in seen
                    and member.isfile(),'unexpected native publisher archive member')
            seen.add(member.name)
            if member.name=='._publish_daemon':
                require(member.size==163,'unexpected publisher archive metadata')
                continue
            require(member.size==pin['binary_size'],'native publisher size differs')
            source=archive.extractfile(member);require(source is not None,'publisher member unavailable')
            data=source.read(pin['binary_size']+1)
            require(len(data)==pin['binary_size'] and digest(data)==pin['binary_sha256']
                    and data[:6]==b'\x7fELF\x02\x01' and data[18:20]==b'\x3e\x00',
                    'publisher executable differs from qualified Linux x86-64 bytes')
            atomic(directory/'publish_daemon',data,0o555)
    require(seen=={'publish_daemon','._publish_daemon'},'native publisher archive is incomplete')


def qualified(catalog):
    return {'version':catalog['version'],'source_commit':catalog['source_commit'],
            'archive_sha256':catalog['artifact']['sha256'],'binary_sha256':catalog['artifact']['binary_sha256']}


def check(catalog):
    directory=RELEASES/catalog['version'];owned_directory(directory)
    require(stat.S_IMODE(directory.lstat().st_mode)==0o755,'publisher release is not publicly traversable')
    require(set(p.name for p in directory.iterdir())=={'publish_daemon','receipt.json'},
            'publisher release contains unknown entries')
    require(unique_json(read(directory/'receipt.json'))==qualified(catalog),'publisher release receipt changed')
    path=directory/'publish_daemon';info=path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1
            and stat.S_IMODE(info.st_mode)==0o555,'publisher executable is not original protected code')
    raw=read(path,catalog['artifact']['binary_size'])
    require(digest(raw)==catalog['artifact']['binary_sha256'],'publisher executable digest changed')
    return path


def install(catalog):
    owned_directory(RELEASES,True,0o755)
    final=RELEASES/catalog['version']
    if final.exists() or final.is_symlink():
        check(catalog)
    else:
        stage=RELEASES/('.pending-'+secrets.token_hex(16));stage.mkdir(mode=0o700)
        download(catalog['artifact'],stage/'archive.tar.gz');verify_signature(catalog,stage);unpack(catalog,stage)
        payload=stage/'payload';payload.mkdir(mode=0o700)
        os.replace(stage/'publish_daemon',payload/'publish_daemon')
        atomic(payload/'receipt.json',json_bytes(qualified(catalog)))
        os.chmod(payload,0o755);fsync_dir(payload)
        os.rename(payload,final);fsync_dir(RELEASES)
        # The encrypted-key namespace is separate. Only our immutable public
        # download/signature files are removed from this exact completed stage.
        for name in ('archive.tar.gz','publisher.gpg','publisher.asc'):(stage/name).unlink()
        stage.rmdir();fsync_dir(RELEASES)
        check(catalog)
    for path in (final/'publish_daemon',final/'receipt.json'):
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:os.fsync(fd)
        finally:os.close(fd)
    fsync_dir(final);fsync_dir(RELEASES)
    return qualified(catalog)
