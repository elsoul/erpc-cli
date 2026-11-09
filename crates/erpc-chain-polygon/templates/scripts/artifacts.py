#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Exact artifact acquisition and native-package verification, without maintainer scripts."""
import hashlib
import json
import shutil
from pathlib import Path
import re
import subprocess
import tempfile
import time
import urllib.request
from urllib.parse import urlsplit


HOSTS={'github.com','release-assets.githubusercontent.com','objects.githubusercontent.com','raw.githubusercontent.com','storage.googleapis.com'}


def source(url):
    parsed=urlsplit(url)
    if parsed.scheme!='https' or parsed.hostname not in HOSTS or parsed.username or parsed.password or parsed.port not in (None,443):
        raise ValueError('unreviewed artifact destination or redirect')
    return url


class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,request,fp,code,message,headers,newurl):
        source(newurl)
        return super().redirect_request(request,fp,code,message,headers,newurl)


def open_source(url,timeout):
    return urllib.request.build_opener(urllib.request.ProxyHandler({}),Redirect()).open(source(url),timeout=timeout)


def digest(path):
    value=hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda:stream.read(4*1024*1024),b''):
            value.update(chunk)
    return value.hexdigest()


def authenticate(path, pin):
    if (not path.is_file() or path.is_symlink() or path.stat().st_size!=pin['bytes']
            or digest(path)!=pin['sha256']):
        raise ValueError('artifact length or SHA-256 differs from its reviewed pin')


def fetch(pin, path, opener=open_source, clock=time.monotonic):
    source(pin['url'])
    if path.exists():
        authenticate(path,pin)
        return
    if (not isinstance(pin['bytes'],int) or not 0<pin['bytes']<=3_000_000_000
            or not re.fullmatch('[a-f0-9]{64}',pin['sha256'])):
        raise ValueError('invalid artifact bound or digest')
    temporary=path.with_suffix(path.suffix+'.partial')
    temporary.unlink(missing_ok=True)
    count=0; value=hashlib.sha256(); started=clock()
    try:
        with opener(pin['url'],timeout=30) as response,temporary.open('xb') as output:
            if 'generation=' in pin['url']:
                generation=pin['url'].split('generation=',1)[1]
                if response.headers.get('x-goog-generation')!=generation:
                    raise ValueError('genesis object generation differs')
            if int(response.headers.get('Content-Length','-1'))!=pin['bytes']:
                raise ValueError('download length differs from the reviewed pin')
            while True:
                if clock()-started>1800:
                    raise TimeoutError('bounded artifact download timed out')
                chunk=response.read(4*1024*1024)
                if not chunk:break
                count+=len(chunk)
                if count>pin['bytes']:raise ValueError('artifact exceeded byte bound')
                output.write(chunk);value.update(chunk)
        if count!=pin['bytes'] or value.hexdigest()!=pin['sha256']:
            raise ValueError('downloaded bytes differ from the reviewed pin')
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def signature(verifier, package, signature, certificate, identity, commit, run=subprocess.run):
    # Both the package and verifier are independently authenticated by their
    # reviewed SHA-256 pins before reaching this function. Cosign additionally
    # checks Fulcio identity, signing-time validity and Rekor transparency proof.
    # No ambient proxy, alternate root or ignore-tlog option is accepted.
    with tempfile.TemporaryDirectory(prefix='polygon-cosign-',dir='/run') as home:
        result=run([str(verifier),'verify-blob','--certificate',str(certificate),
                    '--signature',str(signature),'--certificate-identity',identity,
                    '--certificate-github-workflow-sha',commit,
                    '--certificate-oidc-issuer','https://token.actions.githubusercontent.com',str(package)],
                   stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False,timeout=180,
                   env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':home,'LANG':'C.UTF-8'})
        if result.returncode:
            raise ValueError('package Sigstore identity or transparency verification failed')


def extract(package, directory, binary, run=subprocess.run):
    if binary not in ('bor','heimdalld') or directory.is_symlink():
        raise ValueError('unsupported native release extraction')
    package_hash=digest(package)
    installed=directory/'usr/bin'/binary
    if directory.exists():
        receipt=json.loads((directory/'erpc-extraction.json').read_text())
        if (receipt.get('package')!=package_hash or installed.is_symlink()
                or not installed.is_file() or receipt.get('binary')!=digest(installed)):
            raise ValueError('existing native release is incomplete or belongs to another package')
        return installed
    stage=directory.with_name(directory.name+'.pending')
    if stage.is_symlink():
        raise ValueError('release staging cannot be a symlink')
    if stage.exists():
        shutil.rmtree(stage)  # Public artifact staging only, never node data or keys.
    stage.mkdir(mode=0o755);stage.chmod(0o755)
    try:
        # Extract without Debian maintainer scripts, which could otherwise
        # start listeners before firewall confirmation. Publish a receipt in
        # the same rename so an interrupted caller can safely retry.
        run(['dpkg-deb','--extract',str(package),str(stage)],check=True,
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=180,
            env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/root','LANG':'C.UTF-8'})
        for ancestor in (stage,stage/'usr',stage/'usr/bin'):
            if ancestor.is_symlink() or not ancestor.is_dir():raise ValueError('package executable ancestors must be real directories')
            ancestor.chmod(0o755)
        candidate=stage/'usr/bin'/binary
        if candidate.is_symlink() or not candidate.is_file():
            raise ValueError('reviewed package did not contain the expected regular binary')
        candidate.chmod(0o755)
        (stage/'erpc-extraction.json').write_text(json.dumps({'package':package_hash,'binary':digest(candidate)}))
        stage.rename(directory)
        return installed
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def native_version(binary, name, release, architecture, run=subprocess.run,client_config=None,temporary=tempfile.TemporaryDirectory):
    args=[str(binary),'version']+(['--long','--output','json'] if name=='heimdall' else [])
    with temporary(prefix='polygon-version-',dir='/run') as folder:
        if name=='heimdall':
            if not isinstance(client_config,str):raise ValueError('headless Heimdall client configuration is required')
            home=Path(folder)/'home';(home/'config').mkdir(parents=True)
            (home/'config/client.toml').write_text(client_config)
            args.extend(['--home',str(home)])
        result=run(args,check=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30,
                   env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':folder,'LANG':'C.UTF-8'})
    if len(result.stdout)>16384:raise ValueError('native version response exceeded its bound')
    if name=='heimdall':
        value=json.loads(result.stdout)
        observed,commit=value.get('version'),value.get('commit')
    else:
        lines=result.stdout.decode().strip().splitlines()
        if len(lines)!=2 or not lines[0].startswith('Version: ') or not lines[1].startswith('GitCommit:'):
            raise ValueError('native Bor version metadata was not recognized')
        observed,commit=lines[0].split(':',1)[1].strip(),lines[1].split(':',1)[1].strip()
    if observed!=release['tag'].removeprefix('v'):
        raise ValueError('native binary version differs from the reviewed target')
    # The pinned Bor ARM packaging workflow omits its GitCommit linker flag.
    # Its exact source commit is still required by Cosign's workflow-SHA check.
    if commit!=release['commit'] and not (name=='bor' and architecture=='aarch64' and commit==''):
        raise ValueError('native binary source commit differs from the reviewed target')
