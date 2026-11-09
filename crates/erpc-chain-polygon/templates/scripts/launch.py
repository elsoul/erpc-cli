#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Fixed native launchers; release selection comes from sealed public metadata."""
import json
import importlib.util
import os
from pathlib import Path
import re
import sys



def metadata(expected,profile,binaries):
    value={'network':expected['network'],'binaries':{name:record['directory']+'/usr/bin/'+('bor' if name=='bor' else 'heimdalld') for name,record in binaries.items()}}
    if expected.get('role')=='validator':
        phase=profile.get('validator',{}).get('phase')
        if phase not in ('observing','active'):raise ValueError('validator native launch requires its explicit original phase')
        value.update(role='validator',phase=phase)
    return value


def environment(component,value):
    result={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8',
        'HOME':'/var/lib/polygon/'+component,'TMPDIR':'/run/polygon-'+component}
    if value.get('role')=='validator':
        # Go crypto/x509 must not additionally trust ambient issuer directories.
        directory=Path('/etc/polygon/empty-ca');info=directory.lstat()
        import stat
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or any(directory.iterdir()):
            raise ValueError('native private issuer directory is not the sealed empty authority')
        result.update(SSL_CERT_FILE='/etc/polygon/local-ca.pem',SSL_CERT_DIR=str(directory))
    return result


def arguments(component,metadata):
    if component not in ('bor','heimdall') or metadata.get('network') not in ('mainnet','amoy'):
        raise ValueError('unsupported managed native component')
    validator=metadata.get('role')=='validator'
    if (set(metadata)!=({'network','binaries','role','phase'} if validator else {'network','binaries'})
            or set(metadata.get('binaries',{}))!={'bor','heimdall'}
            or validator and metadata['phase'] not in ('observing','active')):
        raise ValueError('native launch metadata has an unknown role or phase')
    binary=metadata['binaries'][component]
    executable='bor' if component=='bor' else 'heimdalld'
    pattern='/opt/polygon/releases/'+component+r'-v[0-9]+\.[0-9]+\.[0-9]+-(x86_64|aarch64)/usr/bin/'+executable
    if not isinstance(binary,str) or not re.fullmatch(pattern,binary):
        raise ValueError('native executable is outside the reviewed release layout')
    if component=='bor':return [binary,'server','-config','/etc/polygon/bor.toml']
    args=[binary,'start','--home','/var/lib/polygon/heimdall','--chain',metadata['network'],'--rest-server']
    if not validator:return [*args,'--bridge=false']
    active=metadata['phase']=='active'
    return [*args,'--bridge='+str(active).lower(),*(['--all'] if active else []),
        '--app','/run/credentials/polygon-heimdall.service/native-app.toml']


def main():
    if len(sys.argv)!=2:raise ValueError('expected managed component')
    metadata=json.loads(Path('/etc/polygon/launch.json').read_text())
    spec=importlib.util.spec_from_file_location('polygon_runtime_accounts',Path(__file__).absolute().with_name('accounts.py'))
    authority=importlib.util.module_from_spec(spec);spec.loader.exec_module(authority)
    authority.runtime(sys.argv[1],metadata['network'])
    args=arguments(sys.argv[1],metadata)
    os.execve(args[0],args,environment(sys.argv[1],metadata))


if __name__=='__main__':
    try:main()
    except Exception:
        print('Polygon native launch metadata unavailable or invalid',file=sys.stderr)
        raise SystemExit(1)
