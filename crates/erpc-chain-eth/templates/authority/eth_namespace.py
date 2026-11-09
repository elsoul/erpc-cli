# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Protected original Ethereum namespaces and closed immutable helper publication."""
import os
from pathlib import Path
import re
import secrets
import stat
from eth_files import atomic,checked_file,digest,read,require,root_directory,synchronize
from eth_trust import trusted_release

SYSTEMD=Path('/etc/systemd/system')
COMMON_FIREWALL=Path('/usr/local/lib/erpc/rpc-firewall.py')
TUNING=(Path('/etc/sysctl.d/90-erpc-eth.conf'),Path('/etc/systemd/journald.conf.d/90-erpc-eth.conf'))
PROFILES={
    'rpc':{'config':Path('/etc/ethereum'),'opt':Path('/opt/ethereum'),
           'helpers':Path('/usr/local/lib/erpc/ethereum-rpc'),'firewall':Path('/etc/erpc/eth'),
           'units':('reth.service','lighthouse.service','reth-snapshot.service','erpc-eth-firewall.service')},
    'validator':{'config':Path('/etc/erpc/eth-validator'),'opt':Path('/opt/erpc-eth-validator'),
                 'helpers':Path('/usr/local/lib/erpc/ethereum-validator'),'firewall':None,
                 'units':('erpc-eth-execution.service','erpc-eth-engine-transport.service','erpc-eth-beacon.service','erpc-eth-validator.service','erpc-eth-peer.service','erpc-eth-peer.timer')},
}
RPC_FILES=('control.py','eth_files.py','eth_state.py','eth_accounts.py','eth_layout.py',
           'eth_namespace.py','eth_process.py','eth_units.py','eth_trust.py','network.yml','eth_migration.py','eth_artifacts.py','eth_source_floor.py')
VALIDATOR_FILES=RPC_FILES+('eth_validator_control.py','eth_validator_custody.py','eth_validator_history.py',
    'eth_validator_native.py','eth_validator_runtime.py','eth_validator_tls.py','eth_validator_transport.py',
    'eth_validator_units.py','eth_validator_peer.py','eth_validator_migration.py','eth_validator_engine.py','eth_validator_health.py','eth_validator_keys.py')
SOURCE=Path(__file__).absolute().parent


def file(path,missing=True,mode=None):
    parent=path.parent
    while not parent.exists() and not parent.is_symlink():parent=parent.parent
    fd=root_directory(parent);os.close(fd)
    try:info=path.lstat()
    except FileNotFoundError:
        require(missing,'original managed file is missing');return
    checked_file(info,mode=mode)


def directory(path,create=False,mode=0o755):
    if not create:
        while not path.exists() and not path.is_symlink():path=path.parent
    fd=root_directory(path,create,mode);os.close(fd)


def public_tree(path,current=None,profile=RPC_FILES):
    pending=[path];count=0
    while pending:
        selected=pending.pop();directory(selected)
        for child in selected.iterdir():
            count+=1;require(count<=100000,'managed runtime namespace exceeds its bound')
            info=child.lstat()
            if child.name in ('current','current.pending') and child.parent==path and current is not None:
                require(stat.S_ISLNK(info.st_mode) and info.st_uid==0,'unowned release selector')
                target=os.readlink(child)
                if current=='helper':
                    require(target.startswith(str(path/'releases')+'/') and re.fullmatch('[a-f0-9]{64}',Path(target).name),
                            'helper selector escapes immutable releases')
                    if child.name=='current':trusted_release(str(path),[list(profile)])
                    else:
                        target=Path(target);directory(target)
                        require(set(p.name for p in target.iterdir())==set(profile)
                                and digest(b''.join(read(target/name) for name in profile))==target.name,
                                'incomplete helper selector does not match its original bytes')
                else:
                    target=Path(target)
                    if not target.is_absolute():target=path/target
                    require(target.parent==path and re.fullmatch(r'reth-v[0-9A-Za-z.-]+--lighthouse-v[0-9A-Za-z.-]+',target.name),
                            'native selector escapes its qualified release pair')
                    directory(target)
            elif stat.S_ISDIR(info.st_mode):pending.append(child)
            else:file(child,missing=False)


def helper_files(role):
    require(role in PROFILES,'unknown original helper role')
    return RPC_FILES if role=='rpc' else VALIDATOR_FILES


def paths(role,runtime=True,create=False):
    require(role in PROFILES,'unknown Ethereum namespace role');selected=PROFILES[role]
    for key in ('config','opt','helpers','firewall'):
        path=selected[key]
        if path is None:continue
        directory(path,create,0o700 if key=='firewall' else 0o755)
        if path.exists() and runtime:
            public_tree(path,'helper' if key=='helpers' else 'native' if key=='opt' else None,helper_files(role))
    directory(SYSTEMD)
    for name in selected['units']:
        unit=SYSTEMD/name
        if unit.is_symlink():
            require(unit.lstat().st_uid==0 and os.readlink(unit)=='/dev/null','unknown unit selector cannot be adopted')
        else:file(unit)
        overrides=SYSTEMD/(name+'.d')
        if overrides.exists() or overrides.is_symlink():
            directory(overrides)
            for item in overrides.iterdir():
                require(role=='rpc' and item.name in ('50-erpc-firewall-guard.conf','50-erpc-firewall-guard.conf.new'),
                        'unknown Ethereum boot override cannot be adopted or ignored')
                file(item,missing=False)
    if role=='rpc':
        file(COMMON_FIREWALL)
        for path in TUNING:
            if create:directory(path.parent,True)
            file(path)
    return selected


def helper_digest(role='rpc'):return digest(b''.join(read(SOURCE/name) for name in helper_files(role)))


def publish(role):
    profile=helper_files(role);selected=paths(role);namespace=selected['helpers'];directory(namespace,True)
    releases=namespace/'releases';directory(releases,True)
    identity=helper_digest(role);destination=releases/identity
    if not destination.exists():
        stage=releases/('.pending-'+secrets.token_hex(16));stage.mkdir(mode=0o700)
        for name in profile:atomic(stage/name,read(SOURCE/name),0o444)
        require(digest(b''.join(read(stage/name) for name in profile))==identity,'helper stage differs from carried code')
        os.chmod(stage,0o755)
        descriptor=root_directory(stage)
        try:os.fsync(descriptor)
        finally:os.close(descriptor)
        os.rename(stage,destination)
        descriptor=root_directory(releases)
        try:os.fsync(descriptor)
        finally:os.close(descriptor)
    require(set(path.name for path in destination.iterdir())==set(profile)
            and digest(b''.join(read(destination/name) for name in profile))==identity,'immutable helper content changed')
    for name in profile:synchronize(destination/name)
    pending=namespace/'current.pending'
    if pending.exists() or pending.is_symlink():
        require(pending.is_symlink() and pending.lstat().st_uid==0,'another helper selection is indirect')
        previous=Path(os.readlink(pending))
        require(previous.parent==releases and re.fullmatch('[a-f0-9]{64}',previous.name)
                and set(path.name for path in previous.iterdir())==set(profile)
                and digest(b''.join(read(previous/name) for name in profile))==previous.name,
                'incomplete helper selection lacks original immutable bytes')
        if previous!=destination:
            # Finish only a fully authenticated original pointer first. A newer
            # CLI can then publish its own revision without deleting old code.
            os.replace(pending,namespace/'current')
            descriptor=root_directory(namespace)
            try:os.fsync(descriptor)
            finally:os.close(descriptor)
    if not pending.is_symlink():pending.symlink_to(destination)
    os.replace(pending,namespace/'current')
    descriptor=root_directory(namespace)
    try:os.fsync(descriptor)
    finally:os.close(descriptor)
    require(trusted_release(str(namespace),[list(profile)])==str(destination),'published helper selection differs')
    return identity
