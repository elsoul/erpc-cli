# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Validate every managed privileged destination before publication or use."""
import os
from pathlib import Path
import re
import stat
from erpc_monad_common import ROOT,CONFIG,HELPERS,RELEASES,atomic,fsync_dir,owned_directory,read,require,unique_json
from erpc_monad_entry import trusted_imports

SYSTEMD=Path('/etc/systemd/system')
FIREWALL=Path('/usr/local/lib/erpc/rpc-firewall.py')
UDEV=Path('/etc/udev/rules.d/99-zz-erpc-monad.rules')
SYSCTL=Path('/etc/sysctl.d/80-erpc-monad.conf')
UNITS=('erpc-monad-bft.service','erpc-monad-execution.service','erpc-monad-rpc.service',
       'erpc-monad-firewall.service','erpc-monad-memory.service','erpc-monad-gateway.service',
       'erpc-monad-cleanup.service','erpc-monad-cleanup.timer')
FILES=('catalog.json','control.py','cleanup.py','erpc_monad_accounts.py','erpc_monad_common.py',
       'erpc_monad_device.py','erpc_monad_entry.py','erpc_monad_identity.py','erpc_monad_namespace.py',
       'erpc_monad_observe.py','erpc_monad_package.py','erpc_monad_processes.py','erpc_monad_setup.py',
       'erpc_monad_state.py','erpc_monad_units.py')


def ancestry(path,public=False):
    for parent in (*reversed(path.parents),path):
        try:info=parent.lstat()
        except FileNotFoundError:return
        require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022 and (not public or info.st_mode&0o001),
                'privileged destination has foreign, writable or linked ancestors')


def file(path,private=False):
    ancestry(path.parent)
    try:info=path.lstat()
    except FileNotFoundError:return
    require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1
            and not info.st_mode&0o022 and (not private or stat.S_IMODE(info.st_mode)==0o600),
            'privileged file is indirect, shared, foreign or writable')


def library_alias(path):
    """Only the extractor's one-hop local regular-library aliases are valid."""
    parts=path.relative_to(RELEASES).parts
    final=(len(parts)==3 and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',parts[0]) and parts[1]=='lib')
    staged=(len(parts)==4 and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+\.partial',parts[0])
            and parts[1:3]==('payload','lib'))
    require(final or staged,'library alias is outside its qualified payload')
    name=os.readlink(path)
    require(re.fullmatch(r'lib[A-Za-z0-9_.+-]*\.so[A-Za-z0-9_.+-]*',path.name)
            and re.fullmatch(r'lib[A-Za-z0-9_.+-]*\.so[A-Za-z0-9_.+-]*',name),
            'library alias is not one local library filename')
    info=(path.parent/name).lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1
            and not info.st_mode&0o022,'library alias target is not a protected regular file')
    receipt=path.parent.parent/'receipt.json'
    if final or receipt.exists():
        file(receipt,private=True)
        expected=unique_json(read(receipt))
        require(expected['links'].get('lib/'+path.name)==name,'library alias differs from its extraction receipt')


def tree(path,release=False):
    ancestry(path)
    pending=[path] if path.exists() else []
    count=0
    while pending:
        for child in pending.pop().iterdir():
            count+=1;require(count<=20000,'managed namespace exceeds its bound')
            info=child.lstat()
            if release and stat.S_ISLNK(info.st_mode):
                require(info.st_uid==0,'foreign library alias')
                library_alias(child)
                continue
            require(info.st_uid==0 and not info.st_mode&0o022,'foreign or writable managed entry')
            if stat.S_ISDIR(info.st_mode):pending.append(child)
            else:require(stat.S_ISREG(info.st_mode) and info.st_nlink==1,'linked or special managed entry')


def paths(runtime=True):
    # Stop authority lives in original root receipts, approved releases and
    # owned units. A broken credential/config file must not prevent shutdown.
    for path in (ROOT,HELPERS,RELEASES,SYSTEMD):ancestry(path)
    ancestry(HELPERS,public=True)
    tree(HELPERS)
    if runtime:
        tree(CONFIG)
        tree(RELEASES,release=True)
        if CONFIG.exists():
            for path in CONFIG.iterdir():
                if path.name.startswith('identity') or path.name in ('monad-secp.cred','monad-bls.cred'):
                    file(path,private=True)
    if ROOT.exists():
        for path in ROOT.iterdir():
            if path.name=='data':continue  # Native-owned contents use descriptor-relative access.
            if path.name=='bootstrap':
                ancestry(path)
                if runtime:
                    for child in path.iterdir():
                        require(child.name in ('receipt.json','node.toml','forkpoint.toml','validators.toml')
                                or re.fullmatch(r'\.erpc-[a-f0-9]{32}',child.name),
                                'unknown cached bootstrap entry')
                        file(child,private=True)
            else:file(path,private=True)
    for name in UNITS:
        file(SYSTEMD/name)
        directory=SYSTEMD/(name+'.d');ancestry(directory)
        if directory.exists():
            for path in directory.iterdir():
                require(path.name in ('50-erpc-firewall-guard.conf','50-erpc-firewall-guard.conf.new'),
                        'unknown managed service override cannot be adopted')
                file(path)
    if runtime:
        for path in (FIREWALL,UDEV,SYSCTL):file(path)


def fresh():
    paths()
    for path in (ROOT,CONFIG,HELPERS,RELEASES):
        require(not path.exists() or not any(path.iterdir()),'unowned native artifacts cannot be adopted')
    for name in UNITS:
        for path in (SYSTEMD/name,SYSTEMD/(name+'.d')):
            require(not path.exists() and not path.is_symlink(),'unowned native boot artifacts cannot be adopted')
    for path in (UDEV,SYSCTL):
        require(not path.exists() and not path.is_symlink(),'unowned device or kernel policy cannot be adopted')


def publish(source):
    paths()
    ancestry(HELPERS,public=True)
    owned_directory(HELPERS.parent)
    if not HELPERS.exists():
        owned_directory(HELPERS,True)
        os.chmod(HELPERS,0o755);fsync_dir(HELPERS.parent)
    require(all(path.name in FILES or path.name=='__pycache__' for path in HELPERS.iterdir()),
            'unknown installed helper cannot be adopted')
    for name in FILES:
        raw=read(source/name)
        atomic(HELPERS/name,raw,0o644)
    fsync_dir(HELPERS)
    trusted_imports(str(HELPERS))
    for name in FILES:
        require(read(source/name)==read(HELPERS/name),'published controller differs from its sealed source')
