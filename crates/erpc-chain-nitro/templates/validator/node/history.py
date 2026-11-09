# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Retained native DB identity before the first original-wallet activation.

Nitro5f02f3f opens arbitrumdata/l2chaindata/wasm under the geth instance path
chain/nitro (geth30456d2 node.Config.ResolvePath). DataPoster stores its queue in
arbitrumdata. Pebble1.1.5 selects its manifest by the highest manifest marker;
older formats use CURRENT. We retain directory identity and a lower bound on
that counter, not a claim of cryptographic backup or corruption recovery.
"""
import hashlib
import os
import re
import stat
import host
import volumes
from storage import require, sync_directory, synchronize

DBS = ('arbitrumdata', 'l2chaindata', 'wasm')


def info(path, account, kind, device=None):
    value = path.lstat()
    require(kind(value.st_mode) and value.st_uid == account['uid'] and value.st_gid == account['gid']
            and not value.st_mode & 0o022, 'original native history path or numeric ownership changed')
    require(device is None or value.st_dev == device, 'native history crosses the original DATA filesystem')
    if stat.S_ISREG(value.st_mode): require(value.st_nlink == 1, 'original native history file has aliases')
    return value


def file(path, account, maximum=4096, device=None):
    before = info(path, account, stat.S_ISREG, device)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as source:
        current = os.fstat(source.fileno())
        require((current.st_dev, current.st_ino) == (before.st_dev, before.st_ino), 'native history changed during inspection')
        value = source.read(maximum+1)
        require(len(value) <= maximum, 'native identity metadata exceeds its bound')
    return value


def database(path, account, device):
    value = info(path, account, stat.S_ISDIR, device)
    entries = list(path.iterdir()); require(len(entries) <= 1000000, 'native database namespace exceeds its bound')
    markers = []
    for entry in entries:
        if not entry.name.startswith('marker.manifest.'): continue
        match = re.fullmatch(r'marker\.manifest\.([0-9]{1,20})\.(MANIFEST-[0-9]{1,20})', entry.name)
        require(match and 0 < int(match[1]) < 2**64, 'native manifest selector is malformed')
        info(entry, account, stat.S_ISREG, device); markers.append((int(match[1]), match[2]))
    if markers:
        sequence = max(row[0] for row in markers)
        selected = {name for counter, name in markers if counter == sequence}
        require(len(selected) == 1, 'native manifest selectors disagree')
        name = selected.pop(); format_name = 'pebble-marker'
    else:
        raw = file(path/'CURRENT', account, 128, device)
        require(re.fullmatch(b'MANIFEST-[0-9]{1,20}\n', raw), 'native current manifest is unavailable')
        name = raw.decode().strip(); sequence = int(name.split('-')[1]); format_name = 'current'
    manifest = info(path/name, account, stat.S_ISREG, device)
    require(manifest.st_size > 0, 'native manifest is empty; automatic database recreation is forbidden')
    return {'inode': value.st_ino, 'format': format_name, 'minimum_sequence': sequence}


def inspect(account, device=None):
    before = info(host.DATA, account, stat.S_ISDIR, device)
    device = before.st_dev
    instance=host.DATA/'chain/nitro'
    freezer=instance/'l2chaindata/ancient/chain-tip-block-records'
    paths = [host.DATA, host.DATA/'chain', instance, instance/'l2chaindata/ancient', freezer]
    anchors = []
    for path in paths:
        value = info(path, account, stat.S_ISDIR, device)
        anchors.append(volumes.stable(value))
    dbs = {name: database(instance/name, account, device) for name in DBS}
    # Native tail pruning may replace index files, so preserve the freezer
    # directory identity and required original-owned tables, not file inodes.
    require(info(freezer/'records.cidx',account,stat.S_ISREG,device).st_size>=6
            and info(freezer/'records.meta',account,stat.S_ISREG,device).st_size>0,
            'persistent chain-tip validation recordings are missing')
    # These secrets remain in the original private data directory. Only hashes
    # enter root receipts; no native key generation/export occurs here.
    identities = {}
    for relative in ('chain/nodekey', 'jwtsecret'):
        raw = file(host.DATA/relative, account, 4096, device)
        require(raw and len(raw) <= 4096, 'native persistent identity is absent')
        identities[relative] = hashlib.sha256(raw).hexdigest()
    after = info(host.DATA, account, stat.S_ISDIR, device)
    require((before.st_dev,before.st_ino)==(after.st_dev,after.st_ino),'native DATA changed during history inspection')
    return {'anchors': anchors, 'databases': dbs, 'identities': identities}


def matches(original, current):
    require(set(original) == {'anchors', 'databases', 'identities'} and
            isinstance(original['anchors'],list) and len(original['anchors'])==len(current['anchors']) and
            [volumes.inode(value) for value in original['anchors']]==[volumes.inode(value) for value in current['anchors']] and
            original['identities'] == current['identities'] and set(original['databases']) == set(DBS),
            'original native data or identities were replaced')
    for name in DBS:
        old, new = original['databases'][name], current['databases'][name]
        require(set(old) in ({'inode','format','minimum_sequence'}, {'device','inode','format','minimum_sequence'}) and
                type(old['inode']) is int and old['inode']>0 and old['inode']==new['inode'] and
                old['format']==new['format'] and type(old['minimum_sequence']) is int and
                new['minimum_sequence']>=old['minimum_sequence'],
                'native signing database was replaced or its retained manifest regressed')
        if 'device' in old: require(type(old['device']) is int and old['device']>=0,'invalid legacy database observation')


def current_history(state, expected, account):
    require((state.root/'data.json').exists(),'original DATA receipt is missing')
    first=volumes.verify(state,expected)
    current=inspect(account,first['data']['device'])
    require(volumes.verify(state,expected)==first,'filesystem changed during native history qualification')
    return current


def verify(state, expected, account, quiet):
    state.owner(expected); quiet()
    record = state.get('signer-activated.json')
    require(record.get('contract') == expected and record.get('account') == account,
            'original signing-history receipt differs')
    current = current_history(state,expected,account); matches(record['history'], current); quiet()
    return record


def activate(state, expected, account, origin, quiet, validated):
    """Only after a proved healthy observer is drained; caller rechecks admission."""
    state.owner(expected); quiet()
    require(validated.get('phase') == 'observing' and validated.get('local_validation_ready') is True
            and validated.get('validated_block_hash') and validated.get('wasm_module_root'),
            'first signer activation requires original healthy native WASM observation')
    current = current_history(state,expected,account)
    path = state.root/'signer-activated.json'
    if path.exists():
        original = verify(state, expected, account, quiet)
        require(original['origin'] == origin, 'original signer custody differs'); synchronize(path)
        return original
    for relative in ('', 'chain', 'chain/nitro', *('chain/nitro/'+name for name in DBS),
                     'chain/nitro/l2chaindata/ancient','chain/nitro/l2chaindata/ancient/chain-tip-block-records'):
        sync_directory(host.DATA/relative)
    quiet()
    record = {'contract': expected, 'account': account, 'origin': origin, 'history': current,
              'observer': validated}
    state.put('signer-activated.json', record)
    return verify(state, expected, account, quiet)


def retain(state, expected, account, quiet):
    original = verify(state, expected, account, quiet)
    current = current_history(state,expected,account); matches(original['history'], current); quiet()
    state.put('signer-activated.json', dict(original, history=current))
    return current
