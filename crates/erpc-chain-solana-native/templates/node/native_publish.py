# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Copy a quiescent unprivileged build into fresh root-owned executable inodes.

This publishes a candidate only. Runtime approval, credential loading and service
startup are separate operations bound to the still-current deployment intent.
"""
import hashlib
import os
from pathlib import Path
import re
import secrets
import stat
import struct
from native_files import atomic, digest_file, encoded, json_value, read, require, root_directory, sync_directory
from native_state import token

RELEASES = Path('/opt/erpc/solana/releases')
MAX_BINARY = 3_000_000_000


def qualified_result(work, public, catalog, builder):
    require(builder != 0, 'compiler account must be unprivileged')
    for path in (work, work / 'output', work / 'output/bin'):
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == builder and not info.st_mode & 0o7022,
                'build output directory is not owned by its isolated compiler')
    result = json_value(read(work / 'build-result.json', 65536, builder))
    profile = catalog['networks'][public['network']]
    source = {'commit': profile['commit'], 'cargo_lock_sha256': profile['cargo_lock_sha256'], 'rust': profile['rust']}
    require(set(result) == {'request', 'source', 'files'} and result['request'] == public and result['source'] == source,
            'compiler receipt belongs to another source or intent')
    files = result['files']
    require(isinstance(files, dict) and set(files) == set(catalog['publish_binaries']), 'compiler artifact set differs')
    for name, record in files.items():
        require(re.fullmatch('[a-z][a-z0-9-]{0,63}', name) and isinstance(record, dict)
                and set(record) == {'size', 'sha256'} and type(record['size']) is int
                and 64 <= record['size'] <= MAX_BINARY and isinstance(record['sha256'], str)
                and re.fullmatch('[a-f0-9]{64}', record['sha256']), 'invalid compiler artifact receipt')
    return result


def copy_binary(source, destination, expected, builder):
    """Do not chmod/chown the builder's inode: an old open writer must not survive."""
    source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(source_fd, 'rb') as incoming:
        before = os.fstat(incoming.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == builder and before.st_nlink == 1
                and not before.st_mode & 0o7022 and before.st_size == expected['size'], 'compiler candidate ownership or size differs')
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, 'wb') as outgoing:
            header = incoming.read(64)
            require(len(header) == 64 and header[:7] == b'\x7fELF\x02\x01\x01'
                    and struct.unpack_from('<HH', header, 16) in ((2, 62), (3, 62)),
                    'compiler candidate is not a Linux x86-64 ELF executable')
            digest, count = hashlib.sha256(header), len(header)
            outgoing.write(header)
            for chunk in iter(lambda: incoming.read(1048576), b''):
                count += len(chunk)
                require(count <= expected['size'], 'compiler candidate grew during publication')
                digest.update(chunk)
                outgoing.write(chunk)
            after = os.fstat(incoming.fileno())
            require(count == expected['size'] and digest.hexdigest() == expected['sha256']
                    and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                    == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                    'compiler candidate changed or differs from its receipt')
            os.fchmod(outgoing.fileno(), 0o555)
            os.fsync(outgoing.fileno())


def verify(directory, expected):
    root_directory(directory)
    require(set(path.name for path in directory.iterdir()) == {'receipt.json', 'bin'}, 'published release has unexpected entries')
    root_directory(directory / 'bin')
    require(json_value(read(directory / 'receipt.json', 65536)) == expected, 'published release receipt differs')
    require(set(path.name for path in (directory / 'bin').iterdir()) == set(expected['files']), 'published executable set differs')
    for name, record in expected['files'].items():
        path = directory / 'bin' / name
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and info.st_mode & 0o7777 == 0o555 and info.st_size == record['size']
                and digest_file(path, MAX_BINARY) == record['sha256'], 'published executable differs')
    return expected


def publish(state, contract, intent, work, public, catalog, builder, quiescent):
    """Root caller holds the operation lock and has stopped both exact build units."""
    token(intent)
    pending = state.current(contract, intent)
    require(public['intent'] == intent and public['network'] == contract['network']
            and all(pending['target'][key] == public[key] for key in ('network', 'commit', 'version', 'catalog_sha256')),
            'publication does not match the current deployment')
    quiescent()
    root_directory(work.parent)
    result = qualified_result(work, public, catalog, builder)
    receipt = dict(result, schema=1)
    root_directory(RELEASES, create=True)
    destination = RELEASES / intent
    if destination.exists() or destination.is_symlink():
        verify(destination, receipt)
        sync_directory(destination / 'bin')
        sync_directory(destination)
        sync_directory(RELEASES)
        state.current(contract, intent)
        return receipt
    stage = RELEASES / ('.stage-' + secrets.token_hex(16))
    stage.mkdir(mode=0o700)
    (stage / 'bin').mkdir(mode=0o700)
    # Failed stages remain private for explicit recovery; they are never runtime
    # releases and are never reused as a source or recursively followed/deleted.
    for name, expected in result['files'].items():
        copy_binary(work / 'output/bin' / name, stage / 'bin' / name, expected, builder)
    atomic(stage / 'receipt.json', encoded(receipt), 0o444)
    os.chmod(stage / 'bin', 0o755)
    sync_directory(stage / 'bin')
    quiescent()
    state.current(contract, intent)
    os.chmod(stage, 0o755)
    sync_directory(stage)
    os.rename(stage, destination)
    sync_directory(RELEASES)
    return verify(destination, receipt)
