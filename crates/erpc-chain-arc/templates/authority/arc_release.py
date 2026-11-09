#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Qualified Arc archive, immutable native images and highest DB-opening source."""
import hashlib
import os
import re
import stat
import tarfile
from arc_files import digest, encoded, require

BINARIES = ('arc-node-execution', 'arc-node-consensus', 'arc-snapshots')
# Runtime/source qualification is deliberately closed. Future releases require a
# new carried catalog; generic metadata reservation does not authorize execution.
QUALIFIED_VERSION = 'v0.8.1'
QUALIFIED_COMMIT = 'ab09dbfd9553a7ad48f9c134ec5e808c36512c74'
QUALIFIED_ARCHIVES = {
    'x86_64-unknown-linux-gnu': '04127c5bb9488de743755b5089f4434c335cf349386d5d01347abfbc402d932a',
    'aarch64-unknown-linux-gnu': 'b6b4de979c457e0ff595a75b2987104f6b69d71492ca372ff35cff3648a99d69',
}


def executable(target):
    source(target)
    require(target['version'] == QUALIFIED_VERSION and target['commit'] == QUALIFIED_COMMIT and
            QUALIFIED_ARCHIVES.get(target['platform']) == target['archive_sha256'],
            'Arc native source is not in the carried execution catalog; existing history is retained')
    return target


def version(value):
    require(isinstance(value, str) and re.fullmatch(r'v(0|[1-9][0-9]{0,5})[.](0|[1-9][0-9]{0,5})[.](0|[1-9][0-9]{0,5})', value),
            'Arc authority requires a stable native release version')
    number = tuple(map(int, value[1:].split('.')))
    require(number >= (0, 8, 0), 'Arc source is below the qualified network fork floor')
    return number


def source(value):
    require(isinstance(value, dict) and set(value) == {'version', 'commit', 'archive_sha256', 'platform'},
            'invalid Arc release qualification')
    version(value['version'])
    require(isinstance(value['commit'], str) and re.fullmatch('[0-9a-f]{40}', value['commit']) and
            isinstance(value['archive_sha256'], str) and re.fullmatch('[0-9a-f]{64}', value['archive_sha256']) and
            value['platform'] in ('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu'),
            'Arc source hash or platform is invalid')
    return value


def identifier(target):
    return digest(encoded(source(target)))


def directory(target):
    return '/opt/arc/releases/' + identifier(target)


def file_hash(c, name):
    path = c.protected(name)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == c.owner and before.st_nlink == 1
                and not before.st_mode & 0o022 and before.st_size <= 1024 * 1024 * 1024,
                'Arc native image is unsafe or too large')
        hasher = hashlib.sha256()
        for block in iter(lambda: stream.read(1048576), b''):
            hasher.update(block)
        after = os.fstat(stream.fileno())
        named = path.lstat()
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) and
                (named.st_dev, named.st_ino) == (before.st_dev, before.st_ino),
                'Arc native image changed while hashed')
    return hasher.hexdigest()


def qualify(c, target):
    executable(target)
    root = directory(target)
    receipt_name = root + '/release.json'
    receipt = c.json(receipt_name)
    require(receipt.get('source') == target and set(receipt.get('images', {})) == set(BINARIES),
            'Arc native release receipt differs from the requested source')
    folder = c.protected(root, directory=True)
    require(set(os.listdir(folder)) == set(BINARIES) | {'release.json'},
            'Arc native release directory contains unknown files')
    for name, expected in receipt['images'].items():
        require(re.fullmatch('[0-9a-f]{64}', expected) and file_hash(c, root + '/' + name) == expected,
                'Arc native release image changed')
        require(folder.joinpath(name).stat().st_mode & 0o111 == 0o111,
                'Arc original release is not executable by its dedicated identity')
    return receipt


def install(c, target, archive):
    """Only the three flat regular entries emitted by upstream release-package.sh."""
    executable(target)
    require(archive == '/opt/arc/downloads/' + identifier(target) + '.tar.gz',
            'unexpected Arc archive staging path')
    require(file_hash(c, archive) == target['archive_sha256'], 'Arc release archive digest differs')
    root = directory(target)
    path = c.protected(root, missing=True, directory=True)
    if path.exists():
        return confirm_versions(c, target)
    staging = c.protected(root + '.staging', missing=True, directory=True)
    if staging.exists():
        require(set(os.listdir(staging)) <= set(BINARIES) | {'release.json', 'release.json.pending'},
                'unknown files in interrupted Arc archive extraction')
        for item in staging.iterdir():
            c.protected(root + '.staging/' + item.name)
            item.unlink()
        staging.rmdir()
        c.sync(staging.parent)
    c.mkdir(root + '.staging', mode=0o755)
    archive_path = c.protected(archive)
    images = {}
    with tarfile.open(archive_path, 'r:gz') as bundle:
        members = bundle.getmembers()
        require(len(members) == 3 and {item.name for item in members} == set(BINARIES)
                and all(item.isfile() and 0 < item.size <= 1024 * 1024 * 1024 for item in members),
                'Arc release archive has unknown, linked or oversized entries')
        for item in members:
            member = bundle.extractfile(item)
            require(member is not None, 'Arc archive member is unavailable')
            destination = staging / item.name
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o755)
            try:
                hasher, size = hashlib.sha256(), 0
                with member:
                    for block in iter(lambda: member.read(1048576), b''):
                        size += len(block)
                        require(size <= item.size, 'Arc archive member grew during extraction')
                        hasher.update(block)
                        view = memoryview(block)
                        while view:
                            count = os.write(fd, view)
                            require(count > 0, 'Arc image write made no progress')
                            view = view[count:]
                require(size == item.size, 'Arc archive member is truncated')
                os.fchmod(fd, 0o755)
                os.fsync(fd)
                images[item.name] = hasher.hexdigest()
            finally:
                os.close(fd)
    require(file_hash(c, archive) == target['archive_sha256'], 'Arc archive changed during extraction')
    receipt = {'source': target, 'images': images}
    c.write(root + '.staging/release.json', receipt, 0o644)
    c.sync(staging)
    os.rename(staging, path)
    c.sync(path.parent)
    return confirm_versions(c, target)


def confirm_versions(c, target):
    qualified = qualify(c, target)
    path = c.path(directory(target))
    # A visible rename is not proof that the original release directory was
    # durably published. Repeat its ancestry barrier before native execution.
    c.sync(path)
    for name in BINARIES:
        result = c.command(str(path / name), '--version', check=False)
        text = result.stdout.decode('utf-8', 'strict')
        require(result.returncode == 0 and target['version'] in text and target['commit'][:8] in text,
                'Arc native version command did not confirm the qualified release')
    return qualified


def floor(c, state, target, opening=False):
    source(target)
    previous = state.get('source_floor')
    if previous is not None:
        historical = previous.get('archive_sha256') is None
        if historical:
            require(state.get('migration_binding') and set(previous) == {'version', 'commit', 'archive_sha256', 'platform'} and
                    state.get('migration_evidence', {}).get('highest') == {key: previous[key] for key in ('version', 'commit')},
                    'unknown Arc historical source cannot be reconstructed')
            version(previous['version'])
        else:
            source(previous)
        require(version(target['version']) >= version(previous['version']),
                'Arc release is below the original highest database-opening source')
        if target['version'] == previous['version']:
            require(target['commit'] == previous['commit'] and target['platform'] == previous['platform'] and
                    (historical or target['archive_sha256'] == previous['archive_sha256']),
                    'same-version Arc source substitution is refused')
    else:
        require(state.get('bootstrap_complete') is not True and state.get('native_started') is not True,
                'original Arc source history is absent')
    if opening:
        state['source_floor'] = target
        c.save(state)
        c.sync(c.ROOT)
    return target
