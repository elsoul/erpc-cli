# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Digest-qualified package extraction without invoking distribution maintainer scripts."""
import hashlib
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import urllib.request
from erpc_monad_common import ENV, atomic, digest, execute, fsync_dir, json_bytes, read, require, unique_json

BINARIES = ('monad', 'monad-node', 'monad-rpc', 'monad-mpt', 'monad-keystore',
            'monad-sign-name-record', 'monad-debug-node')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('release/config redirects are refused')


def download(url, destination, expected_hash, size):
    require(url.startswith(('https://pkg.category.xyz/', 'https://bucket.monadinfra.com/')),
            'unqualified download origin')
    h, count = hashlib.sha256(), 0
    request = urllib.request.Request(url, headers={'User-Agent': 'erpc-node-controller'})
    with urllib.request.build_opener(NoRedirect).open(request, timeout=60) as response:
        require(response.status == 200 and response.geturl() == url, 'download origin changed')
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            while True:
                data = response.read(min(1024 * 1024, size - count + 1))
                if not data:
                    break
                count += len(data)
                require(count <= size, 'download exceeds qualified size')
                h.update(data)
                stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    require(count == size and h.hexdigest() == expected_hash, 'download size or SHA256 differs')
    fsync_dir(destination.parent)


def hash_file(path):
    h = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def extraction_path(name):
    p = PurePosixPath(name)
    require(not p.is_absolute() and '..' not in p.parts, 'unsafe archive member path')
    parts = tuple(part for part in p.parts if part != '.')
    if len(parts) == 4 and parts[:3] == ('usr', 'local', 'bin') and parts[3] in BINARIES:
        return Path('bin') / parts[3]
    if len(parts) == 4 and parts[:3] == ('usr', 'local', 'lib'):
        require(parts[3].startswith('lib') and '.so' in parts[3], 'unexpected private library')
        return Path('lib') / parts[3]
    return None


def extract(package, directory):
    """Only regular native binaries/libs and local library aliases are copied."""
    process = subprocess.Popen(['/usr/bin/dpkg-deb', '--fsys-tarfile', str(package)],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=ENV)
    seen, links, total = set(), [], 0
    try:
        with tarfile.open(fileobj=process.stdout, mode='r|') as archive:
            for member in archive:
                path = extraction_path(member.name)
                if path is None:
                    continue
                require(str(path) not in seen, 'duplicate native package member')
                seen.add(str(path))
                target = directory / path
                target.parent.mkdir(mode=0o755, exist_ok=True)
                if member.issym():
                    name = PurePosixPath(member.linkname)
                    require(path.parts[0] == 'lib' and len(name.parts) == 1 and name.name.startswith('lib'),
                            'library alias escapes private directory')
                    links.append((target, name.name))
                    continue
                require(member.isfile() and 0 < member.size <= 2_500_000_000, 'unsupported native package member')
                total += member.size
                require(total <= 5_000_000_000, 'expanded native payload exceeds limit')
                source = archive.extractfile(member)
                require(source is not None, 'native archive member unreadable')
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o555 if path.parts[0] == 'bin' else 0o444)
                with os.fdopen(fd, 'wb') as output:
                    shutil.copyfileobj(source, output, 1024 * 1024)
                    output.flush()
                    os.fchmod(output.fileno(), 0o555 if path.parts[0] == 'bin' else 0o444)
                    os.fsync(output.fileno())
        require(process.wait(timeout=30) == 0, 'native package extraction failed')
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
    for target, name in links:
        require((target.parent / name).is_file() and not (target.parent / name).is_symlink(),
                'library alias does not name an extracted regular file')
        target.symlink_to(name)
    require(all((directory / 'bin' / name).is_file() for name in BINARIES), 'package lacks required native tools')
    for parent in (directory / 'bin', directory / 'lib', directory):
        fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fchmod(fd, 0o755)
            os.fsync(fd)
        finally:
            os.close(fd)


def receipt(directory):
    files, links = {}, {}
    for category in ('bin', 'lib'):
        for path in (directory / category).iterdir():
            if path.is_symlink():
                links[str(path.relative_to(directory))] = os.readlink(path)
            else:
                files[str(path.relative_to(directory))] = hash_file(path)
    return {'files': files, 'links': links}


def check(directory, expected):
    require(directory.is_dir() and not directory.is_symlink()
            and directory.stat().st_uid == 0 and directory.stat().st_mode & 0o7777 == 0o755,
            'installed native payload is not traversable by its dedicated account')
    require(receipt(directory) == {key: expected[key] for key in ('files', 'links')},
            'installed binary/library payload differs from its receipt')
    for category in ('bin', 'lib'):
        parent = directory / category
        require(parent.is_dir() and not parent.is_symlink() and parent.stat().st_uid == 0
                and parent.stat().st_mode & 0o7777 == 0o755, 'unsafe installed native directory')
        for path in parent.iterdir():
            info = path.lstat()
            required_mode = 0o555 if category == 'bin' else 0o444
            require(info.st_uid == 0 and (path.is_symlink() or info.st_mode & 0o7777 == required_mode),
                    'installed native file has unsafe or inaccessible permissions')
