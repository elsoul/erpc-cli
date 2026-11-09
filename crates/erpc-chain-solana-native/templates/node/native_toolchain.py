# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Extract hash-qualified Rust components without running installers or rustup."""
import hashlib
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import tarfile
import urllib.request
from urllib.parse import urlsplit
from native_files import atomic, digest_file, encoded, json_value, read, require, root_directory, sync_directory

TARGET = 'x86_64-unknown-linux-gnu'
MAX_EXPANDED = 2_000_000_000


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('compiler redirects are refused')


def download(pin, path):
    url = urlsplit(pin['url'])
    require(url.scheme == 'https' and url.netloc == 'static.rust-lang.org'
            and not url.query and not url.fragment and url.path.startswith('/dist/'),
            'compiler origin differs from its qualified publisher')
    maximum = pin['maximum_bytes']
    require(type(maximum) is int and type(pin['size']) is int
            and 0 < pin['size'] <= maximum <= 536870912, 'invalid compiler artifact bound')
    request = urllib.request.Request(pin['url'], headers={'Accept-Encoding': 'identity', 'User-Agent': 'erpc-node-builder'})
    count, digest = 0, hashlib.sha256()
    with urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect).open(request, timeout=60) as response:
        require(response.status == 200 and response.geturl() == pin['url']
                and response.headers.get('Content-Encoding', 'identity') == 'identity', 'compiler transport differs')
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            while True:
                chunk = response.read(min(1048576, maximum - count + 1))
                if not chunk:
                    break
                count += len(chunk)
                require(count <= maximum, 'compiler download exceeds its bound')
                digest.update(chunk)
                stream.write(chunk)
            require(count == pin['size'] and digest.hexdigest() == pin['sha256'],
                    'compiler artifact size or SHA256 differs')
            stream.flush()
            os.fsync(stream.fileno())
    sync_directory(path.parent)


def extract(archive, component, version, destination):
    require(component in ('rustc', 'cargo', 'rust-std'), 'unknown compiler component')
    top = component + '-' + version + '-' + TARGET
    inner = component if component != 'rust-std' else 'rust-std-' + TARGET
    seen, published, expanded, entries = set(), {}, 0, 0
    # Digest qualification happens before this function is called. The current
    # official components contain only regular files/directories, never links.
    with tarfile.open(archive, mode='r|xz') as tar:
        for member in tar:
            entries += 1
            path = PurePosixPath(member.name)
            require(entries <= 100000 and len(member.name) <= 1024 and not path.is_absolute()
                    and '..' not in path.parts and path.parts and path.parts[0] == top,
                    'unsafe compiler member path')
            require(member.isdir() or member.isfile(), 'compiler links and special files are refused')
            expanded += member.size
            require(0 <= member.size <= MAX_EXPANDED and expanded <= MAX_EXPANDED,
                    'expanded compiler artifact exceeds its bound')
            canonical = str(path)
            require(canonical not in seen, 'duplicate compiler archive path')
            seen.add(canonical)
            if member.isdir() or len(path.parts) < 3 or path.parts[1] != inner:
                continue
            relative = Path(*path.parts[2:])
            if relative == Path('manifest.in'):
                continue
            require(relative.parts[0] in ('bin', 'lib', 'libexec', 'share', 'etc'), 'unexpected component payload')
            target = destination / relative
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            source = tar.extractfile(member)
            require(source is not None, 'compiler member cannot be read')
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            mode = 0o555 if member.mode & 0o111 else 0o444
            digest, count = hashlib.sha256(), 0
            with os.fdopen(fd, 'wb') as stream:
                while True:
                    chunk = source.read(1048576)
                    if not chunk:
                        break
                    count += len(chunk)
                    require(count <= member.size, 'compiler member grew beyond its declared size')
                    stream.write(chunk)
                    digest.update(chunk)
                require(count == member.size, 'truncated compiler member')
                stream.flush()
                os.fchmod(stream.fileno(), mode)
                os.fsync(stream.fileno())
            published[str(relative)] = {'sha256': digest.hexdigest(), 'mode': mode, 'size': count}
    require(published, 'compiler component contains no payload')
    return published


def seal_directories(destination):
    directories = [destination]
    for root, names, _ in os.walk(destination, followlinks=False):
        for name in names:
            child = Path(root) / name
            require(not child.is_symlink(), 'compiler directory redirected')
            directories.append(child)
    for path in reversed(directories):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fchmod(fd, 0o755)
            os.fsync(fd)
        finally:
            os.close(fd)


def verify(destination, profile):
    root_directory(destination)
    receipt = json_value(read(destination / 'receipt.json', 1048576))
    require(receipt['rust'] == profile['rust'] and receipt['components'] == profile['components'],
            'installed compiler receipt differs from its qualified profile')
    seen = set()
    for root, directories, names in os.walk(destination, followlinks=False):
        info = Path(root).lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_mode & 0o7777 == 0o755,
                'compiler directory has unsafe reader permissions')
        for name in directories:
            require(not (Path(root) / name).is_symlink(), 'compiler directory cannot be a link')
        for name in names:
            path = Path(root) / name
            if path == destination / 'receipt.json':
                continue
            relative = str(path.relative_to(destination))
            require(relative in receipt['files'], 'unrecorded compiler file')
            expected = receipt['files'][relative]
            require(expected['mode'] in (0o444, 0o555), 'invalid compiler receipt permissions')
            info = path.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                    and info.st_mode & 0o7777 == expected['mode'] and info.st_size == expected['size'],
                    'compiler file ownership, permissions or size changed')
            require(digest_file(path, MAX_EXPANDED) == expected['sha256'], 'compiler file digest changed')
            seen.add(relative)
    require(seen == set(receipt['files']), 'compiler payload is incomplete')
    return receipt


def install(profile, directory):
    """The root controller serializes this cache; it is never writable by builder/node."""
    root_directory(directory, create=True)
    version = profile['rust']
    require(version in ('1.97.1', '1.98.1'), 'unqualified compiler version')
    destination, stage = directory / version, directory / (version + '.partial')
    if destination.exists() or destination.is_symlink():
        receipt = verify(destination, profile)
        sync_directory(destination)
        sync_directory(directory)
        return receipt
    if stage.exists() or stage.is_symlink():
        root_directory(stage)
        shutil.rmtree(stage)
        sync_directory(directory)
    require(shutil.disk_usage(directory).free >= 8_000_000_000,
            'compiler staging needs eight GB of free system storage')
    stage.mkdir(mode=0o700)
    payload = stage / 'payload'
    payload.mkdir(mode=0o700)
    files = {}
    for component in ('rustc', 'cargo', 'rust-std'):
        pin = profile['components'][component]
        archive = stage / (component + '.tar.xz')
        download(pin, archive)
        require(digest_file(archive, pin['maximum_bytes']) == pin['sha256'], 'downloaded compiler artifact changed')
        published = extract(archive, component, version, payload)
        require(not set(files).intersection(published), 'compiler components contain conflicting files')
        files.update(published)
    require(all(name in files for name in ('bin/rustc', 'bin/cargo')),
            'compiler package lacks required executable')
    receipt = {'rust': version, 'components': profile['components'], 'files': files}
    atomic(payload / 'receipt.json', encoded(receipt))
    seal_directories(payload)
    os.rename(payload, destination)
    sync_directory(directory)
    shutil.rmtree(stage)
    sync_directory(directory)
    return verify(destination, profile)
