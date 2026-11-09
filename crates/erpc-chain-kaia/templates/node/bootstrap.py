#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Bounded downloads and staged extraction of fixed official Kaia snapshots.

The official manifest only supplies MD5: it detects transfer corruption, not a
publisher signature. TLS and the reviewed embedded manifest values establish the
publisher trust boundary. No archive member can install code, keys, links or device nodes.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import urllib.parse
import urllib.request

HOSTS = {'kaia-chaindata-r2-logging.kaia-foundation.workers.dev'}
RESERVE = 200_000_000_000


class Refused(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Refused(message)


def destination(url):
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == 'https' and parsed.hostname in HOSTS and
            parsed.username is None and parsed.password is None and
            parsed.port in (None, 443) and not parsed.fragment,
            'download destination is outside the fixed official source boundary')
    return url


class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        return super().redirect_request(request, response, code, message, headers, destination(newurl))


def digest(path, algorithm):
    result = hashlib.new(algorithm, usedforsecurity=algorithm != 'md5')
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def durable_json(path, value):
    require(not path.is_symlink(), 'unsafe bootstrap receipt')
    temporary = path.with_suffix('.new')
    require(not temporary.is_symlink(), 'unsafe bootstrap receipt')
    temporary.unlink(missing_ok=True)
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream)
        stream.flush(); os.fsync(stream.fileno())
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_DIRECTORY)
    try: os.fsync(directory)
    finally: os.close(directory)


def download(url, path, expected, algorithm, limit):
    require(algorithm in ('md5', 'sha256') and re.fullmatch('[a-f0-9]{32}' if algorithm == 'md5' else '[a-f0-9]{64}', expected), 'invalid pinned download digest')
    require(type(limit) is int and limit > 0, 'invalid download size limit')
    require(not path.is_symlink() and (not path.exists() or path.is_file()), 'unsafe download destination')
    if path.exists():
        require(path.stat().st_size <= limit, 'cached download exceeds bound')
        if digest(path, algorithm) == expected:
            return path
        raise Refused('completed download differs from its catalog; preserve it for inspection')
    partial = path.with_suffix(path.suffix + '.partial')
    require(not partial.is_symlink() and (not partial.exists() or partial.is_file()), 'unsafe partial download')
    offset = partial.stat().st_size if partial.exists() else 0
    require(offset <= limit, 'partial download exceeds bound')
    # A connection may have ended after the final byte but before atomic rename.
    if offset == limit and digest(partial, algorithm) == expected:
        os.replace(partial, path)
        return path
    # The official Cloudflare object endpoint requires an explicit application
    # identity; generic Python-urllib is rejected by its browser-integrity rule.
    headers = {'User-Agent': 'erpc-cli/0.0.1'}
    if offset: headers['Range'] = 'bytes=' + str(offset) + '-'
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), Redirect())
    with opener.open(urllib.request.Request(destination(url), headers=headers), timeout=30) as response:
        require(response.status in (200, 206), 'snapshot server did not return data')
        if response.status == 206:
            match = re.fullmatch(r'bytes ([0-9]+)-([0-9]+)/([0-9]+)', response.headers.get('Content-Range', ''))
            require(match is not None and int(match[1]) == offset and int(match[2]) + 1 == int(match[3]) <= limit, 'invalid resumed download range')
            total = int(match[3])
        else:
            offset = 0
            length = response.headers.get('Content-Length', '')
            require(length.isdigit() and 0 < int(length) <= limit, 'unbounded download response')
            total = int(length)
        require(shutil.disk_usage(path.parent).free >= total - offset + RESERVE, 'insufficient download headroom')
        fd = os.open(partial, os.O_CREAT | os.O_NOFOLLOW | os.O_WRONLY | (os.O_APPEND if offset else os.O_TRUNC), 0o600)
        with os.fdopen(fd, 'ab' if offset else 'wb') as stream:
            size = offset
            for chunk in iter(lambda: response.read(1024 * 1024), b''):
                size += len(chunk)
                require(size <= total, 'download exceeded advertised size')
                stream.write(chunk)
            stream.flush(); os.fsync(stream.fileno())
        require(size == total and digest(partial, algorithm) == expected, 'download incomplete or checksum differs; no archive extracted')
    os.replace(partial, path)
    return path


def member_path(member):
    require(not member.name.startswith('/') and '\\' not in member.name and '\x00' not in member.name, 'unsafe archive path')
    parts = PurePosixPath(member.name).parts
    require('..' not in parts and len(parts) <= 32, 'unsafe archive path')
    if not parts:
        require(member.isdir(), 'snapshot root is not a directory')
        return None
    require(parts[0] == 'klay', 'snapshot contains data outside the declared instance')
    relative = parts
    require(len(relative) <= 1 or relative[1] == 'chaindata', 'snapshot contains non-database data')
    require(member.isdir() or member.isfile(), 'snapshot links, devices and special entries are refused')
    return Path(*relative)


def extract_stream(stream, stage, ceiling):
    count = 0
    expanded = 0
    with tarfile.open(fileobj=stream, mode='r|') as archive:
        for member in archive:
            relative = member_path(member)
            if relative is None:
                continue
            target = stage / relative
            require(not target.is_symlink(), 'unsafe existing snapshot entry')
            if member.isdir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
                continue
            require(type(member.size) is int and 0 <= member.size <= ceiling, 'snapshot entry exceeds deployment capacity')
            expanded += member.size
            require(expanded <= ceiling, 'snapshot exceeds declared uncompressed size')
            require(shutil.disk_usage(stage).free >= member.size + RESERVE, 'insufficient extraction headroom')
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            source = archive.extractfile(member)
            require(source is not None, 'snapshot regular file is unreadable')
            fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY, 0o600)
            with os.fdopen(fd, 'wb') as output:
                remaining = member.size
                while remaining:
                    chunk = source.read(min(1024 * 1024, remaining))
                    require(bool(chunk), 'snapshot file was truncated')
                    output.write(chunk); remaining -= len(chunk)
                output.flush(); os.fsync(output.fileno())
            count += 1
    require(count > 0, 'snapshot archive contains no database files')


def extract(archive, stage, ceiling):
    process = subprocess.Popen(['/usr/bin/zstd', '-d', '-c', '--', str(archive)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'})
    try:
        extract_stream(process.stdout, stage, ceiling)
        require(process.wait(timeout=30) == 0, 'snapshot decompression failed')
    finally:
        if process.poll() is None:
            process.kill(); process.wait()
        process.stdout.close()


def bootstrap(root, owner, snapshot, uid, gid, ceiling):
    """Only publish a complete staging database. Existing databases are never reset."""
    require(all(type(v) is int and 100 <= v <= 65534 for v in (uid, gid)), 'invalid database account')
    data, stage, cache = root / 'data', root / 'snapshot-stage', root / 'snapshot-downloads'
    receipt = root / 'bootstrap.json'
    identity = {'owner': owner, 'snapshot': snapshot['name'], 'digest': snapshot['md5'], 'bytes': snapshot['bytes']}
    for path in (data, data / 'klay', data / 'klay/chaindata', stage, cache, receipt):
        require(not path.is_symlink(), 'unsafe bootstrap path')
    if receipt.exists():
        record = json.loads(receipt.read_text())
        require(record.get('identity') == identity and record.get('phase') in ('extracting', 'publish-ready', 'complete'), 'bootstrap ownership differs')
    else:
        require(not stage.exists() and not (data / 'klay').exists(), 'existing database cannot be adopted as a new snapshot')
        record = {'identity': identity, 'phase': 'extracting'}
        durable_json(receipt, record)
    if record['phase'] == 'complete':
        require((data / 'klay/chaindata').is_dir(), 'completed bootstrap database is missing')
        return
    if record['phase'] == 'extracting':
        require(not (data / 'klay').exists(), 'incomplete bootstrap cannot overwrite a database')
        # Staging belongs only to this uncommitted extraction; published data is
        # never the cleanup target. Downloaded verified archives remain reusable.
        if stage.exists(): shutil.rmtree(stage)
        stage.mkdir(mode=0o700)
        cache.mkdir(mode=0o700, exist_ok=True)
        name = snapshot['name']
        require(re.fullmatch('kaia-(?:mainnet|kairos)-pruning-chaindata-[0-9]{14}\\.tar\\.zst', name), 'invalid catalog archive name')
        archive = download(snapshot['url'], cache / name, snapshot['md5'], 'md5', snapshot['bytes'])
        require(archive.stat().st_size == snapshot['bytes'], 'snapshot compressed size differs')
        extract(archive, stage, snapshot['uncompressed_bytes'])
        require((stage / 'klay/chaindata').is_dir(), 'snapshot database directory is missing')
        for parent, dirs, files in os.walk(stage):
            for name in [*dirs, *files]:
                path = Path(parent) / name
                require(not path.is_symlink(), 'unsafe extracted database')
                os.chown(path, uid, gid)
        for parent, _, _ in os.walk(stage, topdown=False):
            fd = os.open(parent, os.O_DIRECTORY)
            try: os.fsync(fd)
            finally: os.close(fd)
        record['phase'] = 'publish-ready'; durable_json(receipt, record)
    data.mkdir(mode=0o700, exist_ok=True)
    require(data.stat().st_dev == stage.parent.stat().st_dev, 'snapshot publication requires one filesystem')
    if (stage / 'klay').exists():
        require(not (data / 'klay').exists(), 'bootstrap target already exists')
        os.rename(stage / 'klay', data / 'klay')
    require((data / 'klay/chaindata').is_dir(), 'published database is missing')
    fd = os.open(data, os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)
    record['phase'] = 'complete'; durable_json(receipt, record)
