# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Resumable copy into private staging; the caller must fence original writers.

This module neither starts a runtime nor grants its UID access to copied data.
The migration controller must authenticate mounts/NSS and provide a revocable
original-operation gate. File receipts alone do not authorize a migration.
"""
import fcntl
import hashlib
import os
from pathlib import Path
import re
import stat
from native_files import atomic, encoded, json_value, read, require, sync_directory, sync_file

ROOT_UID = 0
CHUNK = 1024 * 1024
MAX_ENTRIES = 250000
MAX_DEPTH = 64
FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


def fingerprint(info):
    # Device numbers may change across boots; the caller binds filesystem UUIDs.
    return {name: getattr(info, 'st_' + name) for name in
            ('ino', 'uid', 'gid', 'mode', 'nlink', 'size', 'mtime_ns', 'ctime_ns')}


def root_fd(path, owner, private=False, durable=False):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'invalid copy root')
    current = os.open('/', FLAGS | os.O_DIRECTORY)
    try:
        for component in path.parts[1:]:
            child = os.open(component, FLAGS | os.O_DIRECTORY, dir_fd=current)
            try:
                info = os.fstat(child)
                require(info.st_uid in (0, ROOT_UID, owner) and not info.st_mode & 0o022,
                        'copy root has an untrusted ancestor')
                if durable:
                    os.fsync(child); os.fsync(current)
            except BaseException:
                os.close(child); raise
            os.close(current); current = child
        info = os.fstat(current)
        require(info.st_uid == owner and (not private or info.st_mode & 0o7777 == 0o700),
                'copy root ownership or private mode changed')
        return current
    except BaseException:
        os.close(current); raise


def at(directory, name):
    try: return os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError: return None


class Copy:
    def __init__(self, source, payload, scratch, journal, binding, gate):
        require(isinstance(binding, dict) and set(binding) == {
            'intent', 'source_uuid', 'source_inode', 'source_uid', 'source_gid',
            'target_uuid', 'payload_inode', 'scratch_inode', 'history_sha256'},
            'invalid original copy binding')
        require(isinstance(binding['intent'], str) and re.fullmatch('[a-f0-9]{32}', binding['intent'])
                and isinstance(binding['history_sha256'], str)
                and re.fullmatch('[a-f0-9]{64}', binding['history_sha256']), 'invalid copy operation identity')
        for key in ('source_uuid', 'target_uuid'):
            require(isinstance(binding[key], str) and re.fullmatch('[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}', binding[key]),
                    'invalid original copy filesystem UUID')
        require(binding['source_uuid'] != binding['target_uuid'], 'copy requires a distinct target filesystem')
        require(all(type(binding[key]) is int and binding[key] > 0 for key in
                    ('source_inode', 'source_uid', 'source_gid', 'payload_inode', 'scratch_inode')),
                'invalid original copy account or inode')
        self.binding, self.gate = binding, gate
        self.source, self.payload, self.scratch, self.journal = map(Path, (source, payload, scratch, journal))
        paths = (self.source, self.payload, self.scratch, self.journal)
        require(len(set(paths)) == 4 and all(path.is_absolute() and '..' not in path.parts for path in paths)
                and not any(left in right.parents for left in paths for right in paths if left != right),
                'copy roots cannot overlap or nest')
        self.count = 0

    def source_info(self, info, device):
        require(info.st_dev == device and info.st_uid == self.binding['source_uid']
                and info.st_gid == self.binding['source_gid'] and not info.st_mode & 0o6022
                and (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)),
                'original copy entry has another device, owner or file type')
        return fingerprint(info)

    def private_info(self, info, directory=False, links=1):
        require(info is not None and info.st_uid == ROOT_UID
                and (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
                and info.st_mode & 0o7777 == (0o700 if directory else 0o600)
                and (directory or info.st_nlink == links), 'private copy staging entry changed')
        return info

    def record_path(self, parts):
        key = hashlib.sha256(encoded(list(parts))).hexdigest()
        parent = self.journal / ('entries-' + key[:2])
        if not parent.exists():
            parent.mkdir(mode=0o700); sync_directory(self.journal)
        descriptor = root_fd(parent, ROOT_UID, private=True)
        os.close(descriptor)
        return parent / (key + '.json'), key

    def record(self, path):
        require(not path.is_symlink(), 'indirect copy receipt')
        if not path.exists(): return None
        value = json_value(read(path, owner=ROOT_UID))
        sync_file(path, ROOT_UID); sync_directory(path.parent)
        return value

    def put(self, path, value):
        self.gate()
        atomic(path, encoded(value))

    def listing(self, source, parts):
        names = sorted(os.listdir(source))
        require(len(names) <= MAX_ENTRIES and all(name not in ('.', '..') and '/' not in name for name in names),
                'original directory exceeds the copy bounds')
        ignored = None
        if not parts and 'lost+found' in names:
            info = at(source, 'lost+found')
            require(info.st_uid in (ROOT_UID, self.binding['source_uid'])
                    and stat.S_ISDIR(info.st_mode) and info.st_mode & 0o7777 == 0o700
                    and info.st_dev == os.fstat(source).st_dev, 'unqualified filesystem recovery directory')
            fd = os.open('lost+found', FLAGS | os.O_DIRECTORY, dir_fd=source)
            try: require(not os.listdir(fd), 'filesystem recovery directory is not empty')
            finally: os.close(fd)
            ignored = fingerprint(info); names.remove('lost+found')
        return names, hashlib.sha256(encoded({'names': names, 'ignored': ignored})).hexdigest()

    def checksum(self, descriptor, size):
        os.lseek(descriptor, 0, os.SEEK_SET)
        digest = hashlib.sha256(); total = 0
        while True:
            self.gate()
            chunk = os.read(descriptor, CHUNK)
            if not chunk: break
            total += len(chunk)
            require(total <= size, 'copy verification exceeded its original size')
            digest.update(chunk)
        require(total == size, 'copy verification found an incomplete file')
        return digest.hexdigest()

    def file(self, parts, source_parent, target_parent, scratch, source_device):
        name = parts[-1]
        source = os.open(name, FLAGS, dir_fd=source_parent)
        try:
            original = self.source_info(os.fstat(source), source_device)
            require(stat.S_ISREG(original['mode']), 'original copy file changed type')
            path, key = self.record_path(parts)
            base = {'schema': 1, 'parts': list(parts), 'kind': 'file', 'original': original}
            receipt = self.record(path)
            if receipt is None:
                require(at(target_parent, name) is None and at(scratch, key) is None,
                        'unreceipted copy file cannot be replaced')
                receipt = dict(base, phase='reserved', inode=None, sha256=None)
                self.put(path, receipt)
            require(isinstance(receipt, dict) and set(receipt) == {*base, 'phase', 'inode', 'sha256'}
                    and all(encoded(receipt[k]) == encoded(v) for k, v in base.items())
                    and receipt['phase'] in ('reserved', 'streaming', 'ready', 'complete'),
                    'original copy file receipt changed')
            if receipt['phase'] in ('reserved', 'streaming'):
                require(at(target_parent, name) is None, 'incomplete copy has an unexplained published file')
                info = at(scratch, key)
                if info is None:
                    require(receipt['phase'] == 'reserved', 'original copy temporary file is missing')
                    self.gate()
                    fd = os.open(key, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 0o600, dir_fd=scratch)
                else:
                    self.private_info(info)
                    require((receipt['phase'] == 'reserved' and info.st_size == 0)
                            or info.st_ino == receipt['inode'], 'copy temporary file differs from its reservation')
                    fd = os.open(key, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=scratch)
                try:
                    info = self.private_info(os.fstat(fd))
                    if receipt['phase'] == 'streaming': require(info.st_ino == receipt['inode'], 'copy temporary inode changed')
                    os.fsync(fd); os.fsync(scratch)
                    receipt = dict(base, phase='streaming', inode=info.st_ino, sha256=None)
                    self.put(path, receipt)
                    self.gate(); os.ftruncate(fd, 0)
                    digest = hashlib.sha256(); total = 0; zeros = bytes(CHUNK)
                    while True:
                        self.gate(); chunk = os.read(source, CHUNK)
                        if not chunk: break
                        total += len(chunk)
                        require(total <= original['size'], 'original copy file grew')
                        digest.update(chunk)
                        if chunk == zeros[:len(chunk)]: os.lseek(fd, len(chunk), os.SEEK_CUR)
                        else:
                            pending = memoryview(chunk)
                            while pending:
                                written = os.write(fd, pending)
                                require(written > 0, 'copy write made no progress'); pending = pending[written:]
                    require(total == original['size'] and fingerprint(os.fstat(source)) == original,
                            'original copy file changed while reading')
                    os.ftruncate(fd, total); os.fsync(fd)
                    require(self.checksum(fd, total) == digest.hexdigest(), 'copied bytes differ before publication')
                    receipt = dict(receipt, phase='ready', sha256=digest.hexdigest())
                    self.put(path, receipt)
                finally: os.close(fd)
            require(isinstance(receipt['sha256'], str) and re.fullmatch('[a-f0-9]{64}', receipt['sha256']),
                    'copy receipt lacks its original content digest')
            destination, temporary = at(target_parent, name), at(scratch, key)
            if destination is None:
                require(receipt['phase'] == 'ready' and temporary is not None, 'original copied payload is missing')
                self.private_info(temporary)
                require(temporary.st_ino == receipt['inode'], 'copy publication temporary changed')
                self.gate()
                # Atomic no-replace publication, retaining the original inode.
                os.link(key, name, src_dir_fd=scratch, dst_dir_fd=target_parent, follow_symlinks=False)
                destination = at(target_parent, name)
            self.private_info(destination, links=2 if temporary is not None else 1)
            require(destination.st_ino == receipt['inode'] and destination.st_size == original['size'],
                    'published copy differs from its original receipt')
            if temporary is not None:
                require(receipt['phase'] == 'ready' and temporary.st_ino == destination.st_ino,
                        'copy has an unknown extra link')
            fd = os.open(name, FLAGS, dir_fd=target_parent)
            try:
                require(self.checksum(fd, original['size']) == receipt['sha256']
                        and self.checksum(source, original['size']) == receipt['sha256']
                        and fingerprint(os.fstat(source)) == original, 'copied or original data content changed')
                os.fsync(fd); os.fsync(target_parent)
            finally: os.close(fd)
            if temporary is not None:
                self.gate()
                temporary = self.private_info(at(scratch, key), links=2)
                require(temporary.st_ino == receipt['inode'], 'copy temporary changed before release')
                os.unlink(key, dir_fd=scratch); os.fsync(scratch)
            self.put(path, dict(receipt, phase='complete'))
            return {'sha256': receipt['sha256'], 'bytes': original['size']}
        finally: os.close(source)

    def directory(self, parts, source, target, scratch, source_device):
        require(len(parts) <= MAX_DEPTH, 'original data exceeds the copy depth bound')
        self.gate()
        original = self.source_info(os.fstat(source), source_device)
        names, listing = self.listing(source, parts)
        self.count += len(names)
        require(self.count <= MAX_ENTRIES, 'original data exceeds the copy entry bound')
        path, _ = self.record_path(parts)
        base = {'schema': 1, 'parts': list(parts), 'kind': 'directory', 'original': original,
                'listing_sha256': listing, 'inode': os.fstat(target).st_ino}
        receipt = self.record(path)
        if receipt is None:
            require(not os.listdir(target), 'unreceipted copy directory is not empty')
            self.put(path, dict(base, phase='copying', tree_sha256=None))
        else:
            require(isinstance(receipt, dict) and set(receipt) == {*base, 'phase', 'tree_sha256'}
                    and all(encoded(receipt[k]) == encoded(v) for k, v in base.items())
                    and receipt['phase'] in ('copying', 'complete'), 'original copy directory receipt changed')
        require(set(os.listdir(target)) <= set(names), 'copy destination contains an unknown entry')
        digest = hashlib.sha256(); total = 0
        for name in names:
            self.gate(); info = at(source, name)
            self.source_info(info, source_device)
            if stat.S_ISDIR(info.st_mode):
                child_parts = (*parts, name); child_path, _ = self.record_path(child_parts)
                child_receipt = self.record(child_path)
                child_info = at(target, name)
                if child_info is None:
                    require(child_receipt is None, 'original copy directory is missing')
                    self.gate(); os.mkdir(name, 0o700, dir_fd=target); os.fsync(target)
                self.private_info(at(target, name), directory=True)
                child_source = os.open(name, FLAGS | os.O_DIRECTORY, dir_fd=source)
                try:
                    child_target = os.open(name, FLAGS | os.O_DIRECTORY, dir_fd=target)
                    try: result = self.directory(child_parts, child_source, child_target, scratch, source_device)
                    finally: os.close(child_target)
                finally: os.close(child_source)
            else: result = self.file((*parts, name), source, target, scratch, source_device)
            digest.update(encoded([name, result['sha256']])); total += result['bytes']
        require(fingerprint(os.fstat(source)) == original and self.listing(source, parts)[1] == listing
                and set(os.listdir(target)) == set(names), 'original or copied directory changed')
        os.fsync(target); self.gate()
        checksum = digest.hexdigest()
        if receipt is not None and receipt['phase'] == 'complete':
            require(receipt['tree_sha256'] == checksum, 'completed original copy tree changed')
        self.put(path, dict(base, phase='complete', tree_sha256=checksum))
        return {'sha256': checksum, 'bytes': total}

    def run(self):
        self.gate(); self.count = 0; descriptors = []
        try:
            for path, uid in [(self.source, self.binding['source_uid']), (self.payload, ROOT_UID),
                              (self.scratch, ROOT_UID), (self.journal, ROOT_UID)]:
                descriptors.append(root_fd(path, uid, private=path != self.source, durable=path != self.source))
            source, target, scratch, journal = descriptors
            for descriptor in (journal, target, scratch):
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            require(os.fstat(source).st_ino == self.binding['source_inode']
                    and os.fstat(target).st_ino == self.binding['payload_inode']
                    and os.fstat(scratch).st_ino == self.binding['scratch_inode']
                    and os.fstat(target).st_dev == os.fstat(scratch).st_dev,
                    'original copy roots changed')
            require(len({(os.fstat(fd).st_dev, os.fstat(fd).st_ino) for fd in descriptors}) == 4,
                    'copy roots must not alias')
            self.source_info(os.fstat(source), os.fstat(source).st_dev)
            owner = {'schema': 1, 'binding': self.binding, 'source': str(self.source),
                     'payload': str(self.payload), 'scratch': str(self.scratch)}
            path = self.journal / 'owner.json'; existing = self.record(path)
            if existing is None:
                require(not os.listdir(journal) and not os.listdir(target) and not os.listdir(scratch),
                        'fresh copy cannot adopt existing staging')
                self.put(path, owner)
            else: require(encoded(existing) == encoded(owner), 'copy belongs to another original migration')
            result = self.directory((), source, target, scratch, os.fstat(source).st_dev)
            require(not os.listdir(scratch), 'copy left unexplained temporary files')
            self.gate(); result.update(entries=self.count, source_retained=True, runtime_started=False)
            return result
        finally:
            for descriptor in reversed(descriptors): os.close(descriptor)
