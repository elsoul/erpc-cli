# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Same-boot original-generation send authority, held through one native request.

The root controller denies new requests before waiting for an already admitted
request. It never retries a financial request. This cannot revoke a transaction
already accepted by Ethereum and does not replace the durable stopped fence.
"""
from contextlib import contextmanager
import fcntl
import os
import stat
import time
import host
import storage
from state import contract, token
from storage import decode, directory, encode, read, require, sync_directory, write


def paths(): return host.RUNTIME / 'send.lock', host.RUNTIME / 'send.json'


def checked_lock(group):
    lock, _ = paths(); directory(host.RUNTIME)
    descriptor = os.open(lock, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor); actual = lock.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == storage.ROOT_UID
                and info.st_gid == group and info.st_mode & 0o7777 == 0o440
                and (info.st_dev, info.st_ino) == (actual.st_dev, actual.st_ino),
                'native send lock does not belong to the original transport account')
        return descriptor
    except BaseException:
        os.close(descriptor); raise


def initialize(group):
    require(type(group) is int and group > 0, 'original transport group is missing')
    directory(host.RUNTIME, create=True, mode=0o755)
    lock, _ = paths()
    if not lock.exists() and not lock.is_symlink():
        descriptor = os.open(lock, os.O_RDONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
        try:
            os.fchown(descriptor, storage.ROOT_UID, group); os.fchmod(descriptor, 0o440); os.fsync(descriptor)
        finally: os.close(descriptor)
        sync_directory(host.RUNTIME)
    descriptor = checked_lock(group); os.close(descriptor)


def receipt(expected, generation, target, enabled):
    contract(expected); token(generation)
    require(type(enabled) is bool and isinstance(target, dict) and target.get('phase') == 'active',
            'native send authority requires an exact active target')
    return {'contract': expected, 'generation': generation, 'target': target, 'enabled': enabled}


def publish(value, group):
    write(paths()[1], encode(value), mode=0o440, group=group)


def acquire(group, expected, generation, target):
    wanted = receipt(expected, generation, target, True)
    @contextmanager
    def authorized():
        descriptor = checked_lock(group)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
            value = read(paths()[1], 131072, mode=0o440)
            require(paths()[1].lstat().st_gid == group and decode(value) == wanted,
                    'native send authority was revoked, superseded or belongs to another wallet')
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN); os.close(descriptor)
    return authorized


def revoke(group, timeout=90):
    initialize(group)
    # Deny is atomic before waiting. New shared holders refuse immediately, even
    # while a prior request is completing or the controller later fails to drain.
    current = paths()[1]
    if current.exists():
        previous = decode(read(current, 131072, mode=0o440))
        generation = previous.get('generation')
        if generation is not None:
            token(generation)
            write(host.RUNTIME / 'cancelled.json', encode({'generation': generation}), mode=0o440, group=group)
    publish({'enabled': False}, group)
    descriptor = checked_lock(group)
    try:
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB); break
            except BlockingIOError:
                require(time.monotonic() < deadline, 'native request did not release cancelled send authority')
                time.sleep(0.05)
        return True
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN); os.close(descriptor)


def grant(state, expected, records):
    target = state.guard(expected)
    group = records['transport']['gid']; initialize(group)
    wanted = receipt(expected, state.fence()['generation'], target, True)
    cancelled = host.RUNTIME / 'cancelled.json'
    if cancelled.exists():
        require(decode(read(cancelled, mode=0o440)) != {'generation': wanted['generation']},
                'this boot cancelled the original generation; an explicit durable new operation is required')
    descriptor = checked_lock(group)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        require(state.guard(expected) == target and state.fence()['generation'] == wanted['generation'],
                'runtime changed while granting original send authority')
        publish(wanted, group)
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN); os.close(descriptor)
    return wanted
