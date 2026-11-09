# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Connected Unix peer authority for validator-only native RPC adapters.

The root caller supplies a full original-account/unit/executable proof, repeated
before and after connect. No request byte is sent before Linux SO_PEERCRED agrees
with that proof. The connection stays with that peer even if the pathname is
subsequently rebound. This does not trust a matching public JSON-RPC response.
"""
import http.client
import io
import json
from pathlib import Path
import socket
import stat
import struct
import time

PATHS = {'bor': Path('/run/polygon-bor/native.rpc'),
         'heimdall': Path('/run/polygon-heimdall/native.rest')}
MAXIMUM = 16 * 1024 * 1024
TIMEOUT = 30
ROOT_UID = 0
TRUST_ANCHOR = Path('/')


def require(value, message):
    if not value: raise ValueError(message)


def identity(path, uid, reader_gid):
    current = TRUST_ANCHOR
    for part in (None, *path.parent.parent.relative_to(TRUST_ANCHOR).parts):
        if part is not None: current = current/part
        ancestor = current.lstat()
        require(stat.S_ISDIR(ancestor.st_mode) and ancestor.st_uid == ROOT_UID and not ancestor.st_mode & 0o022,
                'native socket ancestor is not root protected')
    parent = path.parent.lstat()
    info = path.lstat()
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == uid and parent.st_gid == reader_gid
            and parent.st_mode & 0o7777 == 0o710 and stat.S_ISSOCK(info.st_mode) and info.st_uid == uid
            and info.st_gid == reader_gid and info.st_nlink == 1 and info.st_mode & 0o7777 == 0o660,
            'private native socket has unknown authority or access')
    return (parent.st_dev, parent.st_ino, info.st_dev, info.st_ino)


def connect(component, prove, factory=socket.socket):
    require(component in PATHS, 'unsupported native Unix component')
    original = prove()
    require(isinstance(original, dict) and set(original) == {'pid', 'uid', 'gid', 'reader_gid', 'generation'}
            and all(type(original[key]) is int and original[key] > 0 for key in ('pid', 'uid', 'gid', 'reader_gid'))
            and isinstance(original['generation'], str) and original['generation'].isdigit(),
            'native peer has no original process proof')
    path = PATHS[component]
    before = identity(path, original['uid'], original['reader_gid'])
    stream = factory(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        stream.settimeout(TIMEOUT)
        stream.connect(str(path))
        peer = struct.unpack('3i', stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
        require(peer == (original['pid'], original['uid'], original['gid']), 'connected native peer differs')
        require(prove() == original and identity(path, original['uid'], original['reader_gid']) == before,
                'native process or socket changed during connect')
        return stream
    except BaseException:
        stream.close()
        raise


def rpc(component, prove, body, decode, factory=socket.socket):
    require(component == 'bor' and isinstance(body, bytes) and 0 < len(body) <= MAXIMUM,
            'invalid bounded native RPC request')
    stream = connect(component, prove, factory)
    try:
        deadline = time.monotonic() + TIMEOUT
        stream.sendall(body + b'\n')
        received = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            require(remaining > 0, 'native RPC response deadline exceeded')
            stream.settimeout(remaining)
            chunk = stream.recv(min(65536, MAXIMUM + 1 - len(received)))
            require(chunk, 'native RPC closed without a response')
            received.extend(chunk)
            require(len(received) <= MAXIMUM, 'native RPC response exceeds its bound')
            # Geth JSON codec emits one newline-terminated JSON value. The
            # response validator supplied by the caller binds every request ID.
            if b'\n' in received:
                line, tail = received.split(b'\n', 1)
                require(not tail.strip(), 'unexpected native RPC response suffix')
                return decode(bytes(line))
    finally: stream.close()


class DeadlineReader(io.RawIOBase):
    def __init__(self, stream, deadline, release=None):
        super().__init__(); self.stream, self.deadline, self.release = stream, deadline, release

    def readable(self): return True

    def close(self):
        if not self.closed and self.release is not None: self.release()
        super().close()

    def readinto(self, buffer):
        remaining = self.deadline-time.monotonic()
        require(remaining > 0, 'native REST response deadline exceeded')
        self.stream.settimeout(remaining)
        count = self.stream.recv_into(buffer)
        require(time.monotonic() <= self.deadline, 'native REST response deadline exceeded')
        return count


class DeadlineSocket:
    def __init__(self, stream, deadline):
        self.stream, self.deadline = stream, deadline
        self.readers, self.closing = 0, False

    def sendall(self, body):
        remaining = self.deadline-time.monotonic()
        require(remaining > 0, 'native REST request deadline exceeded')
        self.stream.settimeout(remaining); self.stream.sendall(body)

    def makefile(self, mode):
        require(mode == 'rb', 'unsupported native HTTP stream')
        self.readers += 1
        return io.BufferedReader(DeadlineReader(self.stream, self.deadline, self.release))

    def release(self):
        self.readers -= 1
        if self.closing and self.readers == 0: self.stream.close()

    def close(self):
        self.closing = True
        if self.readers == 0: self.stream.close()


class HTTPConnection(http.client.HTTPConnection):
    def __init__(self, prove, factory=socket.socket):
        super().__init__('localhost', timeout=TIMEOUT)
        self.prove, self.factory = prove, factory

    def connect(self):
        self.sock = DeadlineSocket(connect('heimdall', self.prove, self.factory), time.monotonic()+TIMEOUT)


def rest(path, prove, connection=HTTPConnection):
    require(isinstance(path, str) and 0 < len(path) <= 8192 and path.startswith('/')
            and not path.startswith('//') and all(32 < ord(char) < 127 for char in path)
            and '#' not in path and '\\' not in path, 'invalid native REST path')
    client = connection(prove)
    try:
        client.request('GET', path, headers={'Accept': 'application/json', 'Connection': 'close'})
        response = client.getresponse()
        require(response.status in (200, 400, 404, 500, 503), 'unexpected native REST response status')
        require(response.getheader('Content-Encoding') in (None, 'identity'), 'compressed native response is not qualified')
        body = bytearray(); deadline = time.monotonic()+TIMEOUT
        while True:
            require(time.monotonic() < deadline, 'native REST response deadline exceeded')
            chunk = response.read1(min(65536, MAXIMUM+1-len(body)))
            if not chunk: break
            body.extend(chunk); require(len(body) <= MAXIMUM, 'native REST response exceeds its bound')
        # Reject arbitrary binary/HTML diagnostics before exposing this private
        # native adapter to another original process; do not log its payload.
        value = json.loads(body)
        require(isinstance(value, (dict, list)), 'native REST response is not a JSON object or array')
        return response.status, bytes(body)
    finally: client.close()
