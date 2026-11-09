# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Prove the nginx process family and both ingress protocols without credentials."""
import re
import socket
import base64
import hashlib
import os
import time
from native_files import require
import native_process as proc
import native_runtime_process as process
import native_runtime_observer as observer
import native_gateway as gateway

CGROUP = b'0::/system.slice/erpc-solana-gateway.service\n'


def title(directory):
    # Linux title/argv padding was qualified against nginx release-1.24.0,
    # commit 84cd7217778b8b3a2e395194b641ea14050344f1, ngx_setproctitle.{c,h}
    # and ngx_process_cycle.c. The actual distribution binary is independently
    # measured in the installed receipt; it is not claimed byte-identical.
    value = proc.bounded(directory / 'cmdline', 65536)
    first, separator, padding = value.partition(b'\0')
    require(separator and not padding.strip(b'\0'), 'ingress process title has unexpected arguments')
    return first.decode('ascii')


def owned(master, account):
    """Normal nginx master/workers inherit one unprivileged original identity."""
    uid, gid = account['uid'], account['gid']
    expected = gateway.BINARY.lstat()
    result = {}
    directories = list(proc.PROC.iterdir())
    require(len(directories) <= 1_000_000, 'process namespace exceeds its bound')
    for directory in directories:
        if not directory.name.isdecimal(): continue
        require(not directory.is_symlink(), 'indirect process directory')
        try:
            generation = proc.generation(directory)
            fields = process.fields(proc.bounded(directory / 'status', 65536))
            uids = process.integers(fields.get('Uid', ''), 4)
            if uid not in uids: continue
            require(uids == (uid,)*4 and process.integers(fields.get('Gid',''),4) == (gid,)*4
                    and set(process.integers(fields.get('Groups',''))) <= {gid}, 'ingress process identity differs')
            require(fields.get('NoNewPrivs') == '1', 'ingress privilege restriction differs')
            for key in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb'):
                value=fields.get(key,'')
                require(re.fullmatch('[a-fA-F0-9]{1,16}',value) and int(value,16)==0, 'ingress retained capabilities')
            require(proc.bounded(directory/'cgroup',16384)==CGROUP,'ingress account has an orphan process')
            executed=(directory/'exe').stat()
            require((executed.st_dev,executed.st_ino)==(expected.st_dev,expected.st_ino),'ingress executable inode differs')
            actual_title=title(directory)
            expected_title=('nginx: master process '+' '.join(gateway.arguments())) if int(directory.name)==master else 'nginx: worker process'
            require(actual_title==expected_title,'ingress master or worker invocation differs')
            require(proc.generation(directory)==generation,'ingress process changed during inspection')
            result[int(directory.name)]=generation
        except FileNotFoundError:
            continue
    require(master in result and 2 <= len(result) <= 3, 'ingress master or workers are unavailable')
    return result


def listeners(directory, uid, owned_inodes):
    found={('tcp',7211):[],('tcp',7212):[],('tcp6',7211):[],('tcp6',7212):[]}
    for name,width in [('tcp',8),('tcp6',32)]:
        lines=proc.bounded(directory/'net'/name,4*1024*1024).decode('ascii').splitlines()
        require(lines and 'local_address' in lines[0],'invalid ingress socket table')
        for line in lines[1:]:
            parts=line.split();require(len(parts)>=10,'invalid ingress socket record')
            address,separator,port=parts[1].partition(':')
            require(separator and re.fullmatch('[A-Fa-f0-9]{'+str(width)+'}',address)
                    and re.fullmatch('[A-Fa-f0-9]{4}',port),'invalid ingress socket address')
            number=int(port,16)
            if (name,number) not in found or parts[3]!='0A':continue
            require(address=='0'*width and parts[7].isdecimal() and int(parts[7])==uid
                    and parts[9].isdecimal() and int(parts[9]) in owned_inodes,
                    'ingress does not own the expected listeners')
            found[(name,number)].append(int(parts[9]))
    require(all(len(values)==1 for values in found.values()),'ingress has missing or duplicate listeners')


def prove(master, account):
    before=owned(master,account)
    directory=proc.PROC/str(master)
    actual=(directory/'ns/net').stat();expected=(proc.PROC/'self/ns/net').stat()
    require((actual.st_dev,actual.st_ino)==(expected.st_dev,expected.st_ino),'ingress network namespace differs')
    listeners(directory,account['uid'],process.socket_inodes(directory))
    require(owned(master,account)==before,'ingress process family changed during observation')
    return tuple(sorted(before.items()))


def upgrade(raw, expected_accept):
    lines=raw.split(b'\r\n\r\n',1)[0].split(b'\r\n')
    require(lines[0].split(b' ',2)[:2]==[b'HTTP/1.1',b'101'],'ingress WebSocket did not upgrade')
    headers={}
    for line in lines[1:]:
        key,separator,value=line.partition(b':');key=key.lower()
        require(separator and key not in headers,'ambiguous WebSocket response header')
        headers[key]=value.strip()
    require(headers.get(b'upgrade',b'').lower()==b'websocket'
            and b'upgrade' in [part.strip().lower() for part in headers.get(b'connection',b'').split(b',')]
            and headers.get(b'sec-websocket-accept')==expected_accept
            and b'sec-websocket-extensions' not in headers
            and b'sec-websocket-protocol' not in headers,
            'ingress WebSocket handshake differs')


def websocket(connect=socket.create_connection, nonce=os.urandom):
    # RFC 6455 requires a fresh 16-byte public connection nonce. It grants no
    # wallet authority and is unrelated to the validator's identity credential.
    raw_nonce = nonce(16)
    require(isinstance(raw_nonce, bytes) and len(raw_nonce) == 16, 'invalid WebSocket connection nonce')
    encoded_nonce = base64.b64encode(raw_nonce)
    expected_accept = base64.b64encode(hashlib.sha1(
        encoded_nonce + b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11', usedforsecurity=False).digest())
    request=(b'GET / HTTP/1.1\r\nHost: 127.0.0.1:7212\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
             b'Sec-WebSocket-Key: ' + encoded_nonce + b'\r\nSec-WebSocket-Version: 13\r\n\r\n')
    with connect(('127.0.0.1',7212),timeout=5) as stream:
        stream.sendall(request);raw=b''
        while b'\r\n\r\n' not in raw:
            block=stream.recv(1024);require(block,'ingress WebSocket handshake ended early')
            raw+=block;require(len(raw)<=16384,'ingress WebSocket headers exceed their bound')
        upgrade(raw, expected_accept)
        mask = nonce(4)
        require(isinstance(mask, bytes) and len(mask) == 4, 'invalid WebSocket close mask')
        stream.sendall(b'\x88\x80' + mask)  # Masked client Close, empty payload.
        deadline = time.monotonic() + 5
        received = 0
        while True:
            remaining = deadline - time.monotonic()
            require(remaining > 0, 'ingress WebSocket close timed out')
            stream.settimeout(remaining)
            chunk = stream.recv(1024)
            if not chunk: break
            received += len(chunk)
            require(received <= 4096, 'ingress WebSocket close exceeded its bound')


def inspect(state,contract,active,profile,run):
    receipt=active['receipt']['gateway']
    def verify():
        require(state.guard(contract)==active,'ingress activation changed')
        account=gateway.verify(state,contract,receipt)
        service=gateway.service(account,run)
        require(service['ActiveState']=='active' and service['SubState']=='running' and service['MainPID']>0,
                'ingress is not running')
        return prove(service['MainPID'],account)
    result=observer.inspect(profile,active['receipt']['identity'],verify,
        lambda method,params:observer.rpc(method,params,port=7211))
    if result['rpc_ready']:
        try:
            before=verify();websocket();require(verify()==before,'ingress changed during WebSocket observation')
            result['websocket_ready']=True
        except Exception:
            result.update(rpc_ready=False,websocket_ready=False,inspection_error='owned ingress WebSocket unavailable')
    return result
