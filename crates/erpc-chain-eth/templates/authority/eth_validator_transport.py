#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Validator-only Engine HTTP/TLS to authenticated Reth IPC transport.

The socket is connected and its kernel peer checked before request bytes are
sent. Server certificates and client trust are separate from the beacon TLS
identity. Private credentials are passed by the checked runtime, never by URL,
argv, environment, or an ambient proxy configuration.
"""
import base64
import hmac
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import time
from eth_files import encoded,require,unique

ENGINE_IP='127.0.0.2'
BEACON_IP='127.0.0.3'
MAX_BODY=64*1024*1024
# Pinned Lighthouse execution_layer/engine_api/http.rs. This is the engine
# client's method surface, not a general transaction/admin forwarding proxy.
METHODS=frozenset({
    'eth_chainId','eth_blockNumber','eth_getBlockByHash','eth_getBlockByNumber',
    'eth_syncing','eth_call','eth_getLogs','engine_exchangeCapabilities',
    'engine_getClientVersionV1','engine_getInclusionListV1',
}|{'engine_newPayloadV'+str(n) for n in range(1,7)}
 |{'engine_getPayloadV'+str(n) for n in range(1,7)}
 |{'engine_forkchoiceUpdatedV'+str(n) for n in range(1,6)}
 |{'engine_getPayloadBodiesByHashV'+str(n) for n in range(1,3)}
 |{'engine_getBlobsV'+str(n) for n in range(2,5)})


def b64(value):
    require(isinstance(value,str) and re.fullmatch('[A-Za-z0-9_-]+',value),'invalid engine authorization')
    return base64.b64decode(value+'='*((-len(value))%4),altchars=b'-_',validate=True)


def jwt(header,key,now=None):
    require(isinstance(header,str) and header.startswith('Bearer ') and len(header)<=4096
            and isinstance(key,bytes) and len(key)==32,'invalid engine authorization')
    parts=header[7:].split('.');require(len(parts)==3,'invalid engine authorization')
    head=unique(b64(parts[0]));body=unique(b64(parts[1]));signature=b64(parts[2])
    require(isinstance(head,dict) and head.get('alg')=='HS256' and set(head)<= {'alg','typ'}
            and ('typ' not in head or head['typ']=='JWT') and isinstance(body,dict)
            and type(body.get('iat'))is int,'invalid engine authorization')
    timestamp=time.time() if now is None else now
    require(abs(timestamp-body['iat'])<=60 and hmac.compare_digest(signature,
            hmac.digest(key,(parts[0]+'.'+parts[1]).encode(),'sha256')),'invalid engine authorization')
    if 'exp' in body:require(type(body['exp'])is int and body['exp']>=timestamp,'expired engine authorization')


def request(raw):
    require(isinstance(raw,bytes) and 0<len(raw)<=MAX_BODY,'engine request exceeds its bound')
    value=unique(raw)
    require(isinstance(value,dict) and set(value)=={'jsonrpc','id','method','params'} and value['jsonrpc']=='2.0'
            and (type(value['id'])is int or isinstance(value['id'],str)) and value['method'] in METHODS
            and isinstance(value['params'],list),'unsupported engine RPC request')
    return value


def public_file(path,limit=16384):
    """Read one root-published proof, checking each ancestor before opening it."""
    require(path.is_absolute() and str(path)==os.path.normpath(path),'normalized runtime peer proof required')
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            new=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
            try:
                info=os.fstat(new)
                require(info.st_uid==0 and not info.st_mode&0o022,'untrusted runtime peer ancestor')
            except BaseException:os.close(new);raise
            os.close(fd);fd=new
        selected=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=fd)
    finally:os.close(fd)
    with os.fdopen(selected,'rb') as stream:
        info=os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1
                and stat.S_IMODE(info.st_mode)==0o644 and info.st_size<=limit,'untrusted runtime peer proof')
        raw=stream.read(limit+1);require(len(raw)<=limit,'runtime peer proof exceeds its bound')
    return unique(raw)


def generation(pid,proc=Path('/proc')):
    raw=(proc/str(pid)/'stat').read_bytes()
    require(len(raw)<=16384 and b') ' in raw,'native process generation unavailable')
    fields=raw.rsplit(b') ',1)[1].split()
    require(len(fields)>=20 and fields[19].isdigit() and fields[0] not in (b'Z',b'X'),'native process is unavailable')
    return int(fields[19])


def connect(path,proof_path,contract_digest,boot_id,now=None):
    proof=public_file(proof_path);timestamp=time.monotonic() if now is None else now
    require(isinstance(proof,dict) and set(proof)=={'contract','boot_id','pid','uid','gid','start','socket','expires'}
            and proof['contract']==contract_digest and proof['boot_id']==boot_id
            and all(type(proof[k])is int and proof[k]>0 for k in ('pid','uid','gid','start'))
            and type(proof['expires'])in (int,float) and timestamp<proof['expires']<=timestamp+60
            and isinstance(proof['socket'],dict) and set(proof['socket'])=={'device','inode','path'}
            and proof['socket']['path']==str(path),'original runtime peer proof differs or expired')
    # The namespace itself is root-owned. Reth owns only the socket entry, whose
    # exact identity was published after the root process/image/cgroup proof.
    info=path.lstat()
    require(stat.S_ISSOCK(info.st_mode) and info.st_uid==proof['uid'] and info.st_gid==proof['gid']
            and stat.S_IMODE(info.st_mode)==0o660 and info.st_dev==proof['socket']['device']
            and info.st_ino==proof['socket']['inode'],'original engine IPC socket changed')
    client=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    try:
        client.settimeout(60);client.connect(str(path))
        pid,uid,gid=struct.unpack('3i',client.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize('3i')))
        require((pid,uid,gid)==(proof['pid'],proof['uid'],proof['gid'])
                and generation(pid)==proof['start'],'connected engine IPC peer differs from the original process')
        after=path.lstat()
        require((after.st_dev,after.st_ino)==(info.st_dev,info.st_ino),'engine IPC changed while connecting')
        return client
    except BaseException:client.close();raise


def exchange(client,value):
    raw=encoded(value);require(value['method'] in METHODS,'unsupported engine RPC request')
    client.sendall(raw+b'\n');response=bytearray();decoder=json.JSONDecoder()
    while True:
        block=client.recv(min(65536,MAX_BODY+1-len(response)))
        require(block,'engine IPC closed without a complete response');response.extend(block)
        require(len(response)<=MAX_BODY,'engine response exceeds its bound')
        try:
            text=response.decode();_,end=decoder.raw_decode(text.lstrip())
        except (UnicodeError,json.JSONDecodeError):continue
        # Reparse with duplicate/nonfinite rejection only after framing complete.
        require(not text.lstrip()[end:].strip(),'multiple engine responses for one request')
        result=unique(text)
        require(isinstance(result,dict) and result.get('jsonrpc')=='2.0' and result.get('id')==value['id']
                and ('result' in result)!=('error' in result),'engine IPC response identity differs')
        return encoded(result)


def serve(context,key,path,proof_path,contract_digest,boot_id,identity):
    """Called by the externally checked root controller after TLS custody checks.

    TLS material is already loaded into the SSLContext. The listener and all
    request handling run under the original adapter identity with no groups or
    Linux capabilities. No native diagnostics are written by this transport.
    """
    import ctypes
    require(os.geteuid()==0 and set(identity)=={'uid','gid'} and all(type(identity[k])is int and 100<=identity[k]<=999 for k in identity),
            'original dedicated transport identity required')
    # PR_SET_NO_NEW_PRIVS survives the numeric privilege transition. Failure is
    # fatal before binding any listener; no user-controlled library is loaded.
    libc=ctypes.CDLL(None,use_errno=True)
    require(libc.prctl(38,1,0,0,0)==0,'cannot seal engine transport privileges')
    os.setgroups([]);os.setgid(identity['gid']);os.setuid(identity['uid'])
    require(os.getuid()==identity['uid'] and os.geteuid()==identity['uid']
            and os.getgid()==identity['gid'] and os.getegid()==identity['gid'] and not os.getgroups(),
            'engine transport privilege transition failed')
    status={}
    for line in Path('/proc/self/status').read_text().splitlines():
        if ':' in line:
            name,content=line.split(':',1);status[name]=content.strip()
    require(status.get('NoNewPrivs')=='1' and all(int(status.get(name,'1'),16)==0
            for name in ('CapInh','CapPrm','CapEff','CapAmb')),'engine transport retains privileged capabilities')
    with server(context,key,path,proof_path,contract_digest,boot_id) as instance:instance.serve_forever()


def server(context,key,path,proof_path,contract_digest,boot_id,address=(ENGINE_IP,8552)):
    """Construct the fixed production handler; tests use an ephemeral loopback port."""
    import http.server
    import threading
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version='HTTP/1.0'
        def setup(self):
            super().setup();self.connection.do_handshake()
        def log_message(self,*_):pass
        def send_public(self,status,value):
            raw=encoded(value);self.send_response(status);self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(raw)));self.send_header('Connection','close');self.end_headers();self.wfile.write(raw)
        def do_POST(self):
            client=None
            try:
                require(self.path=='/' and self.headers.get_all('Transfer-Encoding') is None,'unsupported engine framing')
                lengths=self.headers.get_all('Content-Length',[]);auth=self.headers.get_all('Authorization',[])
                require(len(lengths)==1 and re.fullmatch('[0-9]{1,9}',lengths[0]) and 0<int(lengths[0])<=MAX_BODY
                        and len(auth)==1,'invalid engine framing')
                jwt(auth[0],key)
                raw=self.rfile.read(int(lengths[0]));require(len(raw)==int(lengths[0]),'incomplete engine request')
                value=request(raw)
                client=connect(path,proof_path,contract_digest,boot_id)
                answer=exchange(client,value)
                self.send_response(200);self.send_header('Content-Type','application/json')
                self.send_header('Content-Length',str(len(answer)));self.send_header('Connection','close');self.end_headers();self.wfile.write(answer)
            except Exception:
                # Public generic error only; native payloads, keys and private
                # exception diagnostics never enter this adapter's journal.
                try:self.send_public(503,{'error':'original execution peer unavailable'})
                except Exception:pass
            finally:
                if client is not None:client.close()
                self.close_connection=True
        def do_GET(self):self.send_public(404,{'error':'unsupported engine request'})
    class Server(http.server.ThreadingHTTPServer):
        daemon_threads=True
        def __init__(self):
            self.slots=threading.BoundedSemaphore(8)
            super().__init__(address,Handler)
            self.socket=context.wrap_socket(self.socket,server_side=True,do_handshake_on_connect=False)
        def get_request(self):
            connection,address=super().get_request();connection.settimeout(60)
            return connection,address
        def process_request(self,request,address):
            if not self.slots.acquire(blocking=False):self.shutdown_request(request);return
            try:super().process_request(request,address)
            except BaseException:self.slots.release();raise
        def process_request_thread(self,request,address):
            try:super().process_request_thread(request,address)
            finally:self.slots.release()
        def handle_error(self,*_):pass
    return Server()
