# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Validator-only absolute network deadlines, including DNS and slow responses.

Address policy, TLS identity and sanitized JSON remain the shared transport's.
A timed-out resolver may only finish a read-only DNS lookup; it never connects or
submits afterward. At most two daemon resolver workers may remain outstanding.
"""
import scope
import http.client
import io
import re
import socket
import ssl
import threading
import time
import upstreams

RESOLVERS = threading.BoundedSemaphore(2)


def remaining(deadline):
    value = deadline-time.monotonic()
    if value <= 0: upstreams.fail()
    return value


def resolve(function, deadline):
    slots = RESOLVERS
    if not slots.acquire(blocking=False): upstreams.fail()
    complete = threading.Event(); result = []
    def worker():
        try: result.append(function())
        except Exception: pass
        finally: slots.release(); complete.set()
    try: threading.Thread(target=worker, daemon=True).start()
    except Exception:
        slots.release(); upstreams.fail()
    if not complete.wait(remaining(deadline)) or not result: upstreams.fail()
    remaining(deadline)
    return result[0]


class Reader(io.RawIOBase):
    def __init__(self, stream): self.stream = stream
    def readable(self): return True
    def readinto(self, buffer):
        self.stream.check()
        value = self.stream.raw.recv_into(buffer)
        remaining(self.stream.deadline)
        return value


class Socket:
    def __init__(self, raw, deadline): self.raw, self.deadline = raw, deadline
    def check(self): self.raw.settimeout(remaining(self.deadline))
    def sendall(self, data): self.check(); self.raw.sendall(data); remaining(self.deadline)
    def makefile(self, mode):
        if mode != 'rb': upstreams.fail()
        return io.BufferedReader(Reader(self))
    def close(self): self.raw.close()


class Endpoint(upstreams.Endpoint):
    def __init__(self, config, deadline=lambda: float('inf')):
        super().__init__(config); self.deadline = deadline

    def request(self, method, suffix='', body=None):
        deadline = min(self.deadline(), time.monotonic()+30)
        connection = None; raw_socket = None
        try:
            answers = resolve(self.addresses, deadline)
            for family, kind, protocol, address in answers:
                remaining(deadline)
                raw_socket = socket.socket(family, kind, protocol)
                raw_socket.settimeout(remaining(deadline))
                try: raw_socket.connect(address); break
                except OSError:
                    raw_socket.close(); raw_socket = None
            if raw_socket is None: upstreams.fail()
            raw_socket.settimeout(remaining(deadline))
            if self.tls: raw_socket = ssl.create_default_context().wrap_socket(raw_socket, server_hostname=self.host)
            connection = http.client.HTTPConnection(self.host, self.port, timeout=remaining(deadline))
            connection.sock = Socket(raw_socket, deadline)
            path = self.path.rstrip('/')+suffix if suffix else self.path
            if self.query: path += ('&' if '?' in path else '?')+self.query
            connection.request(method, path, body=body, headers={
                'Content-Type':'application/json', 'Accept':'application/json', 'Accept-Encoding':'identity',
                'Connection':'close', **self.headers})
            response = connection.getresponse()
            if (response.status == 404 and method == 'GET'
                    and re.fullmatch(r'/eth/v1/beacon/(?:blobs|blob_sidecars)/[A-Za-z0-9_]+', suffix.partition('?')[0])):
                raise upstreams.MissingBeaconResource()
            if response.status != 200 or response.getheader('Content-Encoding', 'identity') != 'identity': upstreams.fail()
            size = response.getheader('Content-Length')
            if size is not None and (not size.isdecimal() or int(size) > upstreams.MAX_RESPONSE): upstreams.fail()
            raw = response.read(upstreams.MAX_RESPONSE+1)
            if len(raw) > upstreams.MAX_RESPONSE: upstreams.fail()
            remaining(deadline); value = upstreams.strict_json(raw); remaining(deadline)
            return value
        except (OSError, ValueError, TypeError, http.client.HTTPException): upstreams.fail()
        finally:
            if connection: connection.close()
            if raw_socket: raw_socket.close()


def readonly(config):
    result = upstreams.Upstreams(config, scope.PARENT)
    result.execution = Endpoint(config['execution']); result.beacon = Endpoint(config['beacon'])
    return result
