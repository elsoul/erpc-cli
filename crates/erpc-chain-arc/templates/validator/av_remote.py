#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Read-only PublicKey qualification of an externally prepared official signer.

This does not create AWS resources, export a seed, invoke Sign, attest an EIF,
or certify anti-equivocation. Artifact/PCR fields are operator-supplied evidence.
"""
import base64
import ipaddress
import re
import struct
import urllib.parse

from arc_files import digest, require
from av_files import ROOT

CA = ROOT + '/signer-ca.pem'
METHOD = '/arc.signer.v1.SignerService/PublicKey'


def inputs(value):
    require(isinstance(value, dict) and set(value) == {'endpoint', 'server_ca_sha256', 'image_sha256',
                                                     'pcr0', 'pcr1', 'pcr2', 'pcr4'},
            'official remote signer qualification inputs are incomplete')
    require(isinstance(value['endpoint'], str) and len(value['endpoint']) <= 256,
            'remote signer endpoint is invalid')
    url = urllib.parse.urlsplit(value['endpoint'])
    require(url.scheme == 'https' and url.hostname and not url.username and not url.password and
            not url.query and not url.fragment and url.path in ('', '/') and
            (url.port is None or 0 < url.port <= 65535), 'remote signer requires a fixed credential-free TLS endpoint')
    address = ipaddress.ip_address(url.hostname)
    require(not address.is_unspecified and not address.is_multicast, 'remote signer endpoint is not unicast')
    for name, length in (('server_ca_sha256', 64), ('image_sha256', 64), ('pcr0', 96),
                         ('pcr1', 96), ('pcr2', 96), ('pcr4', 96)):
        require(isinstance(value[name], str) and re.fullmatch('[0-9a-f]{' + str(length) + '}', value[name]),
                'remote signer original artifact or PCR evidence is malformed')
    return value


def certificate(raw, profile):
    inputs(profile)
    require(isinstance(raw, bytes) and len(raw) <= 65536 and digest(raw) == profile['server_ca_sha256'] and
            re.fullmatch(rb'-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\r?\n?', raw),
            'remote signer CA differs from the original single public certificate')
    return raw


def ca(context, state):
    return certificate(context.read(CA, limit=65536, private=True), state['remote_signer'])


def public_response(raw):
    require(isinstance(raw, bytes) and len(raw) <= 32768, 'remote signer PublicKey response exceeds its bound')
    ending = b'\nERPC_RESULT=2=200\n'
    require(raw.endswith(ending), 'remote signer did not answer the original HTTP/2 PublicKey method')
    content = raw[:-len(ending)]
    headers, separator, body = content.partition(b'\r\n\r\n')
    require(separator and headers.split(b'\r\n', 1)[0].rstrip(b' ') == b'HTTP/2 200',
            'remote signer did not return HTTP/2 success')
    fields = {}
    for line in headers.split(b'\r\n')[1:]:
        name, colon, value = line.partition(b':')
        require(colon, 'invalid remote signer HTTP/2 header')
        name = name.strip().lower()
        require(name not in fields, 'duplicate remote signer HTTP/2 header')
        fields[name] = value.strip()
    require(fields.get(b'content-type', b'').split(b';')[0] in (b'application/grpc', b'application/grpc+proto'),
            'remote signer PublicKey content type differs')
    require(len(body) >= 5, 'remote signer PublicKey frame is incomplete')
    compressed, length = struct.unpack('>BI', body[:5])
    require(compressed == 0 and length == 34 and len(body) >= 39 and body[5:7] == b'\x0a\x20',
            'remote signer returned an invalid Ed25519 PublicKey protobuf frame')
    trailers = body[39:].strip()
    status = None
    for line in trailers.split(b'\r\n'):
        if not line:
            continue
        name, colon, value = line.partition(b':')
        require(colon, 'invalid remote signer gRPC trailer')
        if name.strip().lower() == b'grpc-status':
            require(status is None, 'duplicate remote signer gRPC status')
            status = value.strip()
    require(status == b'0', 'remote signer PublicKey request failed')
    return base64.b64encode(body[7:39]).decode()


def public_key(context, state):
    profile = inputs(state['remote_signer'])
    original_ca = ca(context, state)
    result = context.command('/usr/bin/curl', '--disable', '--noproxy', '*', '--proto', '=https',
        '--connect-timeout', '10', '--max-time', '20', '--max-filesize', '32768', '--http2',
        '--silent', '--show-error', '--fail-with-body', '--include', '--cacert', str(context.path(CA)),
        '--request', 'POST', '--header', 'Content-Type: application/grpc', '--header', 'TE: trailers',
        '--data-binary', '@-', '--write-out', '\nERPC_RESULT=%{http_version}=%{http_code}\n',
        profile['endpoint'].rstrip('/') + METHOD, input=b'\0' * 5, check=False)
    require(result.returncode == 0 and len(result.stdout) <= 32768, 'remote signer public-key qualification failed')
    public = public_response(result.stdout)
    require(public == state['contract']['public_key'] and ca(context, state) == original_ca,
            'external signer is not the original consensus public key or CA changed')
    return {'public_key': public, 'transport': 'server-authenticated-tls',
            'image_and_pcr': 'operator-supplied', 'signing_history_protection': 'not-qualified'}
