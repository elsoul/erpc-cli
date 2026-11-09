# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Fixed supervisor artifacts. The vendor-managed child is not a fixed release."""
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import urllib.request

ROOT_UID = 0
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8', 'HOME': '/nonexistent'}
ORIGINS = ('https://binaries.hyperliquid.xyz/Mainnet/',
           'https://binaries.hyperliquid-testnet.xyz/Testnet/',
           'https://raw.githubusercontent.com/hyperliquid-dex/node/405cc08b17a727ee51b0f9128918955a84439915/')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def publish(path, body, mode=0o600):
    temporary = path.with_name(path.name + '.new')
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(body)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('supervisor artifact redirects are refused')


def download(url, destination, digest, maximum, exact_size=None):
    require(isinstance(url, str) and url.startswith(ORIGINS)
            and re.fullmatch('[a-f0-9]{64}', digest), 'unqualified supervisor artifact')
    require(type(maximum) is int and 0 < maximum <= 16_000_000, 'invalid artifact bound')
    request = urllib.request.Request(url, headers={'User-Agent': 'erpc-node-controller'})
    # The source boundary is explicit and carries no provider credentials.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)
    with opener.open(request, timeout=60) as response:
        require(response.status == 200 and response.geturl() == url, 'artifact source changed')
        data = response.read(maximum + 1)
    require(0 < len(data) <= maximum and (exact_size is None or len(data) == exact_size),
            'artifact size differs from its qualification')
    require(hashlib.sha256(data).hexdigest() == digest, 'artifact digest changed; review a new supervisor pin')
    publish(destination, data)


def run(args):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=ENV, timeout=120, check=False)
    require(result.returncode == 0 and len(result.stdout) <= 65536,
            'supervisor publisher verification failed')
    return result.stdout


def verify(directory, fingerprint, signed_at):
    require(re.fullmatch('[A-F0-9]{40}', fingerprint)
            and type(signed_at) is int and signed_at > 0, 'invalid publisher signature identity')
    home = directory / 'verify-home'
    home.mkdir(mode=0o700)
    ring = directory / 'publisher.gpg'
    run(['/usr/bin/gpg', '--batch', '--no-options', '--homedir', str(home), '--yes',
         '--dearmor', '--output', str(ring), str(directory / 'publisher.asc')])
    status = run(['/usr/bin/gpgv', '--homedir', str(home), '--status-fd=1', '--keyring',
                  str(ring), str(directory / 'hl-visor.asc'), str(directory / 'hl-visor')])
    signatures = [(line.split()[2], int(line.split()[4])) for line in status.decode('ascii').splitlines()
                  if line.startswith('[GNUPG:] VALIDSIG ')]
    require(signatures == [(fingerprint, signed_at)],
            'supervisor signer or publication time differs from qualification')


def install(root, profile, public_key):
    """Caller holds the host operation lock and has validated immutable ownership."""
    pin = profile['supervisor']
    require(re.fullmatch('visor-[a-f0-9]{16}', pin['id'])
            and pin['id'] == 'visor-' + pin['sha256'][:16], 'invalid supervisor release identity')
    directory = root / pin['id']
    if directory.exists() or directory.is_symlink():
        check(directory, pin, public_key)
        return directory
    stage = root / (pin['id'] + '.partial')
    if stage.exists() or stage.is_symlink():
        info = stage.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == ROOT_UID and info.st_mode & 0o077 == 0,
                'unowned supervisor stage cannot be adopted')
        shutil.rmtree(stage)
    require(shutil.disk_usage(root).free >= 100_000_000, 'insufficient supervisor installation space')
    stage.mkdir(mode=0o700)
    download(pin['url'], stage / 'hl-visor', pin['sha256'], 16_000_000, pin['size'])
    download(pin['signature_url'], stage / 'hl-visor.asc', pin['signature_sha256'], 8192)
    download(public_key['url'], stage / 'publisher.asc', public_key['sha256'], 8192)
    verify(stage, public_key['primary_fingerprint'], pin['signed_at'])
    # Do not execute a foreign architecture during qualification or install.
    header = (stage / 'hl-visor').read_bytes()[:64]
    require(len(header) == 64 and header[:6] == b'\x7fELF\x02\x01'
            and int.from_bytes(header[18:20], 'little') == 62,
            'supervisor is not the qualified little-endian x86_64 ELF')
    (stage / 'hl-visor').chmod(0o555)
    # Native GPG may read this fixed publisher key; the private root receipt and
    # verifier working files are not needed by the node account.
    (stage / 'publisher.asc').chmod(0o444)
    stage.chmod(0o755)
    sync_directory(stage)
    os.rename(stage, directory)
    sync_directory(root)
    check(directory, pin, public_key)
    return directory


def check(directory, pin, public_key):
    info = directory.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == ROOT_UID and info.st_mode & 0o7777 == 0o755,
            'supervisor release directory is unsafe or inaccessible')
    executable = directory / 'hl-visor'
    info = executable.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == ROOT_UID and info.st_mode & 0o7777 == 0o555,
            'supervisor executable permissions differ')
    fd = os.open(executable, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        content = stream.read(16_000_001)
    require(len(content) == pin['size'] and hashlib.sha256(content).hexdigest() == pin['sha256'],
            'supervisor executable differs from its reviewed digest')
    for name, expected in [('publisher.asc', public_key['sha256']), ('hl-visor.asc', pin['signature_sha256'])]:
        path = directory / name
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == ROOT_UID and not info.st_mode & 0o022,
                'publisher proof is not root controlled')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream:
            data = stream.read(8193)
        require(0 < len(data) <= 8192 and hashlib.sha256(data).hexdigest() == expected,
                'publisher proof differs from the qualification')
