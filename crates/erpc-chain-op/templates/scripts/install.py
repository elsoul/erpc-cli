#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Verify fixed release artifacts before extracting a binary or selecting an image."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile

SIGNER = '5EFE7BCFCD85682711F9FC30904841FFEBD38BAD'


def require(value):
    if not value:
        raise ValueError('release verification failed')


def call(args):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            check=False, timeout=180, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    require(result.returncode == 0)
    return result.stdout


def signature(status):
    valid = False
    for line in status.splitlines():
        if not line.startswith('[GNUPG:] '):
            continue
        parts = line[9:].split()
        require(parts)
        require(parts[0] not in {'BADSIG', 'EXPSIG', 'EXPKEYSIG', 'REVKEYSIG', 'FAILURE', 'NODATA', 'ERRSIG'})
        if parts[0] == 'VALIDSIG':
            require(len(parts) in (10, 11) and parts[8] in {'8', '9', '10'} and parts[9] == '00')
            primary = parts[10] if len(parts) == 11 else parts[1]
            require(primary == SIGNER)
            valid = True
    require(valid)


def base_archive(archive, detached, public_key, digest, program, destination):
    require(program in {'base-reth-node', 'base-consensus'} and re.fullmatch('[a-f0-9]{64}', digest))
    require(archive.is_file() and not archive.is_symlink() and not destination.is_symlink())
    with archive.open('rb') as stream:
        actual = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            actual.update(chunk)
        require(actual.hexdigest() == digest)
    with tempfile.TemporaryDirectory() as temporary:
        home = Path(temporary)
        call(['gpg', '--batch', '--no-options', '--homedir', str(home), '--import', str(public_key)])
        keyring = home / 'trustedkeys.gpg'
        keyring.write_bytes(call(['gpg', '--batch', '--no-options', '--homedir', str(home), '--export']))
        status = call(['gpgv', '--homedir', str(home), '--keyring', str(keyring), '--status-fd', '1', str(detached), str(archive)])
        signature(status.decode())
    with tarfile.open(archive, mode='r:gz') as source:
        entries = [entry for entry in source if Path(entry.name).name == program]
        require(len(entries) == 1 and entries[0].isfile() and entries[0].size < 2 * 1024 * 1024 * 1024)
        data = source.extractfile(entries[0])
        require(data is not None)
        # No tar paths, ownership, symlinks or mode bits are applied to the host.
        destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        tmp = destination.with_name(destination.name + '.new')
        require(not tmp.is_symlink())
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o755)
        with os.fdopen(fd, 'wb') as out:
            while chunk := data.read(1024 * 1024):
                out.write(chunk)
            out.flush()
            os.fsync(out.fileno())
        require(tmp.stat().st_size == entries[0].size)
        os.chmod(tmp, 0o755)
        os.replace(tmp, destination)


def image(config, reference, architecture, program):
    require(program in {'op-node', 'op-reth'} and architecture in {'amd64', 'arm64'})
    require(re.fullmatch('us-docker.pkg.dev/oplabs-tools-artifacts/images/' + program + '@sha256:[a-f0-9]{64}', reference))
    result = json.loads(call(['docker', '--config', str(config), 'image', 'inspect', reference]))
    require(isinstance(result, list) and len(result) == 1)
    data = result[0]
    require(data.get('Architecture') == architecture and data.get('Os') == 'linux')
    require(reference in data.get('RepoDigests', []))
    settings = data.get('Config', {})
    require(settings.get('Entrypoint') == ['/usr/local/bin/op-reth'] if program == 'op-reth' else settings.get('Entrypoint') in (None, []))
    env = settings.get('Env', [])
    require(isinstance(env, list) and all(value.split('=', 1)[0] in {'PATH', 'SSL_CERT_FILE'} for value in env))


if __name__ == '__main__':
    try:
        if len(sys.argv) == 8 and sys.argv[1] == 'base':
            _, _, archive, detached, key, digest, program, destination = sys.argv
            base_archive(Path(archive), Path(detached), Path(key), digest, program, Path(destination))
        elif len(sys.argv) == 6 and sys.argv[1] == 'image':
            image(Path(sys.argv[2]), *sys.argv[3:])
        else:
            raise ValueError('invalid verification request')
    except Exception:
        print('Pinned follower release verification failed', file=sys.stderr)
        sys.exit(1)
