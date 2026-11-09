#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Authenticate a small manifest with both carried public primary keys."""
import json
import hashlib
from pathlib import Path
import re
import subprocess
import sys
import tempfile

SIGNERS = {'E777299FC265DD04793070EB944D35F9AC3DB76A', '152812300785C96444D3334D17565732E08E5E41'}


def verify_status(status):
    valid = set()
    for line in status.splitlines():
        if not line.startswith('[GNUPG:] '):
            continue
        fields = line[9:].split()
        if not fields:
            continue
        if fields[0] in {'BADSIG', 'EXPSIG', 'EXPKEYSIG', 'REVKEYSIG', 'FAILURE', 'NODATA'}:
            raise ValueError('invalid release signature')
        if fields[0] == 'VALIDSIG':
            if len(fields) not in (10, 11) or fields[8] not in {'8', '9', '10'} or fields[9] != '00':
                raise ValueError('unsupported release signature')
            primary = fields[10] if len(fields) == 11 else fields[1]
            if primary in SIGNERS:
                valid.add(primary)
    if valid != SIGNERS:
        raise ValueError('both pinned primary signatures are required')


def checksum(manifest, wanted):
    entries = {}
    for line in manifest.splitlines():
        if not line:
            continue
        pair = line.split('  ')
        if len(pair) != 2 or not re.fullmatch('[a-fA-F0-9]{64}', pair[0]) or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]*', pair[1]) or pair[1] in entries:
            raise ValueError('malformed or duplicate manifest entry')
        entries[pair[1]] = pair[0].lower()
    if wanted not in entries:
        raise ValueError('archive not present in signed manifest')
    return entries[wanted]


def verify_archive(path, expected):
    archive = Path(path)
    if archive.is_symlink() or not archive.is_file() or not re.fullmatch('[a-f0-9]{64}', expected):
        raise ValueError('invalid archive or digest')
    digest = hashlib.sha256()
    with archive.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    if digest.hexdigest() != expected:
        raise ValueError('archive digest mismatch')


def main():
    if len(sys.argv) == 4 and sys.argv[1] == 'archive':
        verify_archive(sys.argv[2], sys.argv[3])
        return
    manifest, signature, keydir, archive, expected = sys.argv[1:]
    with tempfile.TemporaryDirectory() as home:
        for key in ['fanquake.asc', 'achow101.asc']:
            subprocess.run(['gpg', '--batch', '--no-options', '--homedir', home, '--import', str(Path(keydir) / key)], check=True, capture_output=True)
        exported = subprocess.run(['gpg', '--batch', '--no-options', '--homedir', home, '--export'], check=True, capture_output=True)
        keyring = Path(home) / 'trustedkeys.gpg'
        keyring.write_bytes(exported.stdout)
        result = subprocess.run(['gpgv', '--homedir', home, '--keyring', str(keyring), '--status-fd', '1', signature, manifest], check=False, capture_output=True, text=True)
        verify_status(result.stdout)
        actual = checksum(Path(manifest).read_text(), archive)
        if actual != expected:
            raise ValueError('authenticated manifest differs from stored archive pin')
        print(json.dumps({'sha256': actual, 'trusted_signatures': len(SIGNERS)}))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Bitcoin manifest authentication failed', file=sys.stderr)
        sys.exit(1)
