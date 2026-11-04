#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Authenticate a pinned release and compile a non-signing native API adapter."""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'}


def signature(status, primary, signing):
    records = [line.split() for line in status.splitlines() if line.startswith('[GNUPG:] ')]
    bad = {'BADSIG', 'ERRSIG', 'EXPSIG', 'EXPKEYSIG', 'REVKEYSIG', 'NO_PUBKEY'}
    if any(len(row) > 1 and row[1] in bad for row in records):
        raise ValueError('release signature is invalid, expired or revoked')
    valid = [row for row in records if len(row) >= 11 and row[1] == 'VALIDSIG']
    if len(valid) != 1:
        raise ValueError('expected one valid release signature')
    row = valid[0]
    actual_primary = row[11] if len(row) >= 12 else row[2]
    if row[2] != signing or actual_primary != primary:
        raise ValueError('release signer belongs to another network or unreviewed key')


def main():
    if len(sys.argv) != 9:
        raise ValueError('expected release, public key, fingerprints, JVM and adapter source')
    release, key, primary, signing, java, major, javac, source = sys.argv[1:]
    with tempfile.TemporaryDirectory(prefix='tron-gpg-', dir='/run') as home:
        command = ['/usr/bin/gpg', '--batch', '--no-tty', '--no-autostart', '--no-auto-key-retrieve', '--homedir', home]
        subprocess.run(command + ['--import', key], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=ENV)
        result = subprocess.run(command + ['--status-fd', '1', '--verify', str(Path(release) / 'FullNode.jar.sig'), str(Path(release) / 'FullNode.jar')],
                                check=True, capture_output=True, text=True, env=ENV)
        signature(result.stdout, primary, signing)
    result = subprocess.run([java, '-XshowSettings:properties', '-version'], check=True, capture_output=True, text=True, timeout=30, env=ENV)
    match = re.search(r'^\s*java.specification.version\s*=\s*(\S+)', result.stderr, re.M)
    if not match or match[1] != ('1.8' if major == '8' else '17' if major == '17' else ''):
        raise ValueError('JVM major does not match the reviewed CPU architecture')
    # Disable annotation processors from the client classpath. Compilation does
    # not run the node or load/decrypt a credential.
    subprocess.run([javac, '-proc:none', '-cp', str(Path(release) / 'FullNode.jar'), '-d', str(Path(release) / 'erpc'), source],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120, env=ENV)
    print('TRON release signature and JVM verified; inspection adapter compiled')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('TRON release/platform verification failed', file=sys.stderr)
        raise SystemExit(1)

