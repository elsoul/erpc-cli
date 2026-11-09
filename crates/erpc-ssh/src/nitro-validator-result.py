# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Read one completed sealed run's bounded public validator result, without importing installed helpers."""
import json
import os
from pathlib import Path
import re
import stat
import sys


def protected(info, owner, directory=False):
    valid = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1
    if not valid or info.st_uid != owner or info.st_mode & 0o022:
        raise ValueError('untrusted public-result path')


def read(parent, name, owner):
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    with os.fdopen(descriptor, 'rb') as stream:
        protected(os.fstat(stream.fileno()), owner)
        raw = stream.read(262145)
        if len(raw) > 262144:
            raise ValueError('public result exceeds limit')
        return json.loads(raw)


PROFILES = {
    'arbitrum': ('validator/ansible/control.yml', 'validator-public-result.json', 'erpc-arbitrum-public-result-v1'),
    'robinhood-defensive': ('validator/ansible/control.yml', 'validator-public-result.json', 'erpc-robinhood-defensive-result-v1'),
    'robinhood-admission': ('robinhood-admission/control.yml', 'robinhood-admission-public-result.json', 'erpc-robinhood-admission-public-result-v1'),
}


def result(run, root=Path('/'), owner=0, profile='arbitrum'):
    if profile not in PROFILES:
        raise ValueError('unsupported public-result profile')
    play, filename, schema = PROFILES[profile]
    if not re.fullmatch('r-[a-z0-9-]{8,40}', run):
        raise ValueError('invalid public-result run')
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        protected(os.fstat(descriptor), owner, True)
        for part in ('opt', 'erpc', 'runs', run):
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            protected(os.fstat(descriptor), owner, True)
        completed = read(descriptor, 'result.json', owner)
        if (not isinstance(completed, dict) or completed.get('status') != 'ok'
                or type(completed.get('exit_code')) is not int or completed['exit_code'] != 0
                or completed.get('play') != play):
            raise ValueError('public result requires successful exact control run')
        sealed = read(descriptor, 'sealed.json', owner)
        public = read(descriptor, filename, owner)
        if (not isinstance(public, dict)
                or set(public) != {'schema', 'run', 'bundle_sha256', 'helpers_sha256', 'request_sha256', 'result'}
                or public['schema'] != schema or public['run'] != run
                or not isinstance(sealed, dict) or sealed.get('bundle') != public['bundle_sha256']
                or not isinstance(public['result'], dict)):
            raise ValueError('public-result envelope differs from sealed run')
        for field in ('bundle_sha256', 'helpers_sha256', 'request_sha256'):
            if not isinstance(public[field], str) or not re.fullmatch('[a-f0-9]{64}', public[field]):
                raise ValueError('invalid public-result digest')
        return public
    finally:
        os.close(descriptor)


def main():
    try:
        if len(sys.argv) not in (2, 3) or os.geteuid() != 0 or not sys.flags.isolated:
            raise ValueError('invalid isolated result reader invocation')
        print(json.dumps(result(sys.argv[1], profile=sys.argv[2] if len(sys.argv) == 3 else 'arbitrum'), separators=(',', ':'), sort_keys=True))
    except BaseException:
        print('Nitro public result could not be authenticated', file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
