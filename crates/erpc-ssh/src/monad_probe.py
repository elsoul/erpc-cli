# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
import json
import os
from pathlib import Path
import stat
import sys
request = json.loads(sys.stdin.buffer.read(32769))
owner = Path('/var/lib/erpc-monad/owner.json')
try:
    if owner.exists() or owner.is_symlink():
        for path in [*reversed(owner.parent.parents), owner.parent]:
            s = path.lstat()
            assert stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022
        fd = os.open(owner, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as f:
            s = os.fstat(f.fileno())
            assert stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600
            value = json.loads(f.read(32769))
        assert value['contract'] == request['contract']
        print('{"existing":true}')
    else:
        for name in ['/var/lib/erpc-monad', '/etc/erpc/monad', '/opt/erpc/monad', '/usr/local/lib/erpc/monad']:
            path = Path(name)
            assert not path.is_symlink() and (not path.exists() or not any(path.iterdir()))
        print('{"existing":false}')
except Exception:
    print('Monad host ownership mismatch or unowned artifacts', file=sys.stderr)
    sys.exit(1)
