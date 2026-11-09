#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Immutable helper publication and authenticated systemd entry before credentials."""
import os
import pathlib
from arc_files import digest, require

NAMESPACE = '/usr/local/lib/erpc/arc'


def profile(folder):
    names = sorted(item.name for item in folder.iterdir() if item.name != '__pycache__')
    require(names and len(names) <= 16 and 'control.py' in names and
            all((name.endswith('.py') or name == 'networks.json') and name.replace('_', '').replace('.', '').isalnum() for name in names),
            'unexpected Arc helper profile')
    return names


def source(c, folder):
    names = profile(folder)
    values = []
    for name in names:
        relative = '/' + str((folder / name).relative_to(c.root))
        values.append(c.read(relative))
    return names, values, digest(b''.join(values))


def publish(c, folder, expected):
    names, values, identity = source(c, folder)
    require(identity == expected, 'carried Arc helpers differ from the sealed profile')
    namespace = c.protected(NAMESPACE, missing=True, directory=True)
    c.mkdir(NAMESPACE, mode=0o755)
    c.mkdir(NAMESPACE + '/releases', mode=0o755)
    destination = NAMESPACE + '/releases/' + identity
    target = c.protected(destination, missing=True, directory=True)
    if target.exists():
        actual_names, _, actual_hash = source(c, target)
        require(actual_names == names and actual_hash == identity, 'installed Arc helper release changed')
    else:
        pending = destination + '.pending'
        staged = c.protected(pending, missing=True, directory=True)
        if staged.exists():
            require(set(os.listdir(staged)) <= set(names) | {name + '.pending' for name in names},
                    'unknown files in incomplete Arc helper publication')
        c.mkdir(pending, mode=0o755)
        for name, raw in zip(names, values):
            c.write_bytes(pending + '/' + name, raw, 0o644)
        require(source(c, staged)[2] == identity, 'staged Arc helpers did not read back')
        os.rename(staged, target)
        c.sync(target.parent)
    # Replay the directory barrier even when a failed rename fsync left the
    # immutable release visible. Never point current at an undurable release.
    c.sync(target)
    current = namespace / 'current'
    for link in (current, namespace / 'current.pending'):
        if link.is_symlink():
            info = link.lstat()
            require(info.st_uid == c.owner and os.readlink(link).startswith('releases/') and
                    len(os.readlink(link)) == len('releases/') + 64,
                    'Arc helper pointer is unsafe')
        else:
            require(not link.exists(), 'Arc helper pointer is not a symbolic link')
    pending = namespace / 'current.pending'
    if pending.is_symlink():
        pending.unlink()
    pending.symlink_to('releases/' + identity)
    c.sync(namespace)
    os.replace(pending, current)
    c.sync(namespace)
    return identity


def systemd_command(folder, identity, action, component):
    require(action in ('condition', 'guard', 'snapshot-complete', 'firewall-load') and
            component in ('execution', 'consensus', 'snapshots', 'firewall'),
            'invalid Arc systemd helper action')
    names = profile(folder)
    trust = (folder / 'arc_trust.py').read_text()
    release = (folder / 'arc_helper_release.py').read_text()
    # Canonical common trust/release functions are unchanged. The outer exception
    # boundary also maps pre-import trust failures to condition-failure 255.
    body = (trust + '\n' + release + '\nimport runpy,sys\n'
            + 'selected=trusted_release(' + repr(NAMESPACE) + ', ' + repr([names]) + ')\n'
            + 'if selected != ' + repr(NAMESPACE + '/releases/' + identity) + ': raise ValueError("Arc helper generation differs")\n'
            + 'sys.argv=[selected+"/control.py",' + repr(action) + ',' + repr(component) + ']\n'
            + 'runpy.run_path(selected+"/control.py",run_name="__main__")\n')
    outer = 'import sys\ntry:\n exec(' + repr(body) + ')\nexcept BaseException as error:\n'
    outer += ' if isinstance(error,SystemExit) and error.code in (0,None): raise\n raise SystemExit(255)\n'
    invocation = "exec(bytes.fromhex('" + outer.encode().hex() + "').decode())"
    return '/usr/bin/python3 -I -c "' + invocation + '"'
