#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Validator-only authority paths; shared descriptor primitives stay unchanged."""
import os
import pathlib

from arc_files import Files as BaseFiles

ROOT = '/etc/erpc/arc-validator/authority'
HOME = '/var/lib/erpc-arc-validator'
NAMESPACE = '/usr/local/lib/erpc/arc-validator'


class Files(BaseFiles):
    def __init__(self, root=pathlib.Path('/'), **kwargs):
        super().__init__(root, **kwargs)
        self.ROOT = self.path(ROOT)

    def save(self, state):
        self.write(ROOT + '/owner.json', state)

    def mkdir(self, name, mode=0o700):
        target = self.protected(name, missing=True, directory=True)
        current = self.root
        for component in target.relative_to(self.root).parts:
            current /= component
            virtual = '/' + str(current.relative_to(self.root))
            created = False
            try:
                current.mkdir(mode=0o700)
                created = True
            except FileExistsError:
                pass
            self.protected(virtual, directory=True)
            # Replay the target mode/barrier after a previous mkdir succeeded but
            # its chmod/publication did not. Existing global ancestors stay untouched.
            if created or current == target:
                descriptor = os.open(current, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    info = os.fstat(descriptor)
                    named = current.lstat()
                    self.require((info.st_dev, info.st_ino) == (named.st_dev, named.st_ino),
                                 'Arc validator directory changed before publication')
                    os.fchmod(descriptor, mode if current == target else 0o755)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            self.sync(current)
        return target
