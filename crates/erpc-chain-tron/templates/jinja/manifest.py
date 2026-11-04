#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Record only verified public artifacts; caller already owns the host run lock."""
import json
import os
from pathlib import Path
import sys
from control import Control, digest
from identity import unique_object


def main():
    if len(sys.argv) != 4:
        raise ValueError('expected release directory, intent and exact reviewed target')
    directory, intent, raw = sys.argv[1:]
    target = json.loads(raw, object_pairs_hook=unique_object)
    controller = Control()
    contract = controller.read('/etc/tron/contract.json')
    controller.phase(contract, intent, target)
    if directory != '/opt/tron/releases/' + target['tag'] + '-' + target['architecture']:
        raise ValueError('manifest directory differs from the intended target')
    root = Path(directory)
    if digest(root / 'FullNode.jar') != target['jar_sha256'] or digest(root / 'network.conf') != target['config_sha256']:
        raise ValueError('installed release/config digest changed')
    value = dict(directory=directory, network=target['network'], architecture=target['architecture'],
                 genesis=target['genesis'], client_version=target['version'], target=target,
                 jar_sha256=target['jar_sha256'], config_sha256=target['config_sha256'],
                 inspector_sha256=digest(root / 'erpc/ErpcTronKey.class'),
                 node_config_sha256=digest(Path('/etc/tron/node.conf')))
    pending = Path('/etc/tron/release.pending')
    pending.write_text(json.dumps(value, sort_keys=True))
    os.chmod(pending, 0o640)
    os.replace(pending, '/etc/tron/release.json')


if __name__ == '__main__':
    main()

