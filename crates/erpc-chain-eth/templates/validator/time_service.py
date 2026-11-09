#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Choose a supported existing time service without replacing chrony or ntpd."""
import json
import sys

SERVICES = ('chrony.service', 'chronyd.service', 'ntp.service', 'ntpd.service', 'systemd-timesyncd.service')


def choose(services):
    for name in SERVICES:
        if services.get(name, {}).get('state') == 'running':
            return {'service': name, 'install_fallback': name == 'systemd-timesyncd.service'}
    for name in SERVICES:
        if name in services:
            return {'service': name, 'install_fallback': name == 'systemd-timesyncd.service'}
    return {'service': 'systemd-timesyncd.service', 'install_fallback': True}


if __name__ == '__main__':
    print(json.dumps(choose(json.load(sys.stdin))))
