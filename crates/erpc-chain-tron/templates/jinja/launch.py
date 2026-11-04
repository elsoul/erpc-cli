#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Start the verified client as the service user; password is an inherited stdin FD."""
import json
import os
from pathlib import Path
import sys

JAVA = {
    'x86_64': '/usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java',
    'aarch64': '/usr/lib/jvm/java-17-openjdk-arm64/bin/java',
}


def arguments(contract):
    architecture, role = contract['architecture'], contract['role']
    if architecture not in JAVA or role not in ('fullnode', 'validator'):
        raise ValueError('unsupported TRON service profile')
    args = [JAVA[architecture], '-Xmx24g' if role == 'validator' else '-Xmx12g']
    if architecture == 'x86_64':
        args += ['-Xms9g', '-XX:+UseConcMarkSweepGC', '-XX:+CMSParallelRemarkEnabled',
                 '-XX:+PrintGCDetails', '-XX:+PrintGCDateStamps', '-Xloggc:/var/log/tron/gc.log',
                 '-XX:+UseGCLogFileRotation', '-XX:NumberOfGCLogFiles=5', '-XX:GCLogFileSize=20M', '-XX:NewRatio=2']
    else:
        args += ['-XX:+UseZGC', '-Xlog:gc,gc+heap:file=/var/log/tron/gc.log:time,tags,level:filecount=5,filesize=20M']
    args += ['-XX:ReservedCodeCacheSize=256m', '-XX:+UseCodeCacheFlushing',
             '-XX:MetaspaceSize=256m', '-XX:MaxMetaspaceSize=512m', '-XX:MaxDirectMemorySize=1g',
             '-XX:-HeapDumpOnOutOfMemoryError', '-XX:ErrorFile=/dev/null',
             '-Dlogback.configurationFile=/etc/tron/logback.xml',
             '-jar', '/opt/tron/current/FullNode.jar', '-c', '/etc/tron/node.conf', '-d', '/var/lib/tron']
    if role == 'validator':
        args.append('--witness')
    return args


def main():
    contract = json.loads(Path('/etc/tron/contract.json').read_text())
    args = arguments(contract)
    path = '/run/credentials/tron-node.service/witness-password' if contract['role'] == 'validator' else '/dev/null'
    descriptor = os.open(path, os.O_RDONLY)
    os.dup2(descriptor, 0)
    if descriptor != 0:
        os.close(descriptor)
    os.execve(args[0], args, {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'})


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('TRON launch profile or private credential input unavailable', file=sys.stderr)
        raise SystemExit(1)

