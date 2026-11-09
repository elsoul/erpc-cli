# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Native service definitions with independent gateway ACLs and startup receipts."""
import ipaddress
from erpc_monad_common import ROOT, CONFIG, RELEASES, HELPERS, atomic, digest, require
from erpc_monad_entry import command as entrypoint
from erpc_monad_accounts import account_plan,NATIVE,GATEWAY


def allow(values, public=False):
    require(isinstance(values, list) and len(values) <= 64, 'invalid allow list')
    result = []
    for value in values:
        require(isinstance(value, str), 'invalid allow range')
        network = ipaddress.ip_network(value, strict=True)
        require(public or network.prefixlen != 0, 'management/monitoring cannot allow every address')
        result.append(str(network))
    return sorted(set(result))


def service(c, name, command, cpus, identities,extra=''):
    guard = entrypoint()+' guard '+c["owner"]
    condition = entrypoint(condition=True)+' condition '+c["owner"]
    native=identities[NATIVE]
    return f'''[Unit]
Description=ERPC Monad {name}
Requires=erpc-monad-firewall.service erpc-monad-memory.service
After=network-online.target erpc-monad-firewall.service erpc-monad-memory.service
Wants=network-online.target
RequiresMountsFor=/var/lib/erpc-monad/data /etc/erpc/monad /opt/erpc/monad
[Service]
User={native['uid']}
Group={native['gid']}
ExecCondition=+{condition}
ExecStartPre=+{guard}
ExecStart={command}
WorkingDirectory={ROOT}/data
Environment=LD_LIBRARY_PATH={RELEASES}/0.16.5/lib
Environment=HOME=/var/lib/erpc-monad/data
Restart=on-failure
RestartSec=5
TimeoutStopSec=150
KillMode=control-group
LimitNOFILE=1048576
LimitMEMLOCK=infinity
LimitCORE=0
UMask=0077
AllowedCPUs={cpus}
CPUAffinity={cpus}
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths={ROOT}/data
DevicePolicy=closed
DeviceAllow=/dev/disk/by-partuuid/{c['partuuid']} rw
{extra}
[Install]
WantedBy=multi-user.target
'''


def render(catalog, c, cpus, rpc_allow, monitoring_allow, identities):
    account_plan(identities)
    native=identities[NATIVE];gateway=identities[GATEWAY]
    binary = str(RELEASES / catalog['version'] / 'bin')
    data, conf = str(ROOT / 'data'), str(CONFIG)
    device = '/dev/disk/by-partuuid/' + c['partuuid']
    cfg = '--node-config ' + conf + '/node.toml'
    bft = f'{binary}/monad-node --secp-identity %d/monad-secp --bls-identity %d/monad-bls {cfg} ' + \
        f'--forkpoint-config {data}/forkpoint/forkpoint.toml --wal-path {data}/wal ' + \
        f'--mempool-ipc-path {data}/mempool.sock --control-panel-ipc-path {data}/controlpanel.sock ' + \
        f'--statesync-ipc-path {data}/statesync.sock --ledger-path {data}/ledger --triedb-path {device} ' + \
        f'--triedb-stats-path {data}/triedb-stats --statesync-sq-thread-cpu {cpus[8]} ' + \
        f'--validators-path {data}/validators/validators.toml --persisted-peers-path {data}/peers.toml'
    execution = f'{binary}/monad --chain {catalog["networks"][c["network"]]["execution_chain"]} ' + \
        f'--db {device} --block_db {data}/ledger --statesync {data}/statesync.sock ' + \
        f'--db-stats-file {data}/triedb-stats --sq_thread_cpu {cpus[1]} --log_level INFO'
    rpc = f'{binary}/monad-rpc --ipc-path {data}/mempool.sock --triedb-path {device} {cfg} --rpc-addr 127.0.0.1 --rpc-port 8080'
    affinity = lambda indexes: ' '.join(str(cpus[i]) for i in indexes)
    result = {
        'erpc-monad-memory.service': f'''[Unit]
Description=Reserve native Monad hugepages
Requires=erpc-monad-firewall.service
After=erpc-monad-firewall.service
Before=erpc-monad-bft.service erpc-monad-execution.service erpc-monad-rpc.service
[Service]
Type=oneshot
ExecStart={entrypoint()} memory {c['owner']}
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
''',
        'erpc-monad-bft.service': service(c, 'consensus', bft, affinity(range(8,12)),identities,
            f'LoadCredentialEncrypted=monad-secp:{conf}/monad-secp.cred\nLoadCredentialEncrypted=monad-bls:{conf}/monad-bls.cred'),
        'erpc-monad-execution.service': service(c, 'execution', execution, affinity(range(1,8)),identities),
        'erpc-monad-rpc.service': service(c, 'RPC', rpc, affinity(range(12,16)),identities),
        'erpc-monad-firewall.service': f'''[Unit]
Description=Restore the confirmed Monad firewall
Before=erpc-monad-bft.service erpc-monad-execution.service erpc-monad-rpc.service erpc-monad-gateway.service
After=network-pre.target nftables.service
Wants=network-pre.target
[Service]
Type=oneshot
ExecStart={entrypoint()} firewall-load {c['owner']}
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
''',
        'erpc-monad-gateway.service': f'''[Unit]
Description=ERPC Monad RPC gateway
Requires=erpc-monad-firewall.service
After=network-online.target erpc-monad-firewall.service
[Service]
User={gateway['uid']}
Group={gateway['gid']}
ExecStartPre=+{entrypoint()} guard {c['owner']}
ExecStartPre=/usr/sbin/nginx -t -c {CONFIG}/nginx.conf -p /run/erpc-monad-gateway
ExecStart=/usr/sbin/nginx -c {CONFIG}/nginx.conf -p /run/erpc-monad-gateway -g 'daemon off;'
RuntimeDirectory=erpc-monad-gateway
RuntimeDirectoryMode=0700
Restart=on-failure
KillMode=control-group
LimitCORE=0
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/run/erpc-monad-gateway
PrivateTmp=true
[Install]
WantedBy=multi-user.target
''',
        'erpc-monad-cleanup.service': f'''[Unit]
Description=Retain recent Monad ledger and checkpoint history
[Service]
Type=oneshot
User={native['uid']}
Group={native['gid']}
ExecStartPre=+{entrypoint()} guard {c['owner']}
ExecStart={entrypoint('cleanup.py')}
LimitCORE=0
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths={ROOT}/data
ProtectHome=true
PrivateTmp=true
''',
        'erpc-monad-cleanup.timer': '''[Unit]
Description=Monad history retention
[Timer]
OnBootSec=1h
OnUnitActiveSec=1h
Unit=erpc-monad-cleanup.service
[Install]
WantedBy=timers.target
'''}
    # Secrets are only systemd credential paths; no password in argv/environment.
    for name, value in result.items():
        result[name] = value.replace('/0.16.5/lib', '/' + catalog['version'] + '/lib')
    acl = lambda values: ''.join('        allow ' + value + ';\n' for value in values) + '        deny all;\n'
    result['nginx.conf'] = '''worker_processes auto;
error_log stderr warn;
pid /run/erpc-monad-gateway/nginx.pid;
events { worker_connections 4096; }
http {
    access_log off;
    client_max_body_size 2m;
    client_body_temp_path /run/erpc-monad-gateway/client;
    proxy_temp_path /run/erpc-monad-gateway/proxy;
    server {
        listen 8545;
        listen [::]:8545;
''' + acl(allow(rpc_allow, True)) + '''        location / {
            proxy_pass http://127.0.0.1:8080;
            proxy_read_timeout 60s;
            proxy_buffering off;
        }
    }
    server {
        listen 9144;
        listen [::]:9144;
''' + acl(allow(monitoring_allow)) + '''        location = /metrics { proxy_pass http://127.0.0.1:9143/metrics; }
        location / { return 404; }
    }
}
'''
    return result


def install(catalog, c, cpus, rpc_allow, monitoring_allow,identities):
    files = render(catalog, c, cpus, rpc_allow, monitoring_allow,identities)
    receipt = {}
    for name, content in files.items():
        path = CONFIG / name if name == 'nginx.conf' else __import__('pathlib').Path('/etc/systemd/system') / name
        atomic(path, content.encode(), 0o644)
        receipt[str(path)] = digest(content.encode())
    receipt[str(CONFIG / 'node.toml')] = digest((CONFIG / 'node.toml').read_bytes())
    return receipt
