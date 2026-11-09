# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Explicit original numeric credential recipient and isolated publisher process."""
from pathlib import Path
import re
from erpc_aqa_common import ROOT,CONFIG,HELPERS,UNIT,RUNTIME_FILES,require

FIREWALL_UNIT='erpc-hyperliquid-aqa-firewall.service'
OBSERVER='erpc-hyperliquid-aqa-observe.service'
TIMER='erpc-hyperliquid-aqa-observe.timer'


def bootstrap(condition=False):
    trust=(Path(__file__).parent/'erpc_aqa_trust.py').read_text()
    body='selected=trusted_release('+repr(str(HELPERS))+','+repr([list(RUNTIME_FILES)])+')\nrunpy.run_path(selected+"/control.py",run_name="__main__")'
    if condition:
        body=('try:\n'+''.join('    '+line+'\n' for line in body.splitlines())
              +'except BaseException as error:\n'
              +'    if isinstance(error,SystemExit) and error.code in (None,0): raise\n'
              +'    print("AQA startup authority verification failed",file=sys.stderr)\n'
              +'    raise SystemExit(255) from None\n')
    program=trust+'\nimport runpy,sys\n'+body
    return '/usr/bin/python3 -I -c "exec(bytes.fromhex(\''+program.encode().hex()+'\'))"'


def render(contract,identity):
    require(re.fullmatch('[a-f0-9]{32}',contract['owner']) and set(identity)=={'uid','gid'}
            and type(identity['uid'])is int and identity['uid']==identity['gid'] and 100<=identity['uid']<=999,
            'original AQA runtime account required')
    controller=bootstrap();owner=contract['owner']
    return {
        UNIT:f'''[Unit]
Description=Original dedicated Hyperliquid AQA agent publisher
Requires={FIREWALL_UNIT}
After=network-online.target {FIREWALL_UNIT}
Wants=network-online.target
[Service]
Type=exec
User={identity['uid']}
Group={identity['gid']}
WorkingDirectory=/
LoadCredentialEncrypted=.env:{CONFIG}/credentials/agent.cred
ExecCondition=+{bootstrap(condition=True)} condition {owner}
ExecStartPre=+{controller} guard {owner}
ExecStart={controller} launch {owner}
UnsetEnvironment=PUBLISHER_PRIVATE_KEY NETWORK RUST_LOG LD_PRELOAD LD_LIBRARY_PATH PYTHONPATH PYTHONHOME HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy
StandardOutput=null
StandardError=null
KillMode=control-group
KillSignal=SIGTERM
SendSIGKILL=no
TimeoutStopSec=120
TimeoutStartSec=180
Restart=on-failure
RestartSec=30
UMask=0077
LimitCORE=0
MemoryMax=1G
TasksMax=128
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
[Install]
WantedBy=multi-user.target
''',
        FIREWALL_UNIT:f'''[Unit]
Description=Restore original AQA management filtering
Before={UNIT} {OBSERVER}
After=network-pre.target nftables.service
Wants=network-pre.target
[Service]
Type=oneshot
ExecStart={controller} firewall-load {owner}
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
''',
        OBSERVER:f'''[Unit]
Description=Verify original AQA agent approval and process authority
After={FIREWALL_UNIT}
[Service]
Type=oneshot
User=root
ExecStart={controller} observe {owner}
TimeoutStartSec=180
UMask=0077
LimitCORE=0
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_KILL CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths={ROOT}
''',
        TIMER:f'''[Unit]
Description=Original AQA approval observation interval
[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
Unit={OBSERVER}
[Install]
WantedBy=timers.target
'''}
