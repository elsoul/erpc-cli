# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Fixed follower/validator topology with original numeric credential recipients."""
import re
from pathlib import Path
from erpc_hl_common import RUNTIME_PROFILES, require

ROOT = '/var/lib/erpc-hyperliquid'
CONF = '/etc/hyperliquid'
HELPERS = '/usr/local/lib/erpc/hyperliquid'
HOME = ROOT + '/home'


def controller_bootstrap(condition=False):
    # The inline program authenticates the complete immutable release before
    # loading any installed controller code. No replaceable script is its own
    # authority check; systemd performs no shell expansion of these hex bytes.
    trust = (Path(__file__).parent / 'erpc_hl_trust.py').read_text()
    invocation=('selected=trusted_release('+repr(HELPERS)+','+repr([list(profile) for profile in RUNTIME_PROFILES])
                +')\nrunpy.run_path(selected + "/control.py",run_name="__main__")')
    if condition:
        # v255 treats exit1..254 as a successful condition skip. Convert outer
        # path/profile/import failures as well as inner nonzero SystemExit.
        invocation=('try:\n'+''.join('    '+line+'\n' for line in invocation.splitlines())
            +'except SystemExit as error:\n    if error.code not in (None,0):\n        raise SystemExit(255) from None\n    raise\n'
            +'except BaseException:\n    print("Hyperliquid startup condition authentication failed",file=sys.stderr)\n    raise SystemExit(255) from None\n')
    program=trust+'\nimport runpy,sys\n'+invocation
    return '/usr/bin/python3 -I -c "exec(bytes.fromhex(\'' + program.encode().hex() + '\'))"'


def render(contract, pin, identities, mode='follower'):
    require(contract.get('role') in ('rpc','validator') and re.fullmatch('[a-f0-9]{32}', contract.get('owner', '')),
            'an owned native profile is required')
    require(mode in ('follower','validator') and (contract['role']=='validator' or mode=='follower'),
            'validator startup requires its separate owned profile')
    if contract['role']=='validator':
        from erpc_hl_validator import public_identity
        public_identity(contract)
    active=mode=='validator'
    names=('erpc-hyperliquid','erpc-hyperliquid-rpc')
    require(isinstance(identities,dict) and set(identities)==set(names)
            and all(set(value)=={'uid','gid'} and type(value['uid']) is int and type(value['gid']) is int
                    and 100<=value['uid']<=999 and value['uid']==value['gid'] for value in identities.values())
            and identities[names[0]]['uid']!=identities[names[1]]['uid'],
            'unit requires the original numeric service identities')
    native=identities[names[0]];gateway=identities[names[1]]
    require(re.fullmatch('visor-[a-f0-9]{16}', pin.get('id', '')), 'invalid supervisor selector')
    require(contract['network'] in ('mainnet', 'testnet'), 'unsupported network')
    guard = controller_bootstrap() + ' guard ' + contract['owner']
    native_guard = controller_bootstrap() + (' guard-validator ' if active else ' guard ') + contract['owner']
    condition = controller_bootstrap(condition=True) + ' condition ' + contract['owner']
    base = '''[Unit]
Requires=erpc-hyperliquid-firewall.service
After=network-online.target erpc-hyperliquid-firewall.service
Wants=network-online.target
RequiresMountsFor=/var/lib/erpc-hyperliquid /etc/hyperliquid /opt/erpc/hyperliquid
[Service]
Type=simple
Restart=on-failure
RestartSec=10
KillMode=control-group
TimeoutStopSec=1800
SendSIGKILL=no
LimitCORE=0
UMask=0077
NoNewPrivileges=yes
ProtectHome=yes
ProtectSystem=strict
PrivateTmp=yes
'''
    binds = f'BindReadOnlyPaths={CONF}/visor.json:{HOME}/visor.json\n'
    binds += f'BindReadOnlyPaths={CONF}/public-ip:{HOME}/hl/override_public_ip_address\n'
    if contract['network'] == 'mainnet':
        binds += f'BindReadOnlyPaths={CONF}/gossip.json:{HOME}/override_gossip_config.json\n'
    credentials=''
    if active:
        credentials='LoadCredentialEncrypted=erpc-hyperliquid-consensus.json:/etc/credstore.encrypted/erpc-hyperliquid-consensus.json\n'
        binds+=f'BindReadOnlyPaths=%d/erpc-hyperliquid-consensus.json:{HOME}/hl/hyperliquid_data/node_config.json\n'
    result = {
        'erpc-hyperliquid-node.service': base + f'''User={native['uid']}
Group={native['gid']}
Environment=HOME={HOME}
Environment=GNUPGHOME={CONF}/gnupg
WorkingDirectory={HOME}
ExecCondition=+{condition}
ExecStartPre=+{native_guard}
ExecStart=/opt/erpc/hyperliquid/{pin['id']}/hl-visor {'run-validator' if active else 'run-non-validator'} --serve-eth-rpc --serve-info --replica-cmds-style recent-actions
ReadWritePaths={HOME}
{credentials}
{binds}
[Install]
WantedBy=multi-user.target
''',
        'erpc-hyperliquid-rpc.service': base + f'''User={gateway['uid']}
Group={gateway['gid']}
ExecStartPre=+{guard}
ExecStart=/usr/bin/python3 -I {HELPERS}/current/erpc_hl_gateway.py {CONF}/gateway.json
[Install]
WantedBy=multi-user.target
''',
        'erpc-hyperliquid-firewall.service': f'''[Unit]
Description=Restore the confirmed Hyperliquid firewall
Before=erpc-hyperliquid-node.service erpc-hyperliquid-rpc.service
After=network-pre.target nftables.service
Wants=network-pre.target
[Service]
Type=oneshot
ExecStart={controller_bootstrap()} firewall-load {contract['owner']}
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
''',
        'erpc-hyperliquid-retention.service': f'''[Unit]
Description=Retain Hyperliquid public node outputs
[Service]
Type=oneshot
User={native['uid']}
Group={native['gid']}
ExecStartPre=+{guard}
ExecStart=/usr/bin/python3 -I {HELPERS}/current/retention.py
LimitCORE=0
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths={HOME}/hl/data
''',
        'erpc-hyperliquid-retention.timer': '''[Unit]
Description=Hyperliquid output retention interval
[Timer]
OnBootSec=1h
OnUnitActiveSec=1h
Unit=erpc-hyperliquid-retention.service
[Install]
WantedBy=timers.target
'''}
    return result
