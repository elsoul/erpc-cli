# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Offline Jinja matrix: python3 with Jinja2, no node binaries or service calls."""
from pathlib import Path
import shlex
import jinja2

ROOT = Path(__file__).parents[1] / 'templates/jinja'
ENV = jinja2.Environment(loader=jinja2.FileSystemLoader(ROOT), undefined=jinja2.StrictUndefined, trim_blocks=True)
PROFILES = [('optimism', 'mainnet', 'optimism', 'op-mainnet'),
            ('optimism', 'sepolia', 'optimism-sepolia', 'op-sepolia'),
            ('base', 'mainnet', 'base', '8453'), ('base', 'sepolia', 'base-sepolia', '84532'),
            ('soneium', 'mainnet', 'soneium', 'soneium-mainnet'),
            ('soneium', 'minato', 'soneium-minato-sepolia', 'soneium-minato-sepolia')]


def argv(text):
    lines = text.replace('\\\n', '').splitlines()
    return shlex.split(next(line.removeprefix('ExecStart=') for line in lines if line.startswith('ExecStart=')))


def matrix():
    count = 0
    for family, network, execution, consensus in PROFILES:
        for history in ('full', 'archive'):
            for architecture in ('amd64', 'arm64'):
                for rpc, monitor in (([], []), (['192.0.2.0/24'], ['198.51.100.4']), (['2001:db8::/32'], ['2001:db8:1::/48'])):
                    values = {'op_family':family, 'op_network':network, 'op_owner':'syntheticowner',
                              'op_history':history, 'op_conf':'/etc/erpc/'+family, 'op_opt':'/opt/erpc/'+family,
                              'op_data':'/var/lib/erpc/'+family, 'op_proxy_user':'erpc-'+family+'-l1',
                              'op_uid':1234, 'op_gid':1234, 'op_l1':'mainnet' if network=='mainnet' else 'sepolia',
                              'op_execution_chain':execution, 'op_consensus_chain':consensus,
                              'op_execution_image':'us-docker.pkg.dev/oplabs-tools-artifacts/images/op-reth@sha256:'+'a'*64,
                              'op_consensus_image':'us-docker.pkg.dev/oplabs-tools-artifacts/images/op-node@sha256:'+'b'*64,
                              'op_sequencer':'https://github.com/synthetic-sequencer', 'op_advertise_ip':'8.8.8.8',
                              'op_controller_ip':'192.0.2.3', 'op_ssh_port':2222, 'op_management_allow':['192.0.2.0/24'],
                              'op_rpc_allow':rpc, 'op_monitoring_allow':monitor,
                              'op_rpc_v6':bool(rpc and ':' in rpc[0]), 'op_monitoring_v6':bool(monitor and ':' in monitor[0])}
                    rendered = {path.name:ENV.get_template(path.name).render(values) for path in ROOT.glob('*.j2')}
                    el, cl = argv(rendered['execution.service.j2']), argv(rendered['consensus.service.j2'])
                    assert el[el.index('--chain')+1] == execution
                    assert ('--full' in el) == (history == 'full')
                    assert '--storage.v2=true' in el
                    assert not any(value.split('=')[0] in {'--minimal', '--proofs-history',
                        '--engine.num-state-masking-blocks', '--engine.disable-bal-parallel-execution',
                        '--engine.disable-bal-parallel-state-root', '--engine.disable-bal-batch-io',
                        '--rpc-cache.max-bals', '--rpc-cache.cache-computed-bals',
                        '--rpc-cache.prewarm-bals', '--db.balstore-cache-size'} for value in el)
                    for flag in ('--http.addr', '--ws.addr', '--authrpc.addr'):
                        assert el[el.index(flag)+1] == '127.0.0.1'
                    assert cl[cl.index('--rpc.addr')+1] == '127.0.0.1'
                    assert cl[cl.index('--l1')+1] == 'http://127.0.0.1:18545'
                    assert cl[cl.index('--l1.beacon')+1] == 'http://127.0.0.1:15052'
                    if family == 'base':
                        assert el[0].endswith('/base-reth-node') and cl[0].endswith('/base-consensus')
                        assert cl[cl.index('--chain')+1] == consensus
                        assert '--upgrade-signal.l1-rpc' in el
                        assert el[el.index('--p2p-secret-key')+1] == '%d/execution-peer'
                        assert cl[cl.index('--p2p.priv.path')+1] == '%d/consensus-peer'
                        assert 'BASE_NODE_L1_TRUST_RPC=false BASE_NODE_L2_TRUST_RPC=false' in rendered['consensus.service.j2']
                    else:
                        assert el[0] == cl[0] == '/usr/bin/docker'
                        assert cl[cl.index('--network', cl.index('op-node'))+1] == consensus
                        for command in (el, cl):
                            assert command[command.index('--user')+1] == '1234:1234'
                            assert '--read-only' in command and 'no-new-privileges' in command
                            assert not any(value.startswith(('HTTP_PROXY=', 'HTTPS_PROXY=')) for value in command)
                        assert '--l1.trustrpc=false' in cl
                        assert el[el.index('--p2p-secret-key')+1] == '/peer-key'
                        assert cl[cl.index('--p2p.priv.path')+1] == '/peer-key'
                        assert any('peer-key,target=/peer-key,readonly' in value for value in el)
                        assert any('peer-key,target=/peer-key,readonly' in value for value in cl)
                    for role in ('execution', 'consensus', 'rpc', 'upstreams'):
                        unit = rendered[role+'.service.j2']
                        assert 'rollup_control.py guard '+role+' syntheticowner '+family+' '+network+' '+history in unit
                        assert 'Requires=erpc-'+family+'-firewall.service' in unit
                    for role in ('execution', 'consensus'):
                        assert 'LoadCredentialEncrypted='+role+'-peer:' in rendered[role+'.service.j2']
                    assert 'rollup_upstreams.py '+values['op_l1'] in rendered['upstreams.service.j2']
                    assert 'User=erpc-'+family+'-l1' in rendered['upstreams.service.j2']
                    assert 'LoadCredentialEncrypted=l1-upstreams:' in rendered['upstreams.service.j2']
                    assert 'rpc-firewall.py '+family+' load' in rendered['firewall.service.j2']
                    assert 'ConditionPathExists' not in rendered['firewall.service.j2']
                    nginx = rendered['nginx.conf.j2']
                    assert ('listen [::]:8555' in nginx) == values['op_rpc_v6']
                    assert ('listen [::]:9060' in nginx) == values['op_monitoring_v6']
                    assert 'listen '+('0.0.0.0' if rpc else '127.0.0.1')+':8555' in nginx
                    assert nginx.count('deny all;') == 3
                    firewall = rendered['firewall.nft.j2']
                    assert 'table inet erpc_'+family in firewall and 'tcp dport 2222 drop' in firewall
                    assert all('{{' not in text and '{%' not in text for text in rendered.values())
                    count += 1
    print(str(count)+' strict profile/history/platform/ACL render cases passed')


if __name__ == '__main__':
    matrix()
