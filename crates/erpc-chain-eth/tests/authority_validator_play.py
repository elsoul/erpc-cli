# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Render actual Rust-generated public inventory using pinned Ansible; execute no task."""
import json
from pathlib import Path
import sys
sys.dont_write_bytecode=True


def render(inventory):
    import yaml
    from ansible.parsing.dataloader import DataLoader
    from ansible.template import Templar
    root=Path(__file__).parents[1]/'templates/validator'
    hosts=inventory['all']['hosts'];assert len(hosts)==1
    variables=dict(next(iter(hosts.values())));assert variables['ev_network'] in ('mainnet','hoodi')
    assert 'eth_authority_request' not in variables and 'eth_authority_loader' not in variables
    play=yaml.safe_load((root/'deploy.yml').read_text())[0]
    variables.update(play['vars']);variables['playbook_dir']=str(root)
    variables['ansible_facts']={'services':{}}
    plan={'role':'validator','users':{name:{'uid':901+i,'gid':901+i} for i,name in enumerate(('ev-reth','ev-beacon','ev-validator','ev-transport'))}}
    actions=[];native=[]
    def template(value):return Templar(loader=DataLoader(),variables=variables).template(value)
    def walk(tasks):
        for task in tasks:
            if 'when' in task and not template('{{ '+task['when']+' }}'):continue
            if 'block' in task:walk(task['block']);continue
            if 'ansible.builtin.include_tasks' in task:
                selected=template(task['ansible.builtin.include_tasks']);assert selected=='install_release.yml'
                walk(yaml.safe_load((root/selected).read_text()));continue
            if 'ansible.builtin.set_fact' in task:
                variables.update(template(task['ansible.builtin.set_fact']));continue
            items=template(task['loop']) if 'loop' in task else [None]
            for item in items:
                variables['item']=item
                module=next((key for key in task if key.startswith('ansible.builtin.')),None)
                if module is None:continue
                payload=template(task[module])
                if module=='ansible.builtin.command':
                    argv=payload['argv'];assert isinstance(argv,list) and argv[0].startswith('/')
                    if argv[0]=='/usr/bin/setpriv':
                        assert '--clear-groups' in argv and '--no-new-privs' in argv
                        assert argv[-1]=='--version' and '.pending-'+variables['ev_intent'] in argv[-2]
                        assert argv[2] in [str(plan['users'][name]['uid']) for name in ('ev-reth','ev-beacon')]
                        native.append(argv[-2])
                    elif argv[-1]=='request':
                        envelope=json.loads(payload['stdin']);assert envelope['contract']['role']=='validator'
                        assert envelope['contract']['network']==variables['ev_network']
                        request=envelope['request'];assert request['owner']==variables['ev_owner']
                        if request['action'] not in ('reserve','prepare'):
                            assert request['intent']==variables['ev_intent']
                            assert request['target']['fee_recipient']==variables['ev_fee_recipient']
                        actions.append(request['action'])
                        if request['action']=='prepare':variables['ev_prepared']={'stdout':json.dumps({'accounts':plan})}
                    else:
                        assert argv[-1].endswith('/time_service.py')
                        variables['ev_clock']={'stdout':json.dumps({'install_fallback':False,'service':'inert-time.service'})}
                elif module=='ansible.builtin.get_url':
                    assert payload['use_netrc'] is False and payload['owner']=='root'
                    assert payload['url'].startswith('https://github.com/')
                elif module=='ansible.builtin.shell':
                    assert 'gpg --no-options' in payload['cmd'] and 'VALIDSIG' in payload['cmd']
    walk(play['tasks'])
    if variables['ev_phase']=='init':assert actions==['reserve','prepare'] and native==[]
    else:
        assert actions==['check-deploy','prepare','check-deploy','extract','qualify','begin','install','activate-support']
        assert len(native)==2
    return {'network':variables['ev_network'],'phase':variables['ev_phase'],'controller_actions':actions}


if __name__=='__main__':
    assert sys.argv[1:]==['--inventory']
    print(json.dumps(render(json.loads(sys.stdin.read()))))
