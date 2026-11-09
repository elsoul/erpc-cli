# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0

"""Optional strict rendering check; run with the Python environment used by Ansible."""
import json, pathlib, subprocess
import jinja2, yaml
root=pathlib.Path(__file__).resolve().parents[1] / 'templates'
env=jinja2.Environment(undefined=jinja2.StrictUndefined)
env.filters['to_json']=json.dumps
for path in root.rglob('*.yml'):
 yaml.safe_load(path.read_text())
for network in ['mainnet','fuji']:
 for kind in ['full','archive']:
  for allow in [[],['192.0.2.0/24']]:
   context=dict(avax_network=network,avax_type=kind,avax_rpc_allow=allow,avax_monitoring_allow=allow,avax_fw_management_v4=['192.0.2.10'],avax_fw_management_v6=[],avax_ssh_port=22,avax_fw_file='/etc/erpc/avax/firewall.nft',avax_fw_dir='/etc/erpc/avax',avax_fw_marker='/run/erpc-avax-firewall.armed',avax_helpers='/usr/local/lib/erpc',avax_runtime_account={'uid':999,'gid':999},avax_control_unit='/usr/bin/python3 -I checked.py',avax_control_condition='/usr/bin/python3 -I checked.py')
   for path in (root/'jinja').glob('*.j2'):
    text=env.from_string(path.read_text()).render(**context)
    if '.json' in path.name:
     data=json.loads(text)
     if path.name=='node.json.j2': assert data['http-host']=='127.0.0.1' and not data['api-admin-enabled']
     if path.name=='c-chain.json.j2': assert data['pruning-enabled']==(kind=='full') and data['state-sync-enabled']==(kind=='full') and 'eth-filter' not in data['apis']
    if '.sh.' in path.name: subprocess.run(['bash','-n'],input=text,text=True,check=True)
    if path.name=='proxy.conf.j2': assert text.count('deny all;')==2 and 'location / { return 403; }' in text
print('All play/task YAML and 8 network/history/exposure template combinations passed')

# Actual command/stdin and guarded source composition with only root/NSS identity
# modeled in a temporary fixture. The sentinel is never real chain data.
import tempfile,shutil,sys,importlib.util,os
if shutil.which('ansible-playbook'):
 spec=importlib.util.spec_from_file_location('avax_render_authority',root.parent/'tests/authority.py')
 module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 test=module.Authority();test.setUp()
 try:
  test.c.prepare(test.expected)
  with tempfile.TemporaryDirectory() as directory:
   tmp=pathlib.Path(directory)
   code=(root/'jinja/control.py').read_text()
   code=code.replace("root=pathlib.Path('/')",'root=pathlib.Path('+repr(str(test.root))+')').replace('owner=0):','owner='+str(os.getuid())+'):')
   code=code.replace("if __name__=='__main__':trusted_imports(pathlib.Path(__file__).absolute().parent)","# fixture-owned carried source; production external loader tested separately")
   code=code.replace('if os.geteuid()!=0:', 'if os.geteuid()!='+str(os.getuid())+':')
   (tmp/'control.py').write_text(code);shutil.copyfile(root/'jinja/account.py',tmp/'account.py')
   guard=tmp/'guard.yml';guard.write_text((root/'ansible/avax/tasks/contract.yml').read_text())
   for network,history,validator,allowed in [('mainnet','full',True,False),('fuji','archive',True,False),('fuji','full',False,False),('fuji','full',True,True)]:
    sentinel=tmp/'database-sentinel';sentinel.write_text('inert data')
    variables={'ansible_python_interpreter':sys.executable,'avax_jinja':str(tmp),'avax_contract_value':{'network':network,'type':history,'validator':validator,'owner':test.expected['owner']}}
    play=[{'hosts':'all','connection':'local','gather_facts':False,'vars':variables,
           'tasks':[{'ansible.builtin.import_tasks':str(guard)},{'ansible.builtin.file':{'path':str(sentinel),'state':'absent'}}]}]
    path=tmp/'play.yml';path.write_text(yaml.safe_dump(play))
    result=subprocess.run(['ansible-playbook','-i','localhost,',str(path)],capture_output=True,text=True)
    assert (result.returncode==0)==allowed,result.stdout+result.stderr
    assert sentinel.exists()!=allowed,'wrong scope crossed the carried authority boundary'
 finally:test.doCleanups()
 print('Actual carried contract command rejects foreign network/role/history before the inert mutation')
