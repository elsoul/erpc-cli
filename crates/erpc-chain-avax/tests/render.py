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
   context=dict(avax_network=network,avax_type=kind,avax_rpc_allow=allow,avax_monitoring_allow=allow,avax_fw_management_v4=['192.0.2.10'],avax_fw_management_v6=[],avax_ssh_port=22,avax_fw_file='/etc/erpc/avax/firewall.nft',avax_fw_dir='/etc/erpc/avax',avax_fw_marker='/run/erpc-avax-firewall.armed',avax_helpers='/usr/local/lib/erpc')
   for path in (root/'jinja').glob('*.j2'):
    text=env.from_string(path.read_text()).render(**context)
    if '.json' in path.name:
     data=json.loads(text)
     if path.name=='node.json.j2': assert data['http-host']=='127.0.0.1' and not data['api-admin-enabled']
     if path.name=='c-chain.json.j2': assert data['pruning-enabled']==(kind=='full') and data['state-sync-enabled']==(kind=='full') and 'eth-filter' not in data['apis']
    if '.sh.' in path.name: subprocess.run(['bash','-n'],input=text,text=True,check=True)
    if path.name=='proxy.conf.j2': assert text.count('deny all;')==2 and 'location / { return 403; }' in text
print('All play/task YAML and 8 network/history/exposure template combinations passed')

# Execute the real ownership task file against temporary local fixtures only.
# The sentinel stands in for destroy --purge-data; no service/host/node is touched.
import tempfile, shutil, sys
if shutil.which('ansible-playbook'):
 with tempfile.TemporaryDirectory() as directory:
  tmp=pathlib.Path(directory)
  contract=tmp/'contract.json'
  contract.write_text(json.dumps({'network':'mainnet','type':'full','validator':False}))
  guard=tmp/'guard.yml'
  guard.write_text((root/'ansible/avax/tasks/contract.yml').read_text().replace('/etc/avalanchego/contract.json',str(contract)))
  for network,history,validator,expected in [('fuji','full',False,False),('mainnet','archive',False,False),('mainnet','full',True,False),('mainnet','full',False,True)]:
   sentinel=tmp/'database-sentinel'
   sentinel.write_text('inert database fixture')
   play=[{'hosts':'all','connection':'local','gather_facts':False,
          'vars':{'ansible_python_interpreter':sys.executable,'avax_network':network,'avax_type':history,'avax_validator':validator},
          'tasks':[{'ansible.builtin.import_tasks':str(guard)},{'ansible.builtin.file':{'path':str(sentinel),'state':'absent'}}]}]
   playfile=tmp/'play.yml';playfile.write_text(yaml.safe_dump(play))
   result=subprocess.run(['ansible-playbook','-i','localhost,',str(playfile)],capture_output=True,text=True)
   assert result.returncode==0 if expected else result.returncode!=0,result.stdout+result.stderr
   assert sentinel.exists()!=expected,'a mismatched ownership contract allowed deletion'
 print('Ansible contract fixtures reject failed cross-network initialization, role/history mismatch before deletion')
