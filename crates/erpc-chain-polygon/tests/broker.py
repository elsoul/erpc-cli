# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Fixed broker catalog/configuration checks without a container or broker."""
from pathlib import Path
import copy
import sys
import unittest
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'templates/scripts'))
import broker


class Broker(unittest.TestCase):
    def setUp(self):
        self.expected={'role':'validator','architecture':'x86_64','owner':'public-fixture'}
        self.value={'format':1,'contract':self.expected,'password':'a'*64,'cookie':'b'*64}

    def test_closed_catalog_refuses_older_newer_or_retagged_native_database_transitions(self):
        original=broker.transition(self.expected,None)
        self.assertEqual(broker.transition(self.expected,original),original)
        for version in ('4.3.7','4.4.1','5.0.0'):
            with self.assertRaises(ValueError):broker.transition(self.expected,dict(original,version=version))
        with self.assertRaises(ValueError):broker.transition(self.expected,dict(original,config='sha256:'+'c'*64))
        with self.assertRaises(ValueError):broker.identity(dict(self.expected,role='fullnode'))

    def test_only_native_result_queue_compatibility_is_enabled(self):
        config=broker.configuration(self.value,self.expected)
        settings=dict(line.split(' = ',1) for line in config.splitlines())
        self.assertEqual({key:value for key,value in settings.items() if key.startswith('deprecated_features.')},
            {'deprecated_features.permit.transient_nonexcl_queues':'true'})
        self.assertEqual(settings['listeners.tcp'],'none')
        self.assertEqual(settings['listeners.ssl.1'],'127.0.0.14:5671')
        self.assertEqual(settings['default_user_tags.administrator'],'false')
        self.assertEqual(settings['distribution.listener.interface'],'127.0.0.1')
        self.assertNotIn(self.value['cookie'],config)

    def test_original_numeric_user_and_credentials_never_become_container_arguments(self):
        for architecture in broker.IMAGES:
            expected=dict(self.expected,architecture=architecture)
            args=broker.arguments(expected,{'uid':991,'gid':992},'c'*64,'e'*32)
            self.assertEqual(args[args.index('--user')+1],'991:992')
            self.assertEqual(args[-2],broker.image(architecture))
            for value in (self.value['cookie'],self.value['password'],'--privileged','--pid=host','--group-add'):
                self.assertNotIn(value,' '.join(args))
            self.assertIn('--read-only',args);self.assertIn('--pull=never',args)
        for account in ({'uid':0,'gid':992},{'uid':991,'gid':0},{'uid':True,'gid':992}):
            with self.assertRaises(ValueError):broker.arguments(self.expected,account,'c'*64,'e'*32)

    def test_fixed_tls_native_url_and_strict_original_credential_scope(self):
        from urllib.parse import urlsplit
        value=urlsplit(broker.native_url(self.value,self.expected))
        self.assertEqual((value.scheme,value.hostname,value.port,value.path),('amqps','127.0.0.14',5671,'/polygon'))
        for bad in (dict(self.value,password='inert\nunsafe'),dict(self.value,cookie=self.value['password']),
                    dict(self.value,contract=dict(self.expected,owner='foreign'))):
            with self.assertRaises(ValueError):broker.configuration(bad,self.expected)

    def container(self):
        account={'uid':991,'gid':992};helpers='c'*64;wanted=broker.identity(self.expected)
        image={'Id':wanted['config'],'Architecture':'amd64','Os':'linux','RepoDigests':[wanted['image']],
            'Config':{'Entrypoint':['docker-entrypoint.sh'],'Cmd':['rabbitmq-server'],'Env':['RABBITMQ_VERSION=4.4.0']}}
        args=broker.arguments(self.expected,account,helpers,'e'*32)
        overrides=[args[i+1] for i,value in enumerate(args[:-1]) if value=='--env']
        value={'Id':'d'*64,'Name':'/'+broker.NAME,'Image':wanted['config'],
            'Config':{'Image':wanted['image'],'User':'991:992','Entrypoint':['docker-entrypoint.sh'],'Cmd':['rabbitmq-server'],
                'Labels':{'erpc.polygon.owner':self.expected['owner'],'erpc.polygon.helpers':helpers,'erpc.polygon.creation':'e'*32},
                'Env':['RABBITMQ_VERSION=4.4.0',*overrides],'StopTimeout':120},
            'HostConfig':{'ReadonlyRootfs':True,'Privileged':False,'NetworkMode':'host','CgroupnsMode':'private','CgroupParent':'system.slice',
                'PidMode':'','UTSMode':'','UsernsMode':'','IpcMode':'private','CapDrop':['ALL'],'SecurityOpt':['no-new-privileges'],
                'RestartPolicy':{'Name':'no','MaximumRetryCount':0},'AutoRemove':False,'PidsLimit':256,
                'Memory':4*1024**3,'MemorySwap':4*1024**3,'NanoCpus':4*10**9,'LogConfig':{'Type':'none','Config':{}},
                'Ulimits':[{'Name':'core','Soft':0,'Hard':0},{'Name':'nofile','Soft':65536,'Hard':65536}],
                'Tmpfs':{'/tmp':'rw,noexec,nosuid,nodev,size=67108864,mode=1777'}},
            'Mounts':[{'Type':'bind','Source':source,'Destination':destination,'RW':writable,'Propagation':'rprivate'}
                for source,destination,writable in [(broker.DATA,'/var/lib/rabbitmq',True),
                    (broker.RUNTIME+'/config','/etc/rabbitmq',False),(broker.RUNTIME+'/cookie','/var/lib/rabbitmq/.erlang.cookie',False)]]}
        return value,account,helpers,image

    def test_name_and_label_matches_do_not_authorize_foreign_container_runtime(self):
        value,account,helpers,image=self.container()
        self.assertEqual(broker.container_info(value,self.expected,account,helpers,image,'e'*32),'d'*64)
        changes=[('Config','User','0:0'),('Config','Cmd',['arbitrary']),('Config','Env',['RABBITMQ_VERSION=4.4.0','HOME=/root']),
            ('HostConfig','Privileged',True),('HostConfig','ReadonlyRootfs',False),('HostConfig','GroupAdd',['998']),
            ('HostConfig','PidMode','host'),('HostConfig','CapAdd',['SYS_PTRACE']),('HostConfig','Devices',[{'PathOnHost':'/dev/inert'}]),
            ('HostConfig','MemorySwap',-1),('HostConfig','NanoCpus',0),('HostConfig','Ulimits',[{'Name':'core','Soft':-1,'Hard':-1}])]
        for section,name,wrong in changes:
            changed=copy.deepcopy(value);changed[section][name]=wrong
            with self.assertRaises(ValueError):broker.container_info(changed,self.expected,account,helpers,image,'e'*32)
        with self.assertRaises(ValueError):broker.container_info(value,self.expected,account,helpers,image,'e'*32,'e'*64)

    def test_container_mount_redirection_and_image_mismatch_are_not_adopted(self):
        value,account,helpers,image=self.container()
        for index,key,wrong in ((0,'Source','/var/lib/foreign'),(1,'RW',True),(2,'Type','volume'),(0,'Propagation','rshared')):
            changed=copy.deepcopy(value);changed['Mounts'][index][key]=wrong
            with self.assertRaises(ValueError):broker.container_info(changed,self.expected,account,helpers,image,'e'*32)
        changed=copy.deepcopy(value);changed['Mounts'].append(dict(changed['Mounts'][0]))
        with self.assertRaises(ValueError):broker.container_info(changed,self.expected,account,helpers,image,'e'*32)
        for key,wrong in (('Id','sha256:'+'e'*64),('Architecture','arm64'),('RepoDigests',[])):
            changed=copy.deepcopy(image);changed[key]=wrong
            with self.assertRaises(ValueError):broker.container_info(value,self.expected,account,helpers,changed,'e'*32)


if __name__=='__main__':unittest.main()
