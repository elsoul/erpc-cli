# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
# Verbatim release/prepare guards from 3af53169dca9e606ea2e580bda2fa318cab8428d.
import re
import host

def version(tag):
    match=re.fullmatch(r'v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)',tag)
    if not match:raise ValueError('unknown native release ordering requires reviewed migration')
    return tuple(int(part) for part in match.groups())

def target(expected,profile):
    network=expected['network']
    if expected['role']=='validator':
        value=profile.get('validator')
        if (not isinstance(value,dict) or set(value)!={'phase','signer','sentries'}
                or value['signer']!=expected['signer'] or value['phase'] not in ('observing','active')
                or not isinstance(value['sentries'],list) or not 1<=len(value['sentries'])<=8):
            raise ValueError('validator release target lacks its exact original signer, phase and sentry policy')
    elif 'validator' in profile:
        raise ValueError('RPC ownership cannot select a validator runtime target')
    if (profile.get('network')!=network or profile.get('bor_genesis_hash')!=expected['bor_genesis']
            or profile.get('heimdall_genesis',{}).get('sha256')!=expected['heimdall_genesis']
            or profile.get('chain_id')!=(137 if network=='mainnet' else 80002)
            or profile.get('heimdall_chain_id')!=('heimdallv2-137' if network=='mainnet' else 'heimdallv2-80002')
            or profile.get('parent')!=('mainnet' if network=='mainnet' else 'sepolia')):
        raise ValueError('release profile differs from immutable network ownership')
    if set(profile.get('releases',{}))!={'bor','heimdall'}:
        raise ValueError('both independently reviewed client targets are required')
    generation=profile.get('genesis_generation','')
    if not isinstance(generation,str) or not generation.isdigit() or profile['heimdall_genesis']['url']!='https://storage.googleapis.com/'+network+'-heimdallv2-genesis/migrated_dump-genesis.json?generation='+generation:
        raise ValueError('genesis must use the reviewed official immutable object')
    for name,release in profile['releases'].items():
        version(release['tag'])
        repo='bor' if name=='bor' else 'heimdall-v2'
        identity='https://github.com/0xPolygon/'+repo+'/.github/workflows/packager_deb.yml@refs/tags/'+release['tag']
        if release.get('certificate_identity')!=identity:
            raise ValueError('release signature identity differs from its native source and tag')
        if not re.fullmatch('[a-f0-9]{40}',release['commit']) or expected['architecture'] not in release['assets']:
            raise ValueError('incomplete native release identity')
        package=release['assets'][expected['architecture']]
        if set(package)!={'package','signature','certificate'}:
            raise ValueError('all native package verification material is required')
        arch='amd64' if expected['architecture']=='x86_64' else 'arm64'
        base='https://github.com/0xPolygon/'+repo+'/releases/download/'+release['tag']+'/'+name+'-'+release['tag']+'-'+arch+'.deb'
        for component,suffix in [('package',''),('signature','.sig'),('certificate','.pem')]:
            pin=package[component]
            if (pin['url']!=base+suffix or not re.fullmatch('[a-f0-9]{64}',pin['sha256'])
                    or type(pin['bytes']) is not int or pin['bytes']<=0):
                raise ValueError('invalid native artifact source or pin')
    return profile

def monotonic(expected,old,new):
    target(expected,old);target(expected,new)
    if expected['role']=='validator' and old['validator']['phase']=='active' and new['validator']['phase']!='active':
        raise ValueError('active validator signing history cannot return to an observer identity')
    for name in ('bor','heimdall'):
        before,after=old['releases'][name],new['releases'][name]
        older,newer=version(before['tag']),version(after['tag'])
        if newer<older or (newer==older and before!=after):
            raise ValueError('downgrade or ambiguous same-version artifact change refused')

class OldState:
    def prepare(self,expected,intent,profile,helpers):
        self.ownership(expected)
        target(expected,profile)
        if not re.fullmatch('[a-f0-9]{32}',intent) or not re.fullmatch('[a-f0-9]{64}',helpers):raise ValueError('invalid deployment intent or helper revision')
        for filename in ('installed.json','intent.json'):
            path='/etc/polygon/'+filename
            if self.path(path).exists():
                previous=self.read(path).get('profile')
                if previous is not None:monotonic(expected,previous,profile)
        self.capacity(expected)
        if (self.path('/etc/polygon/stopped').exists() and self.path('/etc/polygon/intent.json').exists()
                and self.read('/etc/polygon/intent.json').get('intent')==intent):
            raise ValueError('a cancelled preparation requires a new deployment intent')
        self.write('/etc/polygon/intent.json',{'intent':intent,'profile':profile,'helpers':helpers})
        host.fence(self.protected('/etc/polygon/preparing',missing=True),self.root)
        # An interrupted upgrade must not boot an older unit that delivered
        # credentials before its prestart guard. Only sealed activation enables
        # the checked numeric-recipient units again.
        self.stop(disable=True)
        # A new durable intent and preparation fence supersede cancellation.
        # Never let the delayed activation of the cancelled run remove it.
        host.unlink(self.protected('/etc/polygon/stopped',missing=True),self.root)
