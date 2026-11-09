# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
# Verbatim Control.dispatch from 3af53169dca9e606ea2e580bda2fa318cab8428d,
# wrapped only to exercise its legacy action boundary without native operations.
class OldControl:
    def dispatch(self,request):
        if not isinstance(request,dict):raise ValueError('expected Polygon operation object')
        expected=self.expected(request.get('contract'));action=request.get('action')
        action={'start-v2':'start','stop-v2':'stop','restart-v2':'restart'}.get(action,action)
        if action=='reserve':return self.reserve(expected)
        self.state.ownership(expected)
        if action=='provision-accounts':
            self.state.namespaces()
            self.state.accounts.provision(expected)
            return {'accounts':'established'}
        if action=='broker-daemon-guard':
            import broker_docker
            return broker_docker.start_allowed(self.state,expected)
        if action=='guard':
            self.state.namespaces()
            return {'owned':True}
        if action=='phase':
            expected,profile=self.phase(request)
            installed=self.installation(expected)
            if installed['profile']!=profile:raise ValueError('firewall phase differs from installed pair')
            self.state.stopped()
            return {'prepared_for_firewall':True}
        if action=='confirm':
            self.phase(request)
            token=request['firewall']
            self.state.firewall().confirm(token['run'],token['bundle'])
            return {'firewall_confirmed':True}
        if action=='prepare':return self.prepare(request)
        if action=='registration':
            import validator_activation
            return validator_activation.registration(self,request)
        if action=='authorize-active':
            import validator_activation
            return validator_activation.authorize(self,request)
        if action=='validator-key':return self.validator_key(request)
        if action=='validator-finalize':
            import validator_runtime
            return validator_runtime.finalize(self,request)
        if action=='credential':return self.credential(request)
        if action=='seal':
            expected,profile=self.phase(request)
            install.seal(self.state,expected,request['intent'],profile)
            return {'sealed':True}
        if action=='activate':return self.activate(request)
        if action=='status':return self.status(expected)
        if action=='recover-original':
            self.stop(expected)
            return self.restore(expected,self.state.read('/etc/polygon/original-credentials.backup.json'))
        if action=='backup':return self.backup(expected)
        if action=='restore':return self.restore(expected,request.get('backup'))
        if action=='logs':return self.logs(expected,request)
        if action in ('stop','destroy'):return self.stop(expected,action=='destroy')
        if action in ('start','restart'):return self.start(expected,action=='restart')
        raise ValueError('unsupported Polygon lifecycle operation')
