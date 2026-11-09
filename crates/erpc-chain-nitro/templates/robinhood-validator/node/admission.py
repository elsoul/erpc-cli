# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Robinhood admitted Defensive funding/admission at one finalized parent block.

Sources: Nitro 5f02f3f03076343061f167e81b8e82ec5518064b and its
nitro-contracts submodule 4341b132cfbdcc980ead03765ca5224ff6cb5d97.
Official Robinhood chain-info fixes Bridge, Rollup, parent/child and WETH.
Challenge manager is observed through that Rollup and checked reciprocally;
Defensive never submits challenge-edge or confirmation transactions. The one
WETH cap is this qualified profile's per-assertion limit, not a lifetime budget.
The caller proves original parent transport ownership before observation.
"""
import re
import time

import scope
BRIDGE = scope.BRIDGE
ROLLUP = scope.ROLLUP
WETH = scope.WETH
SELECTORS = {
    'rollup': 'cb23bcb5', 'chainId': '9a8a0592', 'bridge': 'e78cea92',
    'challengeManager': '023a96fe', 'stakeToken': '51ed6a30',
    'baseStake': '76e7e23b', 'validatorWhitelistDisabled': '12ab3d3b',
    'isValidator': 'facd743b',
    'isStaked': '6177fd18', 'amountStaked': 'ef40a670',
    'latestStakedAssertion': '2abdd230', 'paused': '5c975abb',
    'withdrawalAddress': '84728cd0', 'balanceOf': '70a08231',
    'allowance': 'dd62ed3e', 'NUM_BIGSTEP_LEVEL': '5d9e2444',
    'stakeAmounts': '1c1b4f3a', 'challengeGracePeriodBlocks': '3be680ea',
    'wasmModuleRoot': '8ee1a126', 'assertionChain': '48dd2924',
}


def require(value, message):
    if not value: raise ValueError(message)


def address(value):
    require(isinstance(value, str) and re.fullmatch('0x[0-9a-f]{40}', value)
            and int(value[2:], 16) != 0, 'invalid original BoLD wallet or protocol address')
    return value


def quantity(value):
    require(isinstance(value, str) and re.fullmatch(r'0x(?:0|[1-9a-f][0-9a-f]{0,63})', value),
            'invalid bounded Ethereum quantity')
    return int(value[2:], 16)


def word(value):
    require(isinstance(value, str) and re.fullmatch('0x[0-9a-fA-F]{64}', value),
            'invalid fixed-size protocol observation')
    return int(value[2:], 16)


def address_word(value):
    number = word(value)
    require(0 < number < 2**160, 'invalid canonical protocol address word')
    return '0x' + format(number, '040x')


def boolean(value):
    number = word(value)
    require(number in (0, 1), 'invalid protocol boolean')
    return number == 1


def call(rpc, target, method, arguments, block):
    require(method in SELECTORS and isinstance(arguments, tuple), 'unsupported admission read')
    encoded = []
    for value in arguments:
        if isinstance(value, str): encoded.append(address(value)[2:].rjust(64, '0'))
        else:
            require(type(value) is int and 0 <= value < 2**256, 'invalid protocol argument')
            encoded.append(format(value, '064x'))
    return rpc('eth_call', [{'to': target, 'data': '0x' + SELECTORS[method] + ''.join(encoded)}, block])


def header(value, now):
    require(isinstance(value, dict), 'missing finalized Ethereum header')
    number = quantity(value.get('number'))
    timestamp = quantity(value.get('timestamp'))
    digest = value.get('hash')
    require(isinstance(digest, str) and re.fullmatch('0x[0-9a-f]{64}', digest)
            and int(digest[2:], 16) != 0 and number > 0, 'invalid finalized Ethereum identity')
    # ERPC freshness policy includes normal Ethereum finalization delay. It is
    # an observation bound, not a claim of a protocol finality-time guarantee.
    require(now - 1800 <= timestamp <= now + 30, 'finalized Ethereum observation is stale')
    return number, timestamp, digest


def observe(rpc, wallet, now=None):
    """Return external funding and exact allowlist facts; never sign or send.

    Only the assertion budget is needed by this Defensive profile. No claim of
    an unlimited gas/loss budget or administrator/deployed-source verification.
    """
    address(wallet)
    now = int(time.time()) if now is None else now
    require(type(now) is int and now > 0, 'invalid observation time')
    require(quantity(rpc('eth_chainId', [])) == scope.PARENT_ID, 'BoLD requires the qualified Ethereum parent')
    require(rpc('eth_getBlockByNumber', ['0x0', False]).get('hash') == scope.PARENT_GENESIS,
            'parent genesis differs from the sealed Robinhood network')
    number, timestamp, digest = header(rpc('eth_getBlockByNumber', ['finalized', False]), now)
    block = hex(number)
    for target in (BRIDGE, ROLLUP, WETH):
        code = rpc('eth_getCode', [target, block])
        require(isinstance(code, str) and re.fullmatch('0x(?:[0-9a-fA-F]{2}){1,65536}', code)
                and any(c != '0' for c in code[2:]), 'qualified protocol contract code is unavailable')
    def read(target, method, *args): return call(rpc, target, method, args, block)
    require(address_word(read(BRIDGE, 'rollup')) == ROLLUP,
            'bridge selects an unreviewed BoLD rollup; update the qualified catalog')
    require(word(read(ROLLUP, 'chainId')) == scope.CHILD_ID
            and address_word(read(ROLLUP, 'bridge')) == BRIDGE,
            'rollup does not identify the sealed Robinhood child and original bridge')
    challenge=address_word(read(ROLLUP,'challengeManager'))
    require(challenge not in (BRIDGE,ROLLUP,WETH), 'ambiguous challenge authority')
    code=rpc('eth_getCode',[challenge,block])
    require(isinstance(code,str) and re.fullmatch('0x(?:[0-9a-fA-F]{2}){1,65536}',code)
            and any(c!='0' for c in code[2:]),'observed challenge code is unavailable')
    require(address_word(read(challenge,'assertionChain'))==ROLLUP,
            'observed challenge authority does not point back to the original rollup')
    require(all(address_word(read(target,'stakeToken'))==WETH for target in (ROLLUP,challenge)),
            'protocol staking token differs from the sealed Robinhood WETH')
    require(rpc('eth_getCode',[wallet,block])=='0x','dedicated signer must remain an undelegated EOA')
    # This getter distinguishes BoLD from the legacy rollup in Nitro's source.
    grace = word(read(ROLLUP, 'challengeGracePeriodBlocks'))
    require(grace < 2**64, 'unsupported BoLD grace period')
    module_root = read(ROLLUP, 'wasmModuleRoot')
    require(word(module_root) != 0, 'BoLD execution module root is missing')
    public = boolean(read(ROLLUP, 'validatorWhitelistDisabled'))
    allowlisted = boolean(read(ROLLUP, 'isValidator', wallet))
    admitted = public or allowlisted
    paused = boolean(read(ROLLUP, 'paused'))
    base = word(read(ROLLUP, 'baseStake'))
    require(base > 0, 'invalid BoLD assertion bond')
    staked = boolean(read(ROLLUP, 'isStaked', wallet))
    allocated = word(read(ROLLUP, 'amountStaked', wallet))
    require(staked or allocated == 0, 'ambiguous existing BoLD stake')
    latest_assertion = None
    if staked:
        latest_assertion = read(ROLLUP, 'latestStakedAssertion', wallet)
        require(word(latest_assertion) != 0, 'original validator stake has no assertion')
        require(address_word(read(ROLLUP, 'withdrawalAddress', wallet)) == wallet,
                'existing BoLD stake belongs to another withdrawal authority')
    balance = word(read(WETH, 'balanceOf', wallet))
    allowance = word(read(WETH, 'allowance', wallet, ROLLUP))
    gas = quantity(rpc('eth_getBalance', [wallet, block]))
    assertion_need = 0 if staked else base
    problems = []
    if not admitted: problems.append('dedicated validator is not currently admitted')
    if base > scope.ASSERTION_BOND_LIMIT_WEI: problems.append('live assertion bond exceeds this qualified profile limit')
    if paused: problems.append('qualified rollup is paused')
    if staked and allocated < base: problems.append('existing assertion deposit needs an external top-up')
    if balance < assertion_need: problems.append('external WETH funding is below the observed assertion budget')
    if allowance < assertion_need: problems.append('external rollup WETH approval is insufficient')
    if gas == 0: problems.append('dedicated wallet has no external ETH gas funding')
    repeated = rpc('eth_getBlockByNumber', [block, False])
    require(header(repeated, now) == (number, timestamp, digest), 'Ethereum observation changed during admission reads')
    return {'network': scope.NETWORK, 'strategy': 'Defensive', 'parent_chain_id':scope.PARENT_ID, 'child_chain_id':scope.CHILD_ID, 'wallet': wallet,
            'block': block, 'block_hash': digest, 'observed_at': now,
            'rollup': ROLLUP, 'challenge_manager': challenge, 'stake_token': WETH,
            'wasm_module_root': module_root.lower(), 'permissionless': public, 'allowlisted':allowlisted, 'admitted':admitted, 'rollup_paused': paused,
            'assertion_bond_wei': str(base), 'challenge_path_bonds_wei': [], 'challenge_sends_enabled':False, 'assertion_bond_limit_wei':str(scope.ASSERTION_BOND_LIMIT_WEI),
            'is_staked': staked, 'latest_staked_assertion': latest_assertion,
            'existing_stake_wei': str(allocated), 'weth_balance_wei': str(balance),
            'eth_balance_wei': str(gas), 'rollup_allowance_wei': str(allowance),
            'external_weth_budget_wei': str(assertion_need),
            'funding_checks_passed': not problems, 'gas_adequacy_verified': False,
            'activation_authorized': False, 'problems': problems}
