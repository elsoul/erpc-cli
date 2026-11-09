# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Canonical decoding of the nine native BoLD write methods, not an arbitrary ABI.

The data types and method signatures are qualified from nitro-contracts
4341b132cfbdcc980ead03765ca5224ff6cb5d97, Assertion.sol, AssertionState.sol,
RollupUserLogic.sol and challengeV2/{IEdgeChallengeManager,libraries/Structs}.sol.
"""
from storage import require

GLOBAL = (('fixed', 'bytes32', 2), ('fixed', 'uint64', 2))
ASSERTION = (GLOBAL, 'uint8', 'bytes32')
CONFIG = ('bytes32', 'uint256', 'address', 'uint64', 'uint64')
INPUTS = (('bytes32', 'bytes32', CONFIG), ASSERTION, ASSERTION)
STATE_DATA = (ASSERTION, 'bytes32', 'bytes32')
METHODS = {
    '50f32f68': ('rollup', 'newStakeOnNewAssertion', ('uint256', INPUTS, 'bytes32', 'address')),
    '3b86de19': ('rollup', 'stakeOnNewAssertion', (INPUTS, 'bytes32')),
    '10b98a35': ('rollup', 'confirmAssertion', ('bytes32', 'bytes32', ASSERTION, 'bytes32', CONFIG, 'bytes32')),
    '05fae141': ('challenge', 'createLayerZeroEdge', (('uint8', 'bytes32', 'uint256', 'bytes32', 'bytes', 'bytes'),)),
    'c8bc4e43': ('challenge', 'bisectEdge', ('bytes32', 'bytes32', 'bytes')),
    'b2a1408e': ('challenge', 'confirmEdgeByTime', ('bytes32', STATE_DATA)),
    '432bb78a': ('challenge', 'multiUpdateTimeCacheByChildren', ('bytes32[]', 'uint256')),
    '8826a370': ('challenge', 'updateTimerCacheByClaim', ('bytes32', 'bytes32', 'uint256')),
    '8c1b3a40': ('challenge', 'confirmEdgeByOneStepProof', ('bytes32', ('bytes32', 'bytes'), CONFIG, 'bytes32[]', 'bytes32[]')),
}


def signature(kind):
    if isinstance(kind, str): return kind
    if kind[0] == 'fixed': return signature(kind[1]) + '[' + str(kind[2]) + ']'
    return '(' + ','.join(signature(item) for item in kind) + ')'


def width(kind):
    if isinstance(kind, tuple):
        if kind[0] == 'fixed': return width(kind[1]) * kind[2]
        sizes = [width(item) for item in kind]
        return None if None in sizes else sum(sizes)
    return None if kind in ('bytes', 'bytes32[]') else 32


def decode(data):
    require(isinstance(data, bytes) and 4 <= len(data) <= 1024 * 1024, 'invalid bounded BoLD calldata')
    selected = METHODS.get(data[:4].hex())
    require(selected is not None, 'transaction method is outside native BoLD participation')
    raw = data[4:]
    def word(position):
        require(0 <= position <= len(raw) - 32, 'truncated BoLD ABI word')
        return raw[position:position + 32]
    def number(position): return int.from_bytes(word(position), 'big')
    def tuple_value(types, begin):
        head = sum(width(kind) or 32 for kind in types)
        require(begin + head <= len(raw), 'truncated BoLD ABI tuple')
        cursor, tail, result = begin, begin + head, []
        for kind in types:
            size = width(kind)
            if size is None:
                require(number(cursor) == tail - begin, 'noncanonical BoLD ABI offset, alias or gap')
                value, tail = value_at(kind, tail); cursor += 32
            else:
                value, end = value_at(kind, cursor)
                require(end == cursor + size, 'invalid static BoLD ABI width'); cursor = end
            result.append(value)
        return tuple(result), tail
    def value_at(kind, position):
        if isinstance(kind, tuple):
            types = (kind[1],) * kind[2] if kind[0] == 'fixed' else kind
            return tuple_value(types, position)
        if kind == 'bytes':
            length = number(position); begin = position + 32
            end = begin + (length + 31) // 32 * 32
            require(length <= 1024 * 1024 and end <= len(raw)
                    and not any(raw[begin + length:end]), 'invalid BoLD byte payload or padding')
            return raw[begin:begin + length], end
        if kind == 'bytes32[]':
            length = number(position)
            require(length <= 2048, 'BoLD proof array exceeds its bound')
            return tuple_value(('bytes32',) * length, position + 32)
        if kind == 'bytes32': return word(position), position + 32
        if kind == 'address':
            value = word(position)
            require(not any(value[:12]), 'noncanonical BoLD ABI address')
            return '0x' + value[12:].hex(), position + 32
        require(kind in ('uint8', 'uint64', 'uint256'), 'unqualified BoLD ABI type')
        value = number(position)
        require(value < 2**int(kind[4:]), 'BoLD integer exceeds its declared type')
        return value, position + 32
    family, name, arguments = selected
    values, end = tuple_value(arguments, 0)
    require(end == len(raw), 'BoLD calldata has trailing or overlapping bytes')
    return family, name, values
