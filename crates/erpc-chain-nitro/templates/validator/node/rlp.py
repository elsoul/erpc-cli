# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Bounded canonical EIP-2718/EIP-1559 decoding of already-signed payloads."""
from storage import require

MAX_TRANSACTION = 1024 * 1024


def encode(value):
    if isinstance(value, list):
        raw = b''.join(encode(item) for item in value); offset = 0xc0
    else:
        require(isinstance(value, bytes), 'invalid RLP item')
        if len(value) == 1 and value[0] < 0x80: return value
        raw = value; offset = 0x80
    if len(raw) < 56: return bytes([offset + len(raw)]) + raw
    size = len(raw).to_bytes((len(raw).bit_length() + 7) // 8, 'big')
    return bytes([offset + 55 + len(size)]) + size + raw


def parse(raw):
    require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_TRANSACTION, 'transaction exceeds its bounded encoding')
    def item(start, limit, depth):
        require(depth <= 4 and start < limit, 'invalid or nested transaction encoding')
        prefix = raw[start]; start += 1
        if prefix < 0x80: return bytes([prefix]), start
        sequence = prefix >= 0xc0
        offset = 0xc0 if sequence else 0x80
        length = prefix - offset
        if length > 55:
            count = length - 55
            require(1 <= count <= 4 and start + count <= limit and raw[start] != 0, 'invalid RLP length')
            length = int.from_bytes(raw[start:start + count], 'big'); start += count
            require(length >= 56, 'noncanonical long RLP length')
        stop = start + length
        require(stop <= limit, 'truncated RLP payload')
        if not sequence:
            require(length != 1 or raw[start] >= 0x80, 'noncanonical short RLP string')
            return raw[start:stop], stop
        result = []
        while start < stop:
            require(len(result) < 1024, 'too many transaction list items')
            value, start = item(start, stop, depth + 1); result.append(value)
        return result, stop
    result, end = item(0, len(raw), 0)
    require(end == len(raw) and encode(result) == raw, 'noncanonical or trailing transaction data')
    return result


def integer(value):
    require(isinstance(value, bytes) and len(value) <= 32 and (not value or value[0] != 0),
            'noncanonical Ethereum transaction integer')
    return int.from_bytes(value, 'big')


def dynamic_fee(raw):
    require(isinstance(raw, bytes) and raw[:1] == b'\x02', 'only qualified EIP-1559 transactions are accepted')
    fields = parse(raw[1:])
    require(isinstance(fields, list) and len(fields) == 12, 'unexpected EIP-1559 field count')
    require(all(isinstance(fields[index], bytes) for index in range(12) if index != 8)
            and isinstance(fields[8], list), 'invalid EIP-1559 field types')
    values = {name: integer(fields[index]) for name, index in
              [('chain', 0), ('nonce', 1), ('tip', 2), ('fee', 3), ('gas', 4), ('value', 6),
               ('parity', 9), ('r', 10), ('s', 11)]}
    require(len(fields[5]) == 20 and values['tip'] <= values['fee'] and values['parity'] in (0, 1),
            'invalid EIP-1559 recipient, fees or signature parity')
    return dict(values, recipient='0x' + fields[5].hex(), data=fields[7], access_list=fields[8],
                signing_payload=b'\x02' + encode(fields[:9]))
