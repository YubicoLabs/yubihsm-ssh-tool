from __future__ import absolute_import, division

import struct
from cryptography.utils import int_to_bytes


def create_template(ts_public_key, key_whitelist, not_before, not_after,
                    principals_blacklist):
    TS_ALGO_TAG = 1
    TS_KEY_TAG = 2
    CA_KEYS_WL_TAG = 3
    NB_TAG = 4
    NA_TAG = 5
    PRINCIPALS_BL_TAG = 6

    templ = b''

    numbers = ts_public_key.public_numbers()
    pubkey_n = int_to_bytes(numbers.n)
    if len(pubkey_n) == 256:
        algo = 9
    elif len(pubkey_n) == 384:
        algo = 10
    elif len(pubkey_n) == 512:
        algo = 11
    else:
        return None

    templ += struct.pack('!B', TS_ALGO_TAG)
    templ += struct.pack('!H', 1)
    templ += struct.pack('!B', algo)

    templ += struct.pack('!B', TS_KEY_TAG)
    templ += struct.pack('!H', len(pubkey_n))
    templ += pubkey_n

    templ += struct.pack('!B', CA_KEYS_WL_TAG)
    templ += struct.pack('!H', len(key_whitelist) * 2)
    for s in key_whitelist:
        templ += struct.pack('!H', int(s))

    templ += struct.pack('!B', NB_TAG)
    templ += struct.pack('!H', 4)
    templ += struct.pack('!I', int(not_before))

    templ += struct.pack('!B', NA_TAG)
    templ += struct.pack('!H', 4)
    templ += struct.pack('!I', int(not_after))

    templ += struct.pack('!B', PRINCIPALS_BL_TAG)
    n_principals = len(principals_blacklist)
    total_principals_length = sum(len(s) for s in principals_blacklist)
    templ += struct.pack('!H', n_principals + total_principals_length)
    for s in principals_blacklist:
        templ += s.encode('utf8') + b'\x00'

    return templ
