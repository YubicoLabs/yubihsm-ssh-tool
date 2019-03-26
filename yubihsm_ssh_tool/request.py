from __future__ import absolute_import, division

import os
import struct
from cryptography.utils import int_to_bytes

CERT_NAME = b'ssh-rsa-cert-v01@openssh.com'
CERT_TYPE = 1  # 1 = user, 2 = host
CA_KEY_TYPE = b'ssh-rsa'


def create_request(ca_public_key, user_public_key, key_id, principals, options,
                   not_before, not_after, serial):
    req = b''

    req += struct.pack('!I', len(CERT_NAME)) + CERT_NAME

    nonce = os.urandom(32)
    req += struct.pack('!I', len(nonce)) + nonce

    numbers = user_public_key.public_numbers()
    pubkey_e = int_to_bytes(numbers.e)
    pubkey_n = int_to_bytes(numbers.n)
    if pubkey_n[0] >= 0x80:
        pubkey_n = b'\x00' + pubkey_n

    req += struct.pack('!I', len(pubkey_e)) + pubkey_e

    req += struct.pack('!I', len(pubkey_n)) + pubkey_n

    req += struct.pack('!Q', serial)

    req += struct.pack('!I', CERT_TYPE)

    key_id = key_id.encode('utf8')
    req += struct.pack('!I', len(key_id)) + key_id

    # for each principal print principals
    # starting with the total length of principal+length pairs
    n_principals = len(principals)
    total_principals_length = sum(len(s) for s in principals)

    req += struct.pack('!I', (n_principals * 4) + total_principals_length)

    for s in principals:
        s = s.encode('utf8')
        req += struct.pack('!I', len(s)) + s

    req += struct.pack('!Q', not_after)

    req += struct.pack('!Q', not_before)

    CRITICAL_OPTIONS = b''  # TODO(adma): FIXME
    req += CRITICAL_OPTIONS
    req += struct.pack('!I', len(CRITICAL_OPTIONS))

    EXTENSIONS = b'\x00\x00\x00\x15\x70\x65\x72\x6d\x69\x74\x2d\x58\x31\x31\x2d\x66\x6f\x72\x77\x61\x72\x64\x69\x6e\x67\x00\x00\x00\x00\x00\x00\x00\x17\x70\x65\x72\x6d\x69\x74\x2d\x61\x67\x65\x6e\x74\x2d\x66\x6f\x72\x77\x61\x72\x64\x69\x6e\x67\x00\x00\x00\x00\x00\x00\x00\x16\x70\x65\x72\x6d\x69\x74\x2d\x70\x6f\x72\x74\x2d\x66\x6f\x72\x77\x61\x72\x64\x69\x6e\x67\x00\x00\x00\x00\x00\x00\x00\x0a\x70\x65\x72\x6d\x69\x74\x2d\x70\x74\x79\x00\x00\x00\x00\x00\x00\x00\x0e\x70\x65\x72\x6d\x69\x74\x2d\x75\x73\x65\x72\x2d\x72\x63\x00\x00\x00\x00'  # noqa TODO(adma): FIXME
    req += struct.pack('!I', len(EXTENSIONS)) + EXTENSIONS

    req += struct.pack('!I', 0)  # NOTE(adma): RFU

    numbers = ca_public_key.public_numbers()
    pubkey_e = int_to_bytes(numbers.e)
    pubkey_n = int_to_bytes(numbers.n)
    if pubkey_n[0] >= 0x80:
        pubkey_n = b'\x00' + pubkey_n

    req += struct.pack(
        '!I',
        4 + len(CA_KEY_TYPE) + 4 + len(pubkey_e) + 4 + len(pubkey_n)
    )

    req += struct.pack('!I', len(CA_KEY_TYPE)) + CA_KEY_TYPE
    req += struct.pack('!I', len(pubkey_e)) + pubkey_e
    req += struct.pack('!I', len(pubkey_n)) + pubkey_n

    return req
