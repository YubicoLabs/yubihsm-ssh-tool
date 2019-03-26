# Copyright 2016-2018 Yubico AB
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import, division

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from binascii import b2a_hex

import re
import sys
import struct
import argparse

from .request import create_request
from .template import create_template
from .validity import parse_validity


_VALIDITY_DASH = re.compile(r'^-\d+[s|m|h|d|w]')


def build_parser():
    parser = argparse.ArgumentParser(prog='yubihsm-ssh-tool')
    parser.set_defaults(func=lambda _: parser.print_help())

    subparsers = parser.add_subparsers()

    parser_req = subparsers.add_parser('req', help='Create an SSH request.')
    parser_req.set_defaults(func=req)

    parser_req.add_argument('-s', '--ca', required=True,
                            help='CA PUBLIC key file, in PEM format.')
    parser_req.add_argument('-t', '--timestamp', required=True,
                            help='Timestamp PRIVATE key file, in PEM format.')
    parser_req.add_argument('-I', '--identity', required=True,
                            help='Certificate identity.')
    parser_req.add_argument('-n', '--principals', nargs='+', default=[],
                            help='List of principals.')
    parser_req.add_argument('-O', '--option', help='Certificate option.')
    parser_req.add_argument('-V', '--validity', help='Validity interval.')
    parser_req.add_argument('-z', '--serial', type=int, default=0,
                            help='Serial number.')
    parser_req.add_argument('public_key', help='Public key file.')

    parser_tplt = subparsers.add_parser('templ', help='Create an SSH template.')
    parser_tplt.set_defaults(func=templ)

    parser_tplt.add_argument('-T', '--timestamp', required=True,
                             help='Timestamp PUBLIC key file, in PEM format.')
    parser_tplt.add_argument('-k', '--whitelist', required=True,
                             nargs='+', help='White-list of key CA key IDs.')
    parser_tplt.add_argument('-b', '--before', required=True,
                             help='Not before offset, in seconds.')
    parser_tplt.add_argument('-a', '--after', required=True,
                             help='Not after offset, in seconds.')
    parser_tplt.add_argument('-p', '--blacklist', required=True,
                             nargs='+', help='Black-list of principals.')

    return parser


def main():
    # Correctly parse validity argument that starts with "-".
    for pos, val in enumerate(sys.argv):
        if _VALIDITY_DASH.match(val):
            sys.argv[pos] = ' ' + val

    args = build_parser().parse_args()
    args.func(args)


def req(args):
    with open(args.timestamp, 'rb') as ts_private_key_file:
        ts_private_key = serialization.load_pem_private_key(
            ts_private_key_file.read(),
            password=None,
            backend=default_backend()
        )

    with open(args.public_key, 'rb') as user_public_key_file:
        user_public_key = serialization.load_ssh_public_key(
            user_public_key_file.read(),
            backend=default_backend()
        )

    with open(args.ca, 'rb') as ca_public_key_file:
        ca_public_key = serialization.load_pem_public_key(
            ca_public_key_file.read(),
            backend=default_backend()
        )

    now, not_after, not_before = parse_validity(args.validity)

    req = create_request(
        ca_public_key,
        user_public_key,
        args.identity,
        args.principals,
        args.option,
        not_before,
        not_after,
        args.serial
    )

    # Hash the request
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(req)
    request_hash = digest.finalize()

    print('Hash is:', b2a_hex(request_hash))

    # Hash request + timestamp for signing
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(request_hash)
    digest.update(struct.pack('!I', now))
    message_hash = digest.finalize()

    signature = ts_private_key.sign(
            message_hash,
            padding.PKCS1v15(),
            utils.Prehashed(hashes.SHA256())
    )

    with open('req.dat', 'wb') as f:
        f.write(struct.pack('!I', now) + signature + req)


def templ(args):
    with open(args.timestamp, 'rb') as ts_public_key_file:
        ts_public_key = serialization.load_pem_public_key(
            ts_public_key_file.read(),
            backend=default_backend()
        )

    templ = create_template(
        ts_public_key,
        args.whitelist,
        args.before,
        args.after,
        args.blacklist
    )

    with open('templ.dat', 'wb') as f:
        f.write(templ)


if __name__ == '__main__':
    main()
