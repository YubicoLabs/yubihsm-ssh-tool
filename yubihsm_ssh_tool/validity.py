from __future__ import absolute_import, division

from datetime import datetime
import time
import re


_UNITS = {
    's': 1,
    'm': 60,
    'h': 60 * 60,
    'd': 60 * 60 * 24,
    'w': 60 * 60 * 24 * 7
}


def _convtime(string):
    m = re.findall(r'(\d+)([s|m|h|d|w])', string, re.M | re.I)
    return sum(int(match[0]) * _UNITS[match[1].lower()] for match in m)


def _parse_time(now, value):
    if value[0] == '+':
        return now + _convtime(value[1:])
    if value[0] == '-':
        return now - _convtime(value[1:])
    for pattern in ('%Y%m%d%H%M%S', '%Y%m%d'):
        try:
            return int(datetime.strptime(value, pattern).timestamp())
        except ValueError:
            continue
    raise ValueError('Invalid validity format')


def parse_validity(validity):
    """Parse a validity interval string, as used in `ssh-keygen -V`."""
    now = int(time.time())

    if validity:
        validity = validity.strip()
    if not validity:
        return now, 0, 0xffffffffffffffff

    if ':' in validity:
        from_part, to_part = validity.split(':', 1)
        if ':' in to_part:
            raise ValueError('Invalid Validity format')
        not_before = _parse_time(now, from_part)
    else:
        not_before = now - 60
        to_part = validity
    not_after = _parse_time(now, to_part)

    if not_before > not_after:
        raise ValueError('Invalid relative certificate time')

    return now, not_before, not_after
