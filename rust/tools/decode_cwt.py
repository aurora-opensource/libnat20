#!/usr/bin/env python3
# Copyright 2026 Aurora Operations, Inc.
#
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0
#
# This work is dual licensed.
# You may use it under Apache-2.0 or GPL-2.0 at your option.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# OR
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see
# <https://www.gnu.org/licenses/>.
"""Independently decodes and verifies a nat20 CWT (COSE_Sign1, Ed25519).

Usage:
  decode_cwt.py CERT.bin                 # self-signed: verify with embedded key
  decode_cwt.py CERT.bin ISSUER_CERT.bin # verify with issuer cert's key

Uses a minimal built-in CBOR decoder (definite-length subset) and the
`cryptography` package for Ed25519 verification. Exits non-zero on any
structural or signature failure.
"""

import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

CLAIM_NAMES = {
    1: "issuer",
    2: "subject",
    -4670545: "code_hash",
    -4670546: "code_descriptor",
    -4670547: "configuration_hash",
    -4670548: "configuration_descriptor",
    -4670549: "authority_hash",
    -4670550: "authority_descriptor",
    -4670551: "mode",
    -4670552: "subject_public_key",
    -4670553: "key_usage",
    -4670554: "profile",
}


def decode(data: bytes, pos: int = 0):
    """Minimal definite-length CBOR decoder. Returns (value, next_pos)."""
    ib = data[pos]
    major, arg = ib >> 5, ib & 0x1F
    pos += 1
    if arg < 24:
        n = arg
    elif arg in (24, 25, 26, 27):
        width = 1 << (arg - 24)
        n = int.from_bytes(data[pos : pos + width], "big")
        pos += width
    else:
        raise ValueError(f"unsupported additional info {arg}")
    if major == 0:
        return n, pos
    if major == 1:
        return -1 - n, pos
    if major == 2:
        return data[pos : pos + n], pos + n
    if major == 3:
        return data[pos : pos + n].decode("utf-8"), pos + n
    if major == 4:
        items = []
        for _ in range(n):
            item, pos = decode(data, pos)
            items.append(item)
        return items, pos
    if major == 5:
        pairs = {}
        for _ in range(n):
            key, pos = decode(data, pos)
            value, pos = decode(data, pos)
            pairs[key] = value
        return pairs, pos
    raise ValueError(f"unsupported major type {major}")


def encode_sig_structure(protected: bytes, payload: bytes) -> bytes:
    """Sig_structure for COSE_Sign1 with empty external_aad."""

    def bstr(b: bytes) -> bytes:
        assert len(b) < 65536
        if len(b) < 24:
            return bytes([0x40 | len(b)]) + b
        if len(b) < 256:
            return bytes([0x58, len(b)]) + b
        return b"\x59" + len(b).to_bytes(2, "big") + b

    return b"\x84\x6aSignature1" + bstr(protected) + b"\x40" + bstr(payload)


def load(path: str):
    with open(path, "rb") as f:
        cert = f.read()
    sign1, end = decode(cert)
    if end != len(cert):
        raise ValueError("trailing bytes after COSE_Sign1")
    if not (isinstance(sign1, list) and len(sign1) == 4):
        raise ValueError("COSE_Sign1 must be an array of 4")
    protected, unprotected, payload, signature = sign1
    prot_map, _ = decode(protected)
    if prot_map != {1: -8}:
        raise ValueError(f"unexpected protected header {prot_map!r}")
    if unprotected != {}:
        raise ValueError("unprotected header must be empty")
    claims, _ = decode(payload)
    return protected, payload, signature, claims


def public_key_of(claims) -> bytes:
    cose_key, _ = decode(claims[-4670552])
    if cose_key[1] != 1 or cose_key[-1] != 6 or cose_key[3] != -8:
        raise ValueError(f"not an Ed25519 OKP verify key: {cose_key!r}")
    return cose_key[-2]


def main() -> int:
    if len(sys.argv) not in (2, 3):
        print(__doc__, file=sys.stderr)
        return 2

    protected, payload, signature, claims = load(sys.argv[1])
    if len(sys.argv) == 3:
        _, _, _, issuer_claims = load(sys.argv[2])
        verify_key = public_key_of(issuer_claims)
        against = "issuer certificate key"
    else:
        verify_key = public_key_of(claims)
        against = "embedded key (self-signed)"

    print("claims:")
    for label, value in claims.items():
        name = CLAIM_NAMES.get(label, f"?{label}")
        shown = value.hex() if isinstance(value, bytes) else value
        print(f"  {name:26} = {shown}")

    try:
        Ed25519PublicKey.from_public_bytes(verify_key).verify(
            signature, encode_sig_structure(protected, payload)
        )
    except InvalidSignature:
        print(f"FAIL: signature does not verify against {against}", file=sys.stderr)
        return 1
    print(f"OK: signature verifies against {against}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
