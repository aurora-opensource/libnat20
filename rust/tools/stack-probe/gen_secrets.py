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
"""Writes probe_secrets.h: every secret the probe's calls derive.

Same inputs as tools/gen_vectors.py (root CDI 00..1f; code hash c0*64,
configuration descriptor c1*64, authority hash c2*64, mode normal, hidden
c3*32), so the next CDI here equals VEC_NEXT_CDI. Only the standard library
is used, independently of the code under test.
"""

import hashlib
import hmac
import struct
import sys


def hkdf_expand_block(prk: bytes, info: bytes) -> bytes:
    """The first HKDF-Expand-SHA512 block, T(1): all of it is key material."""
    return hmac.new(prk, info + b"\x01", hashlib.sha512).digest()


# SHA-512 (FIPS 180-4) compression, for the HMAC midstates below: the
# standard library exposes no intermediate state.
K512 = [int(x, 16) for x in """
428a2f98d728ae22 7137449123ef65cd b5c0fbcfec4d3b2f e9b5dba58189dbbc 3956c25bf348b538
59f111f1b605d019 923f82a4af194f9b ab1c5ed5da6d8118 d807aa98a3030242 12835b0145706fbe
243185be4ee4b28c 550c7dc3d5ffb4e2 72be5d74f27b896f 80deb1fe3b1696b1 9bdc06a725c71235
c19bf174cf692694 e49b69c19ef14ad2 efbe4786384f25e3 0fc19dc68b8cd5b5 240ca1cc77ac9c65
2de92c6f592b0275 4a7484aa6ea6e483 5cb0a9dcbd41fbd4 76f988da831153b5 983e5152ee66dfab
a831c66d2db43210 b00327c898fb213f bf597fc7beef0ee4 c6e00bf33da88fc2 d5a79147930aa725
06ca6351e003826f 142929670a0e6e70 27b70a8546d22ffc 2e1b21385c26c926 4d2c6dfc5ac42aed
53380d139d95b3df 650a73548baf63de 766a0abb3c77b2a8 81c2c92e47edaee6 92722c851482353b
a2bfe8a14cf10364 a81a664bbc423001 c24b8b70d0f89791 c76c51a30654be30 d192e819d6ef5218
d69906245565a910 f40e35855771202a 106aa07032bbd1b8 19a4c116b8d2d0c8 1e376c085141ab53
2748774cdf8eeb99 34b0bcb5e19b48a8 391c0cb3c5c95a63 4ed8aa4ae3418acb 5b9cca4f7763e373
682e6ff3d6b2b8a3 748f82ee5defb2fc 78a5636f43172f60 84c87814a1f0ab72 8cc702081a6439ec
90befffa23631e28 a4506cebde82bde9 bef9a3f7b2c67915 c67178f2e372532b ca273eceea26619c
d186b8c721c0c207 eada7dd6cde0eb1e f57d4f7fee6ed178 06f067aa72176fba 0a637dc5a2c898a6
113f9804bef90dae 1b710b35131c471b 28db77f523047d84 32caab7b40c72493 3c9ebe0a15c9bebc
431d67c49c100d4c 4cc5d4becb3e42b6 597f299cfc657e2a 5fcb6fab3ad6faec 6c44198c4a475817
""".split()]
H512 = [int(x, 16) for x in """
6a09e667f3bcc908 bb67ae8584caa73b 3c6ef372fe94f82b a54ff53a5f1d36f1
510e527fade682d1 9b05688c2b3e6c1f 1f83d9abfb41bd6b 5be0cd19137e2179
""".split()]
M64 = (1 << 64) - 1


def rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (64 - n))) & M64


def sha512_compress(state: list, block: bytes) -> list:
    w = list(struct.unpack(">16Q", block))
    for t in range(16, 80):
        s0 = rotr(w[t - 15], 1) ^ rotr(w[t - 15], 8) ^ (w[t - 15] >> 7)
        s1 = rotr(w[t - 2], 19) ^ rotr(w[t - 2], 61) ^ (w[t - 2] >> 6)
        w.append((w[t - 16] + s0 + w[t - 7] + s1) & M64)
    a, b, c, d, e, f, g, h = state
    for t in range(80):
        t1 = (h + (rotr(e, 14) ^ rotr(e, 18) ^ rotr(e, 41)) + ((e & f) ^ (~e & g))
              + K512[t] + w[t]) & M64
        t2 = ((rotr(a, 28) ^ rotr(a, 34) ^ rotr(a, 39)) + ((a & b) ^ (a & c) ^ (b & c))) & M64
        a, b, c, d, e, f, g, h = (t1 + t2) & M64, a, b, c, (d + t1) & M64, e, f, g
    return [(x + y) & M64 for x, y in zip(state, (a, b, c, d, e, f, g, h))]


def hmac_secrets(name: str, key: bytes) -> dict:
    """What an HMAC keyed with `key` computes on that is key-equivalent: the
    padded key blocks, and the SHA-512 states after them (the midstates),
    as stored in memory (u64 words, little-endian on armv7)."""
    out = {}
    for pad, label in ((0x36, "ipad"), (0x5C, "opad")):
        block = bytes(b ^ pad for b in key.ljust(128, b"\0"))
        out[f"{name} ^ {label}"] = block[:32]
        state = struct.pack("<8Q", *sha512_compress(H512, block))
        out[f"{name} {label} midstate lo"] = state[:32]
        out[f"{name} {label} midstate hi"] = state[32:]
    return out


def word_swapped(value: bytes) -> bytes:
    """`value` as a hash's message schedule holds it: big-endian u64 words
    loaded into little-endian memory."""
    return b"".join(value[i : i + 8][::-1] for i in range(0, len(value), 8))


ASYM_SALT = bytes.fromhex(
    "63b6a04d2c077fc10f639f21da793844"
    "356cc2b0b441b3a77124035c03f8e1be"
    "6035d31f282821a7450a02222ab1b3cf"
    "f1679b05ab1ca5d1affb789ccd2b0b3b"
)
KEY_INFO = ASYM_SALT + b"Key Pair Attest"

CDI = bytes(range(32))
input_digest = hashlib.sha512(
    b"\xc0" * 64 + b"\xc1" * 64 + b"\xc2" * 64 + b"\x01" + b"\xc3" * 32
).digest()

secrets = {"root CDI": CDI}
t = hkdf_expand_block(CDI, input_digest + b"CDI_Attest")
next_cdi = t[:32]
secrets["next CDI"] = next_cdi
secrets["next CDI HKDF tail"] = t[32:]
for name, cdi in (("device-id", CDI), ("next-stage", next_cdi)):
    t = hkdf_expand_block(cdi, KEY_INFO)
    seed = t[:32]
    secrets[f"{name} seed"] = seed
    secrets[f"{name} seed HKDF tail"] = t[32:]
    # RFC 8032: SHA-512(seed) gives the scalar (first half, before
    # clamping) and the nonce prefix (second half).
    expanded = hashlib.sha512(seed).digest()
    secrets[f"{name} scalar"] = expanded[:32]
    secrets[f"{name} nonce prefix"] = expanded[32:]

# HKDF keys its HMACs with the CDIs.
secrets.update(hmac_secrets("root CDI", CDI))
secrets.update(hmac_secrets("next CDI", next_cdi))
secrets.update({f"{name} (word-swapped)": word_swapped(value)
                for name, value in list(secrets.items())})

out = sys.stdout
out.write("/* Generated by tools/stack-probe/gen_secrets.py — do not edit. */\n")
out.write("static struct { char const *name; uint8_t bytes[32]; } const secrets[] = {\n")
for name, value in secrets.items():
    body = ", ".join(f"0x{b:02x}" for b in value)
    out.write(f'\t{{"{name}", {{{body}}}}},\n')
out.write("};\n")
