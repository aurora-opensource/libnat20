/*
 * Copyright 2025 Aurora Operations, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <nat20/crypto/nat20/sha.h>
#include <stdint.h>

n20_sha384_sha512_state_t n20_sha512_init(void) {
    n20_sha384_sha512_state_t state = {0};
    /* Constants from NIST FIPS 180-4, Section 5.3.5 */
    state.H[0] = 0x6a09e667f3bcc908;
    state.H[1] = 0xbb67ae8584caa73b;
    state.H[2] = 0x3c6ef372fe94f82b;
    state.H[3] = 0xa54ff53a5f1d36f1;
    state.H[4] = 0x510e527fade682d1;
    state.H[5] = 0x9b05688c2b3e6c1f;
    state.H[6] = 0x1f83d9abfb41bd6b;
    state.H[7] = 0x5be0cd19137e2179;

    return state;
}

n20_sha384_sha512_state_t n20_sha384_init(void) {
    n20_sha384_sha512_state_t state = {0};
    /* Constants from NIST FIPS 180-4, Section 5.3.4 */
    state.H[0] = 0xcbbb9d5dc1059ed8;
    state.H[1] = 0x629a292a367cd507;
    state.H[2] = 0x9159015a3070dd17;
    state.H[3] = 0x152fecd8f70e5939;
    state.H[4] = 0x67332667ffc00b31;
    state.H[5] = 0x8eb44a8768581511;
    state.H[6] = 0xdb0c2e0d64f98fa7;
    state.H[7] = 0x47b5481dbefa4fa4;

    return state;
}

/* Constants from NIST FIPS 180-4, Section 4.2.3 */
static uint64_t const K_512[] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817};

static uint64_t ch(uint64_t x, uint64_t y, uint64_t z) { return (x & y) ^ (~x & z); }

static uint64_t majority(uint64_t x, uint64_t y, uint64_t z) { return (x & y) ^ (x & z) ^ (y & z); }

static uint64_t rotr(uint64_t x, uint64_t n) { return (x >> n) | (x << (64 - n)); }

static uint64_t SIGMA0(uint64_t x) { return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39); }

static uint64_t SIGMA1(uint64_t x) { return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41); }

static uint64_t sigma0(uint64_t x) { return rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7); }

static uint64_t sigma1(uint64_t x) { return rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6); }

#define R_INDEX(i, x) ((-i + x) & 0x07)
#define REG_A(i) R_INDEX(i, 0)
#define REG_B(i) R_INDEX(i, 1)
#define REG_C(i) R_INDEX(i, 2)
#define REG_D(i) R_INDEX(i, 3)
#define REG_E(i) R_INDEX(i, 4)
#define REG_F(i) R_INDEX(i, 5)
#define REG_G(i) R_INDEX(i, 6)
#define REG_H(i) R_INDEX(i, 7)
#define W_INDEX(i) ((i)&0x0f)

static void n20_sha512_main(n20_sha384_sha512_state_t *state) {
    size_t j = 0;
    uint64_t R[8] = {0};
    uint64_t t1 = 0;

    for (j = 0; j < 8; ++j) {
        R[j] = state->H[j];
    }

    for (j = 0; j < 16; ++j) {
        t1 = state->W[j];

        t1 += R[REG_H(j)];
        t1 += SIGMA1(R[REG_E(j)]);
        t1 += ch(R[REG_E(j)], R[REG_F(j)], R[REG_G(j)]);
        t1 += K_512[j];

        R[REG_H(j)] = t1 + SIGMA0(R[REG_A(j)]) + majority(R[REG_A(j)], R[REG_B(j)], R[REG_C(j)]);
        R[REG_D(j)] += t1;
    }

    for (j = 16; j < 80; ++j) {
        t1 = state->W[W_INDEX(j)] += sigma1(state->W[W_INDEX(j - 2)]) + state->W[W_INDEX(j - 7)] +
                                     sigma0(state->W[W_INDEX(j - 15)]);

        t1 += R[REG_H(j)];
        t1 += SIGMA1(R[REG_E(j)]);
        t1 += ch(R[REG_E(j)], R[REG_F(j)], R[REG_G(j)]);
        t1 += K_512[j];

        R[REG_H(j)] = t1 + SIGMA0(R[REG_A(j)]) + majority(R[REG_A(j)], R[REG_B(j)], R[REG_C(j)]);
        R[REG_D(j)] += t1;
    }

    for (j = 0; j < 8; ++j) {
        state->H[j] += R[j];
    }
    /* Make a best effort to erase sensitive information from the stack.*/
    for (j = 0; j < 8; ++j) {
        *(uint64_t volatile *)&R[j] = 0;
    }
    *(uint64_t volatile *)&t1 = 0;
    state->fill = 0;
}

void n20_sha512_update(n20_sha384_sha512_state_t *state, n20_slice_t const data) {
    if (state == NULL || data.buffer == NULL) {
        /* No-op if no state or data is provided. */
        return;
    }

    size_t i = 0;
    state->total += data.size;

    while (i < data.size) {
        /* Fill the buffer with data. */
        size_t j = state->fill;
        for (; j < 128 && i < data.size; ++j) {
            state->W[j >> 3] <<= 8;
            state->W[j >> 3] |= data.buffer[i++];
        }
        if (j < 128) {
            state->fill = j;
            return;
        }

        n20_sha512_main(state);
    }
}

void n20_sha384_update(n20_sha384_sha512_state_t *state, n20_slice_t const data)
    __attribute__((alias("n20_sha512_update")));

static void n20_sha384_sha512_finalize(n20_sha384_sha512_state_t *state,
                                       uint8_t *digest,
                                       size_t digest_size) {
    if (state == NULL) {
        /* No-op if no state is provided. */
        return;
    }

    size_t i = state->fill;

    /* Adding a 0x80 byte must always be possible because of the
     * state->fill < 128 invariant upheld by n20_sha512_update function.
     */
    state->W[i >> 3] <<= 8;
    state->W[i >> 3] |= 0x80;
    ++i;

    /* This handles the case where less than 16 bytes are left
     * so that no space is left to add the 128 bit length.
     * In this case we need to process the current block and
     * add the length to the next block. */
    if (i > 112) {
        for (; i < 128; ++i) {
            state->W[i >> 3] <<= 8;
            state->W[i >> 3] |= 0x00;
        }
        n20_sha512_main(state);
        i = 0;
    }

    /* At this point it is guaranteed that the padding bit
     * has been added and at least 16 bytes are left to add the
     * message length. The following loop fills the buffer with
     * 0x00 bytes until until exactly 8(!) bytes are left to add
     * the length.
     * This implementation only supports 64 bit length. So rather
     * than using 128 bits for the length we use the last 64 bits
     * of the 128 bit length. This is sufficient for all practical
     * purposes, or so this author hopes.
     * precondition:  i <= 112
     * postcondition: i == 120 */
    for (; i < 120; ++i) {
        state->W[i >> 3] <<= 8;
        state->W[i >> 3] |= 0x00;
    }

    uint64_t bit_size = state->total * 8;

    /* Add the message length to the buffer.
     * precondition:  i == 120
     * postcondition: i == 128 */
    for (; i < 128; ++i) {
        state->W[i >> 3] <<= 8;
        state->W[i >> 3] |= (bit_size >> (8 * (127 - i))) & 0xff;
    }

    /* Padding is complete. Process the final chunk. */
    n20_sha512_main(state);

    /* Write the final hash state to the digest output buffer. */
    for (size_t i = 0; i < digest_size; ++i) {
        digest[i] = (state->H[i >> 3] >> (8 * (7 - (i & 0x7)))) & 0xff;
    }
}

void n20_sha512_finalize(n20_sha384_sha512_state_t *state, uint8_t digest[64]) {
    n20_sha384_sha512_finalize(state, digest, 64);
}

void n20_sha384_finalize(n20_sha384_sha512_state_t *state, uint8_t digest[48]) {
    n20_sha384_sha512_finalize(state, digest, 48);
}
