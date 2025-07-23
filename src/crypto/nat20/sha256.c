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

n20_sha224_sha256_state_t n20_sha256_init(void) {
    n20_sha224_sha256_state_t state = {0};
    /* Constants from NIST FIPS 180-4, Section 5.3.3 */
    state.H[0] = 0x6a09e667;
    state.H[1] = 0xbb67ae85;
    state.H[2] = 0x3c6ef372;
    state.H[3] = 0xa54ff53a;
    state.H[4] = 0x510e527f;
    state.H[5] = 0x9b05688c;
    state.H[6] = 0x1f83d9ab;
    state.H[7] = 0x5be0cd19;

    return state;
}

n20_sha224_sha256_state_t n20_sha224_init(void) {
    n20_sha224_sha256_state_t state = {0};
    /* Constants from NIST FIPS 180-4, Section 5.3.2 */
    state.H[0] = 0xc1059ed8;
    state.H[1] = 0x367cd507;
    state.H[2] = 0x3070dd17;
    state.H[3] = 0xf70e5939;
    state.H[4] = 0xffc00b31;
    state.H[5] = 0x68581511;
    state.H[6] = 0x64f98fa7;
    state.H[7] = 0xbefa4fa4;

    return state;
}

/* Constants from NIST FIPS 180-4, Section 4.2.2 */
static uint32_t const K_256[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

static uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }

static uint32_t majority(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }

static uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

static uint32_t SIGMA0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }

static uint32_t SIGMA1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }

static uint32_t sigma0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }

static uint32_t sigma1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

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

static void n20_sha256_main(n20_sha224_sha256_state_t *state) {
    size_t j = 0;
    uint32_t R[8] = {0};
    uint32_t t1 = 0;

    for (j = 0; j < 8; ++j) {
        R[j] = state->H[j];
    }

    for (j = 0; j < 16; ++j) {
        t1 = state->W[j];

        t1 += R[REG_H(j)];
        t1 += SIGMA1(R[REG_E(j)]);
        t1 += ch(R[REG_E(j)], R[REG_F(j)], R[REG_G(j)]);
        t1 += K_256[j];

        R[REG_H(j)] = t1 + SIGMA0(R[REG_A(j)]) + majority(R[REG_A(j)], R[REG_B(j)], R[REG_C(j)]);
        R[REG_D(j)] += t1;
    }

    for (j = 16; j < 64; ++j) {
        t1 = state->W[W_INDEX(j)] += sigma1(state->W[W_INDEX(j - 2)]) + state->W[W_INDEX(j - 7)] +
                                     sigma0(state->W[W_INDEX(j - 15)]);

        t1 += R[REG_H(j)];
        t1 += SIGMA1(R[REG_E(j)]);
        t1 += ch(R[REG_E(j)], R[REG_F(j)], R[REG_G(j)]);
        t1 += K_256[j];

        R[REG_H(j)] = t1 + SIGMA0(R[REG_A(j)]) + majority(R[REG_A(j)], R[REG_B(j)], R[REG_C(j)]);
        R[REG_D(j)] += t1;
    }

    for (j = 0; j < 8; ++j) {
        state->H[j] += R[j];
    }
    /* Make a best effort to erase sensitive information from the stack.*/
    for (j = 0; j < 8; ++j) {
        *(uint32_t volatile *)&R[j] = 0;
    }
    *(uint32_t volatile *)&t1 = 0;
    state->fill = 0;
}

void n20_sha256_update(n20_sha224_sha256_state_t *state, n20_slice_t const data) {
    if (state == NULL || data.buffer == NULL) {
        /* No-op if no state or data is provided. */
        return;
    }

    size_t i = 0;
    state->total += data.size;

    while (i < data.size) {
        /* Fill the buffer with data. */
        size_t j = state->fill;
        for (; j < 64 && i < data.size; ++j) {
            state->W[j >> 2] <<= 8;
            state->W[j >> 2] |= data.buffer[i++];
        }
        if (j < 64) {
            state->fill = j;
            return;
        }

        n20_sha256_main(state);
    }
}

void n20_sha224_update(n20_sha224_sha256_state_t *state, n20_slice_t const data)
    __attribute__((alias("n20_sha256_update")));

static void n20_sha224_sha256_finalize(n20_sha224_sha256_state_t *state,
                                       uint8_t *digest,
                                       size_t digest_size) {
    if (state == NULL) {
        /* No-op if no state is provided. */
        return;
    }

    size_t i = state->fill;

    /* Adding a 0x80 byte must always be possible because of the
     * state->fill < 64 invariant upheld by n20_sha256_update function.
     */
    state->W[i >> 2] <<= 8;
    state->W[i >> 2] |= 0x80;
    ++i;

    /* This handles the case where less than 8 bytes are left
     * so that no space is left to add the 64 bit length.
     * In this case we need to process the current block and
     * add the length to the next block. */
    if (i > 56) {
        for (; i < 64; ++i) {
            state->W[i >> 2] <<= 8;
            state->W[i >> 2] |= 0x00;
        }
        n20_sha256_main(state);
        i = 0;
    }

    /* At this point it is guaranteed that the padding bit
     * has been added and at least 8 bytes are left to add the
     * message length. The following loop fills the buffer with
     * 0x00 bytes until until exactly 8 bytes are left to add
     * the length.
     * precondition:  i <= 56
     * postcondition: i == 56 */
    for (; i < 56; ++i) {
        state->W[i >> 2] <<= 8;
        state->W[i >> 2] |= 0x00;
    }

    uint64_t bit_size = state->total * 8;

    /* Add the message length to the buffer.
     * precondition:  i == 56
     * postcondition: i == 64 */
    for (; i < 64; ++i) {
        state->W[i >> 2] <<= 8;
        state->W[i >> 2] |= (bit_size >> (8 * (63 - i))) & 0xff;
    }

    /* Padding is complete. Process the final chunk. */
    n20_sha256_main(state);

    /* Write the final hash state to the digest output buffer. */
    for (size_t i = 0; i < digest_size; ++i) {
        digest[i] = (state->H[i >> 2] >> (8 * (3 - (i & 0x3)))) & 0xff;
    }
}

void n20_sha256_finalize(n20_sha224_sha256_state_t *state, uint8_t digest[32]) {
    n20_sha224_sha256_finalize(state, digest, 32);
}

void n20_sha224_finalize(n20_sha224_sha256_state_t *state, uint8_t digest[28]) {
    n20_sha224_sha256_finalize(state, digest, 28);
}
