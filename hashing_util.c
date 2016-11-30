/*
 * fish-begol - Implementation of the Fish and Begol signature schemes
 * Copyright (C) 2016 Graz University of Technology
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "hashing_util.h"
#include "mpc_lowmc.h"

#include <m4ri/m4ri.h>

#if COMMITMENT_LENGTH == SHA256_DIGEST_LENGTH
typedef SHA256_CTX commitment_ctx;
#define commitment_init SHA256_Init
#define commitment_update SHA256_Update
#define commitment_final SHA256_Final
#elif COMMITMENT_LENGTH == SHA368_DIGEST_LENGTH
typedef SHA386_CTX commitment_ctx;
#define commitment_init SHA386_Init
#define commitment_update SHA386_Update
#define commitment_final SHA386_Final
#elif COMMITMENT_LENGTH == SHA512_DIGEST_LENGTH
typedef SHA512_CTX commitment_ctx;
#define commitment_init SHA512_Init
#define commitment_update SHA512_Update
#define commitment_final SHA512_Final
#endif

static void commit_mzd(commitment_ctx* ctx, mzd_t const* v) {
  const rci_t nrows        = v->nrows;
  const unsigned int width = sizeof(word) * v->width;
  for (rci_t m = 0; m < nrows; ++m) {
    commitment_update(ctx, v->rows[m], width);
  }
}

/*
 * Computes the SHA256 hash of a view using openssl (similar as in
 * https://github.com/Sobuno/ZKBoo/blob/master/MPC_SHA256/shared.h)
 */
void H(const unsigned char k[16], mzd_t* y[3], const view_t* v, unsigned vidx, unsigned vcnt,
       const unsigned char r[COMMITMENT_RAND_LENGTH], unsigned char hash[COMMITMENT_LENGTH]) {
  commitment_ctx ctx;
  commitment_init(&ctx);
  commitment_update(&ctx, k, 16);

  for (unsigned i = 0; i < 3; ++i) {
    commit_mzd(&ctx, y[i]);
  }
  for (unsigned i = 0; i < vcnt; ++i) {
    commit_mzd(&ctx, v[i].s[vidx]);
  }

  commitment_update(&ctx, r, COMMITMENT_RAND_LENGTH);
  commitment_final(hash, &ctx);
}

static void H3_compute(unsigned char hash[SHA256_DIGEST_LENGTH], unsigned char* ch) {
  // Pick bits from hash
  unsigned char* eof      = ch + NUM_ROUNDS;
  unsigned int bitTracker = 0;
  while (ch < eof) {
    if (bitTracker >= SHA256_DIGEST_LENGTH * 8) {
      SHA256_CTX ctx;
      SHA256_Init(&ctx);
      SHA256_Update(&ctx, hash, SHA256_DIGEST_LENGTH);
      SHA256_Final(hash, &ctx);
      bitTracker = 0;
    }

    unsigned char twobits = (hash[bitTracker / 8] >> (bitTracker % 8)) & 0x3;
    if (twobits != 0x3) {
      *ch++ = twobits;
    }
    bitTracker += 2;
  }
}

void fis_H3_verify(unsigned char const h[NUM_ROUNDS][2][COMMITMENT_LENGTH],
                   unsigned char const hp[NUM_ROUNDS][COMMITMENT_LENGTH],
                   unsigned char const ch_in[(NUM_ROUNDS + 3) / 4], const char* m, unsigned m_len,
                   unsigned char* ch) {
  SHA256_CTX ctx;
  SHA256_Init(&ctx);

  for (unsigned i = 0; i < NUM_ROUNDS; i++) {
    switch (getChAt(ch_in, i)) {
    case 0: {
      SHA256_Update(&ctx, h[i], 2 * COMMITMENT_LENGTH);
      SHA256_Update(&ctx, hp[i], COMMITMENT_LENGTH);
      break;
    }
    case 1: {
      SHA256_Update(&ctx, hp[i], COMMITMENT_LENGTH);
      SHA256_Update(&ctx, h[i], 2 * COMMITMENT_LENGTH);
      break;
    }
    default: {
      SHA256_Update(&ctx, h[i][1], COMMITMENT_LENGTH);
      SHA256_Update(&ctx, hp[i], COMMITMENT_LENGTH);
      SHA256_Update(&ctx, h[i][0], COMMITMENT_LENGTH);
      break;
    }
    }
  }
  SHA256_Update(&ctx, m, m_len);

  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_Final(hash, &ctx);
  H3_compute(hash, ch);
}

/**
 * Computes the challenge.
 */
void fis_H3(unsigned char const h[NUM_ROUNDS][3][COMMITMENT_LENGTH], const char* m, unsigned m_len,
            unsigned char* ch) {

  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, h, 3 * COMMITMENT_LENGTH * NUM_ROUNDS);
  SHA256_Update(&ctx, m, m_len);
  SHA256_Final(hash, &ctx);

  H3_compute(hash, ch);
}

void bg_H3_verify(unsigned char const h1[NUM_ROUNDS][2][COMMITMENT_LENGTH],
                  unsigned char const hp1[NUM_ROUNDS][COMMITMENT_LENGTH],
                  unsigned char const h2[NUM_ROUNDS][2][COMMITMENT_LENGTH],
                  unsigned char const hp2[NUM_ROUNDS][COMMITMENT_LENGTH],
                  unsigned char const ch_in[(NUM_ROUNDS + 3) / 4], unsigned char* ch) {

  SHA256_CTX ctx;
  SHA256_Init(&ctx);

  for (unsigned i = 0; i < NUM_ROUNDS; i++) {
    switch (getChAt(ch_in, i)) {
    case 0: {
      SHA256_Update(&ctx, h1[i], 2 * COMMITMENT_LENGTH);
      SHA256_Update(&ctx, hp1[i], COMMITMENT_LENGTH);
      break;
    }
    case 1: {
      SHA256_Update(&ctx, hp1[i], COMMITMENT_LENGTH);
      SHA256_Update(&ctx, h1[i], 2 * COMMITMENT_LENGTH);
      break;
    }
    default: {
      SHA256_Update(&ctx, h1[i][1], COMMITMENT_LENGTH);
      SHA256_Update(&ctx, hp1[i], COMMITMENT_LENGTH);
      SHA256_Update(&ctx, h1[i][0], COMMITMENT_LENGTH);
      break;
    }
    }
  }

  for (unsigned i = 0; i < NUM_ROUNDS; i++) {
    switch (getChAt(ch_in, i)) {
    case 0: {
      SHA256_Update(&ctx, h2[i], 2 * COMMITMENT_LENGTH);
      SHA256_Update(&ctx, hp2[i], COMMITMENT_LENGTH);
      break;
    }
    case 1: {
      SHA256_Update(&ctx, hp2[i], COMMITMENT_LENGTH);
      SHA256_Update(&ctx, h2[i], 2 * COMMITMENT_LENGTH);
      break;
    }
    default: {
      SHA256_Update(&ctx, h2[i][1], COMMITMENT_LENGTH);
      SHA256_Update(&ctx, hp2[i], COMMITMENT_LENGTH);
      SHA256_Update(&ctx, h2[i][0], COMMITMENT_LENGTH);
      break;
    }
    }
  }

  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_Final(hash, &ctx);
  H3_compute(hash, ch);
}

void bg_H3(const unsigned char h1[NUM_ROUNDS][3][COMMITMENT_LENGTH],
           const unsigned char h2[NUM_ROUNDS][3][COMMITMENT_LENGTH], unsigned char* ch) {
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, h1, 3 * COMMITMENT_LENGTH * NUM_ROUNDS);
  SHA256_Update(&ctx, h2, 3 * COMMITMENT_LENGTH * NUM_ROUNDS);
  SHA256_Final(hash, &ctx);

  H3_compute(hash, ch);
}
