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
  commitment_update(ctx, CONST_FIRST_ROW(v), sizeof(word) * v->width * v->nrows);
}

#if COMMITMENT_LENGTH == SHA256_DIGEST_LENGTH
#define hash_mzd commit_mzd
#else
static void hash_mzd(SHA256_CTX* ctx, mzd_t const* v) {
  SHA256_Update(ctx, CONST_FIRST_ROW(v), sizeof(word) * v->width * v->nrows);
}
#endif

void H(const unsigned char k[PRNG_KEYSIZE], mzd_t* y[SC_PROOF], const view_t* v, unsigned vidx,
       unsigned vcnt, const unsigned char r[COMMITMENT_RAND_LENGTH],
       unsigned char hash[COMMITMENT_LENGTH]) {
  commitment_ctx ctx;
  commitment_init(&ctx);
  commitment_update(&ctx, k, PRNG_KEYSIZE);

  for (unsigned i = 0; i < SC_PROOF; ++i) {
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
                   unsigned char const ch_in[(NUM_ROUNDS + 3) / 4], const uint8_t* m, size_t m_len,
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

void fis_H3(unsigned char const h[NUM_ROUNDS][SC_PROOF][COMMITMENT_LENGTH], const uint8_t* m,
            size_t m_len, unsigned char* ch) {

  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, h, SC_PROOF * COMMITMENT_LENGTH * NUM_ROUNDS);
  SHA256_Update(&ctx, m, m_len);
  SHA256_Final(hash, &ctx);

  H3_compute(hash, ch);
}

void bg_H3_verify(const mzd_t* beta, const mzd_t* c, const mzd_t* m, const mzd_t* y,
                  unsigned char const h1[NUM_ROUNDS][2][COMMITMENT_LENGTH],
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

  hash_mzd(&ctx, beta);
  hash_mzd(&ctx, c);
  hash_mzd(&ctx, m);
  hash_mzd(&ctx, y);

  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_Final(hash, &ctx);
  H3_compute(hash, ch);
}

void bg_H3(const mzd_t* beta, const mzd_t* c, const mzd_t* m, const mzd_t* y,
           const unsigned char h1[NUM_ROUNDS][SC_PROOF][COMMITMENT_LENGTH],
           const unsigned char h2[NUM_ROUNDS][SC_PROOF][COMMITMENT_LENGTH], unsigned char* ch) {
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, h1, SC_PROOF * COMMITMENT_LENGTH * NUM_ROUNDS);
  SHA256_Update(&ctx, h2, SC_PROOF * COMMITMENT_LENGTH * NUM_ROUNDS);
  hash_mzd(&ctx, beta);
  hash_mzd(&ctx, c);
  hash_mzd(&ctx, m);
  hash_mzd(&ctx, y);
  SHA256_Final(hash, &ctx);

  H3_compute(hash, ch);
}
