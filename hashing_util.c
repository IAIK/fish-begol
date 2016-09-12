#include "hashing_util.h"
#include "mpc_lowmc.h"
#include <m4ri/m4ri.h>

static inline unsigned int getChAt(unsigned char const *ch, unsigned int i) {
  const int unsigned idx = i / 4;
  const int unsigned offset = (i % 4) * 2;

  return (ch[idx] >> offset) & 3;
}


static void hash_mzd(SHA256_CTX* ctx, mzd_t const* v) {
  const rci_t nrows = v->nrows;
  const unsigned int width = sizeof(word) * v->width;
  for (rci_t m = 0; m < nrows; ++m) {
    SHA256_Update(ctx, v->rows[m], width);
  }
}

/*
 * Computes the SHA256 hash of a view using openssl (similar as in
 * https://github.com/Sobuno/ZKBoo/blob/master/MPC_SHA256/shared.h)
 */
void H(const unsigned char k[16], mzd_t* y[3], const view_t* v, unsigned vidx, unsigned vcnt,
       const unsigned char r[4], unsigned char hash[SHA256_DIGEST_LENGTH]) {
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, k, 16);

  for (unsigned i = 0; i < 3; ++i) {
    hash_mzd(&ctx, y[i]);
  }
  for (unsigned i = 0; i < vcnt; ++i) {
    hash_mzd(&ctx, v[i].s[vidx]);
  }

  SHA256_Update(&ctx, r, 4);
  SHA256_Final(hash, &ctx);
}

void fis_H3_verify(unsigned char h[NUM_ROUNDS][2][SHA256_DIGEST_LENGTH],
                   unsigned char hp[NUM_ROUNDS][SHA256_DIGEST_LENGTH],
                   unsigned char ch_in[(NUM_ROUNDS + 3) / 4], char* m, unsigned m_len, int* ch) {
  unsigned char tmp[NUM_ROUNDS][3][SHA256_DIGEST_LENGTH];
  for (unsigned i = 0; i < NUM_ROUNDS; i++) {
    if (getChAt(ch_in, i) == 0) {
      memcpy(tmp[i][0], h[i], 2 * SHA256_DIGEST_LENGTH);
      memcpy(tmp[i][2], hp[i], SHA256_DIGEST_LENGTH);
    } else if (getChAt(ch_in, i) == 1) {
      memcpy(tmp[i][0], hp[i], SHA256_DIGEST_LENGTH);
      memcpy(tmp[i][1], h[i], 2 * SHA256_DIGEST_LENGTH);
    } else {
      memcpy(tmp[i][0], h[i][1], SHA256_DIGEST_LENGTH);
      memcpy(tmp[i][1], hp[i], SHA256_DIGEST_LENGTH);
      memcpy(tmp[i][2], h[i][0], SHA256_DIGEST_LENGTH);
    }
  }

  fis_H3(tmp, m, m_len, ch);
}

/**
 * Computes the challenge (similar as in
 * https://github.com/Sobuno/ZKBoo/blob/master/MPC_SHA256/shared.h)
 */
void fis_H3(unsigned char h[NUM_ROUNDS][3][SHA256_DIGEST_LENGTH], char* m, unsigned m_len,
            int* ch) {

  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, h, 3 * SHA256_DIGEST_LENGTH * NUM_ROUNDS);
  SHA256_Update(&ctx, m, m_len);
  SHA256_Final(hash, &ctx);

  // Pick bits from hash
  unsigned int i          = 0;
  unsigned int bitTracker = 0;
  while (i < NUM_ROUNDS) {
    if (bitTracker >= SHA256_DIGEST_LENGTH * 8) { // Generate new hash
      SHA256_Init(&ctx);
      SHA256_Update(&ctx, hash, sizeof(hash));
      SHA256_Final(hash, &ctx);
      bitTracker = 0;
      // printf("Generated new hash\n");
    }

    unsigned char twobits = (hash[bitTracker / 8] >> (bitTracker % 8)) & 0x3;
    if (twobits != 0x3) {
      ch[i++] = twobits;
    }
    bitTracker += 2;
  }
}

static void bg_H3_compute(unsigned char hash[SHA256_DIGEST_LENGTH], int* ch) {
  // Pick bits from hash
  int* eof                = ch + NUM_ROUNDS;
  unsigned int bitTracker = 0;
  while (ch < eof) {
    if (bitTracker >= SHA256_DIGEST_LENGTH * 8) { // Generate new hash
      SHA256_CTX ctx;
      SHA256_Init(&ctx);
      SHA256_Update(&ctx, hash, SHA256_DIGEST_LENGTH);
      SHA256_Final(hash, &ctx);
      bitTracker = 0;
      // printf("Generated new hash\n");
    }

    unsigned char twobits = (hash[bitTracker / 8] >> (bitTracker % 8)) & 0x3;
    if (twobits != 0x3) {
      *ch++ = twobits;
    }
    bitTracker += 2;
  }
}

void bg_H3_verify(unsigned char const h1[NUM_ROUNDS][2][SHA256_DIGEST_LENGTH],
                  unsigned char const hp1[NUM_ROUNDS][SHA256_DIGEST_LENGTH],
                  unsigned char const h2[NUM_ROUNDS][2][SHA256_DIGEST_LENGTH],
                  unsigned char const hp2[NUM_ROUNDS][SHA256_DIGEST_LENGTH],
                  unsigned char const ch_in[(NUM_ROUNDS + 3) / 4], int* ch) {

  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_CTX ctx;
  SHA256_Init(&ctx);

  for (unsigned i = 0; i < NUM_ROUNDS; i++) {
    switch (getChAt(ch_in, i)) {
    case 0: {
      SHA256_Update(&ctx, h1[i], 2 * SHA256_DIGEST_LENGTH);
      SHA256_Update(&ctx, hp1[i], SHA256_DIGEST_LENGTH);
      break;
    }
    case 1: {
      SHA256_Update(&ctx, hp1[i], SHA256_DIGEST_LENGTH);
      SHA256_Update(&ctx, h1[i], 2 * SHA256_DIGEST_LENGTH);
      break;
    }
    default: {
      SHA256_Update(&ctx, h1[i][1], SHA256_DIGEST_LENGTH);
      SHA256_Update(&ctx, hp1[i], SHA256_DIGEST_LENGTH);
      SHA256_Update(&ctx, h1[i][0], SHA256_DIGEST_LENGTH);
      break;
    }
    }
  }

  for (unsigned i = 0; i < NUM_ROUNDS; i++) {
    switch (getChAt(ch_in, i)) {
    case 0: {
      SHA256_Update(&ctx, h2[i], 2 * SHA256_DIGEST_LENGTH);
      SHA256_Update(&ctx, hp2[i], SHA256_DIGEST_LENGTH);
      break;
    }
    case 1: {
      SHA256_Update(&ctx, hp2[i], SHA256_DIGEST_LENGTH);
      SHA256_Update(&ctx, h2[i], 2 * SHA256_DIGEST_LENGTH);
      break;
    }
    default: {
      SHA256_Update(&ctx, h2[i][1], SHA256_DIGEST_LENGTH);
      SHA256_Update(&ctx, hp2[i], SHA256_DIGEST_LENGTH);
      SHA256_Update(&ctx, h2[i][0], SHA256_DIGEST_LENGTH);
      break;
    }
    }
  }

  SHA256_Final(hash, &ctx);
  bg_H3_compute(hash, ch);
}

void bg_H3(const unsigned char h1[NUM_ROUNDS][3][SHA256_DIGEST_LENGTH],
           const unsigned char h2[NUM_ROUNDS][3][SHA256_DIGEST_LENGTH], int* ch) {
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, h1, 3 * SHA256_DIGEST_LENGTH * NUM_ROUNDS);
  SHA256_Update(&ctx, h2, 3 * SHA256_DIGEST_LENGTH * NUM_ROUNDS);
  SHA256_Final(hash, &ctx);

  bg_H3_compute(hash, ch);
}
