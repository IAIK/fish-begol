#include "hashing_util.h"
#include "mpc_lowmc.h"
#include <m4ri/m4ri.h>

static void hash_mzd(SHA256_CTX* ctx, mzd_t* v) {
  const rci_t nrows = v->nrows;
  for (rci_t m = 0; m < nrows; ++m) {
    SHA256_Update(ctx, v->rows[m], sizeof(word) * v->width);
  }
}

/*
 * Computes the SHA256 hash of a view using openssl (similar as in
 * https://github.com/Sobuno/ZKBoo/blob/master/MPC_SHA256/shared.h)
 */
void H(unsigned char k[16], mzd_t* y[3], view_t* v, unsigned vidx, unsigned vcnt,
       unsigned char r[4], unsigned char hash[SHA256_DIGEST_LENGTH]) {
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

/**
 * Computes the challenge (similar as in
 * https://github.com/Sobuno/ZKBoo/blob/master/MPC_SHA256/shared.h)
 */
void H3(unsigned char c[NUM_ROUNDS][3][SHA256_DIGEST_LENGTH], char *m, unsigned m_len, int* ch) {

  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, c, 3 * SHA256_DIGEST_LENGTH * NUM_ROUNDS);
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

void H4(unsigned char c1[NUM_ROUNDS][3][SHA256_DIGEST_LENGTH],
        unsigned char c2[NUM_ROUNDS][3][SHA256_DIGEST_LENGTH], int* ch) {
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, c1, 3 * SHA256_DIGEST_LENGTH * NUM_ROUNDS);
  SHA256_Update(&ctx, c2, 3 * SHA256_DIGEST_LENGTH * NUM_ROUNDS);
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
