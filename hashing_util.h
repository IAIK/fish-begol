#ifndef HASHING_UTIL_H
#define HASHING_UTIL_H

#include "mpc_lowmc.h"
#include "parameters.h"

/**
 * Computes commitments to the view of an execution.
 */
void H(const unsigned char k[PRNG_KEYSIZE], mzd_t* y[SC_PROOF], view_t const* v, unsigned vidx,
       unsigned vcnt, const unsigned char r[COMMITMENT_RAND_LENGTH],
       unsigned char hash[COMMITMENT_LENGTH]);

/**
 * Computes the challenge for Fish (when signing).
 */
void fis_H3(unsigned char const h[NUM_ROUNDS][SC_PROOF][COMMITMENT_LENGTH], const char* m,
            unsigned m_len, unsigned char* ch);

/**
 * Computes the challenge for Fish (when verifying).
 */
void fis_H3_verify(unsigned char const h[NUM_ROUNDS][SC_VERIFY][COMMITMENT_LENGTH],
                   unsigned char const hp[NUM_ROUNDS][COMMITMENT_LENGTH],
                   unsigned char const ch_in[(NUM_ROUNDS + 3) / 4], const char* m, unsigned m_len,
                   unsigned char* ch);

void bg_H3(const mzd_t* beta, const mzd_t* c, const mzd_t* m, const mzd_t* y,
           const unsigned char c1[NUM_ROUNDS][SC_PROOF][COMMITMENT_LENGTH],
           const unsigned char c2[NUM_ROUNDS][SC_PROOF][COMMITMENT_LENGTH], unsigned char* ch);

void bg_H3_verify(const mzd_t* beta, const mzd_t* c, const mzd_t* m, const mzd_t* y,
                  unsigned char const h1[NUM_ROUNDS][2][COMMITMENT_LENGTH],
                  unsigned char const hp1[NUM_ROUNDS][COMMITMENT_LENGTH],
                  unsigned char const h2[NUM_ROUNDS][2][COMMITMENT_LENGTH],
                  unsigned char const hp2[NUM_ROUNDS][COMMITMENT_LENGTH],
                  unsigned char const ch_in[(NUM_ROUNDS + 3) / 4], unsigned char* ch);

static inline unsigned int getChAt(unsigned char const* const ch, unsigned int i) {
  const unsigned int idx    = i / 4;
  const unsigned int offset = (i % 4) * 2;

  return (ch[idx] >> offset) & 0x3;
}

#endif
