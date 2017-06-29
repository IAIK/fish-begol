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
void fis_H3(unsigned char const h[NUM_ROUNDS][SC_PROOF][COMMITMENT_LENGTH], const uint8_t* m,
            size_t m_len, unsigned char* ch);

/**
 * Computes the challenge for Fish (when verifying).
 */
void fis_H3_verify(unsigned char const h[NUM_ROUNDS][SC_VERIFY][COMMITMENT_LENGTH],
                   unsigned char const hp[NUM_ROUNDS][COMMITMENT_LENGTH],
                   unsigned char const ch_in[(NUM_ROUNDS + 3) / 4], const uint8_t* m, size_t m_len,
                   unsigned char* ch);

static inline unsigned int getChAt(unsigned char const* const ch, unsigned int i) {
  const unsigned int idx    = i >> 2;
  const unsigned int offset = (i & 0x3) << 1;

  return (ch[idx] >> offset) & 0x3;
}

#endif
