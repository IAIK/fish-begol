#ifndef MZD_ADDITIONAL_H
#define MZD_ADDITIONAL_H

#include "randomness.h"
#include <m4ri/m4ri.h>

/**
 * Initializes a random vector
 *
 * \param n the length of the vector
 */
mzd_t* mzd_init_random_vector(rci_t n);

void mzd_randomize_ssl(mzd_t* val);

void mzd_randomize_upper_triangular(mzd_t* valu);

mzd_t** mzd_init_random_vectors_from_seed(unsigned char key[16], rci_t n, unsigned count);

void mzd_shift_right(mzd_t* res, mzd_t const* val, unsigned count);

void mzd_shift_left(mzd_t* res, mzd_t const* val, unsigned count);

mzd_t* mzd_and(mzd_t* res, mzd_t const* first, mzd_t const* second);

mzd_t* mzd_xor(mzd_t* res, mzd_t const* first, mzd_t const* second);

/**
 * Compare two vectors for equality. Note that this version is optimized for
 * vectors with a multiple of sizeof(word) * 8 columns.
 *
 * \param first
 *          first vector
 * \param second
 *          second vector
 * \returns 0 if both vectors are equal, non-zero otherwise.
 */
int mzd_equal(mzd_t const* first, mzd_t const* second);

/**
 * Compute v * A optimized for v being a vector.
 */
mzd_t* mzd_mul_v(mzd_t* c, mzd_t const* v, mzd_t const* At);

/**
 * Compute c + v * A optimized for c and v being vectors.
 */
mzd_t* mzd_addmul_v(mzd_t* c, mzd_t const* v, mzd_t const* At);

typedef struct {
  unsigned int share_count;
  mzd_t** shared;
} mzd_shared_t;

void mzd_shared_init(mzd_shared_t* shared_value, mzd_t* value);
void mzd_shared_copy(mzd_shared_t* dst, mzd_shared_t* src);
void mzd_shared_from_shares(mzd_shared_t* shared_value, mzd_t** shares, unsigned int share_count);
void mzd_shared_share(mzd_shared_t* shared_value);
void mzd_shared_share_prng(mzd_shared_t* shared_value, aes_prng_t* aes_prng);
void mzd_shared_clear(mzd_shared_t* shared_value);

#endif
