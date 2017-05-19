#ifndef MZD_ADDITIONAL_H
#define MZD_ADDITIONAL_H

#include "parameters.h"
#include "randomness.h"

#include <m4ri/m4ri.h>
#include <stdbool.h>

/**
 * Modified mzd_init calling malloc less often. Do not pass mzd_t instances
 * initialized with this function to mzd_free.
 */
mzd_t* mzd_local_init_ex(rci_t r, rci_t c, bool clear) __attribute__((assume_aligned(32)));

#define mzd_local_init(r, c) mzd_local_init_ex(r, c, true)

/**
 * Modified mzd_free for mzd_local_init.
 */
void mzd_local_free(mzd_t* v);
/**
 * Initialize multiple mzd_t instances using one large enough memory block.
 */
void mzd_local_init_multiple_ex(mzd_t** dst, size_t n, rci_t r, rci_t c, bool clear)
    __attribute__((nonnull(1)));

#define mzd_local_init_multiple(dst, n, r, c) mzd_local_init_multiple_ex(dst, n, r, c, true)

/**
 * mzd_free for mzd_local_init_multiple.
 */
void mzd_local_free_multiple(mzd_t** vs);
/**
 * Improved mzd_copy for specific memory layouts.
 */
mzd_t* mzd_local_copy(mzd_t* dst, mzd_t const* src) __attribute__((nonnull(2)));

void mzd_local_clear(mzd_t* c) __attribute__((nonnull));

/**
 * Initializes a random vector
 *
 * \param n the length of the vector
 */
mzd_t* mzd_init_random_vector(rci_t n);

mzd_t* mzd_init_random_vector_prng(rci_t n, aes_prng_t* aes_prng);

void mzd_randomize_ssl(mzd_t* val) __attribute__((nonnull(1)));

void mzd_randomize_from_seed(mzd_t* vector, const unsigned char key[16]) __attribute__((nonnull));

mzd_t* mzd_init_random_vector_from_seed(const unsigned char key[16], rci_t n);

void mzd_randomize_multiple_from_seed(mzd_t** vectors, unsigned int count,
                                      const unsigned char key[PRNG_KEYSIZE]);

mzd_t** mzd_init_random_vectors_from_seed(const unsigned char key[PRNG_KEYSIZE], rci_t n,
                                          unsigned count);

void mzd_shift_right(mzd_t* res, mzd_t const* val, unsigned count) __attribute__((nonnull));

void mzd_shift_left(mzd_t* res, mzd_t const* val, unsigned count) __attribute__((nonnull));

mzd_t* mzd_and(mzd_t* res, mzd_t const* first, mzd_t const* second) __attribute__((nonnull));

mzd_t* mzd_xor(mzd_t* res, mzd_t const* first, mzd_t const* second) __attribute__((nonnull));

/**
 * Compare two vectors for equality. Note that this version is optimized for
 * vectors with a multiple of sizeof(word) * 8 columns.
 *
 * \param first
 *          first vector
 * \param second
 *          second vector
 * \returns true if both vectors are equal, false otherwise.
 */
bool mzd_local_equal(mzd_t const* first, mzd_t const* second) __attribute__((nonnull));

/**
 * Compute v * A optimized for v being a vector.
 */
mzd_t* mzd_mul_v(mzd_t* c, mzd_t const* v, mzd_t const* At) __attribute__((nonnull));

/**
 * Compute c + v * A optimized for c and v being vectors.
 */
mzd_t* mzd_addmul_v(mzd_t* c, mzd_t const* v, mzd_t const* At) __attribute__((nonnull));

/**
 * Compute v * A optimized for v being a vector.
 */
mzd_t* mzd_mul_vl(mzd_t* c, mzd_t const* v, mzd_t const* At) __attribute__((nonnull));

/**
 * Compute c + v * A optimized for c and v being vectors.
 */
mzd_t* mzd_addmul_vl(mzd_t* c, mzd_t const* v, mzd_t const* At) __attribute__((nonnull));

/**
 * Compute v * A optimized for v being a vector.
 */
void mzd_mul_vlm(mzd_t** c, mzd_t const* const* v, mzd_t const* At, unsigned int sc)
    __attribute__((nonnull));

/**
 * Compute c + v * A optimized for c and v being vectors.
 */
void mzd_addmul_vlm(mzd_t** c, mzd_t const* const* v, mzd_t const* At, unsigned int sc)
    __attribute__((nonnull));

/**
 * Pre-compute matrices for faster mzd_addmul_v computions.
 *
 */
mzd_t* mzd_precompute_matrix_lookup(mzd_t const* A) __attribute__((nonnull));

#define FIRST_ROW(v) ((word*)(((void*)(v)) + 64))
#define CONST_FIRST_ROW(v) ((word const*)(((void const*)(v)) + 64))

#endif
