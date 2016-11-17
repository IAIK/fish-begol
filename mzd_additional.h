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

#ifndef MZD_ADDITIONAL_H
#define MZD_ADDITIONAL_H

#include "randomness.h"
#include <m4ri/m4ri.h>

/**
 * Modified mzd_init calling malloc less often. Do not pass mzd_t instances
 * initialized with this function to mzd_free.
 */
mzd_t* mzd_local_init(rci_t r, rci_t c) __attribute__((assume_aligned(32)));
/**
 * Modified mzd_free for mzd_local_init.
 */
void mzd_local_free(mzd_t* v);
/**
 * Initialize multiple mzd_t instances using one large enough memory block.
 */
void mzd_local_init_multiple(mzd_t** dst, size_t n, rci_t r, rci_t c);
/**
 * mzd_free for mzd_local_init_multiple.
 */
void mzd_local_free_multiple(mzd_t** vs);
/**
 * Improved mzd_copy for specific memory layouts.
 */
mzd_t* mzd_local_copy(mzd_t* dst, mzd_t const* src);

/**
 * Initializes a random vector
 *
 * \param n the length of the vector
 */
mzd_t* mzd_init_random_vector(rci_t n);

mzd_t* mzd_init_random_vector_prng(rci_t n, aes_prng_t* aes_prng);

void mzd_randomize_ssl(mzd_t* val);

mzd_t** mzd_init_random_vectors_from_seed(const unsigned char key[16], rci_t n, unsigned count);

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

#endif
