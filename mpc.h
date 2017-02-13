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

#ifndef MPC_H
#define MPC_H

#include "mpc_lowmc.h"
#include <m4ri/m4ri.h>

void mpc_shift_right(mzd_t* const* res, mzd_t* const* val, unsigned count, unsigned sc);

void mpc_shift_left(mzd_t* const* res, mzd_t* const* val, unsigned count, unsigned sc);

void mpc_and_const(mzd_t* const* res, mzd_t* const* first, mzd_t const* second, unsigned sc);

void mpc_xor(mzd_t* const* res, mzd_t* const* first, mzd_t* const* second, unsigned sc);

void mpc_clear(mzd_t** res, unsigned sc);

int mpc_and(mzd_t* const* res, mzd_t* const* first, mzd_t* const* second, mzd_t* const* r,
            view_t* view, unsigned viewshift, mzd_t* const* buffer);

int mpc_and_verify(mzd_t* const* res, mzd_t* const* first, mzd_t* const* second, mzd_t* const* r,
                   view_t const* view, mzd_t const* mask, unsigned viewshift, mzd_t* const* buffer);

#ifdef WITH_OPT
#include "simd.h"

int mpc_and_sse(__m128i* res, __m128i const* first, __m128i const* second, __m128i const* r,
                view_t const* view, unsigned viewshift);

int mpc_and_avx(__m256i* res, __m256i const* first, __m256i const* second, __m256i const* r,
                view_t const* view, unsigned viewshift);

int mpc_and_verify_sse(__m128i* res, __m128i const* first, __m128i const* second, __m128i const* r,
                       view_t const* view, __m128i const mask, unsigned viewshift);

int mpc_and_verify_avx(__m256i* res, __m256i const* first, __m256i const* second, __m256i const* r,
                       view_t const* view, __m256i const mask, unsigned viewshift);
#endif

/**
 * Linearly secret shares the vector v.
 *
 * \param  v the vector to be secret shared
 * \return the vector v represented as three shares
 */
mzd_t** mpc_init_share_vector(mzd_t const* v);

/**
 * Initializes a share vector where all three components
 * are set to v
 *
 * \param  v the vector to be copied to all three share components
 * \return   the vector v containing three copies of the vector
 */
mzd_t** mpc_init_plain_share_vector(mzd_t const* v);

/**
 * Initializes a vector representing a sharing of a random
 * vector
 *
 * \param  n the vector length
 * \param  sc    the share count
 * \return a random vector shared in three components
 */
mzd_t** mpc_init_random_vector(rci_t n, unsigned sc);

/**
 * Initializes an array of three empty vectors
 *
 * \param  n the vector length
 * \param    the array of vectors
 * \param  sc    the share count
 */
mzd_t** mpc_init_empty_share_vector(rci_t n, unsigned sc);

/**
 * Reconstructs a vector from three shares
 *
 * \param shared_vec an array containing the shares
 * \return           the reconstructed vector
 */
mzd_t* mpc_reconstruct_from_share(mzd_t* dst, mzd_t** shared_vec);

#if 0
/**
 * Computes the a &= b on two secret shared bits according to
 * https://eprint.iacr.org/2016/163.pdf
 *
 * \param  a     the three shares of the first bit
 * \param  b     the three shares of the second bit
 * \param  r     the three shares containing the randomness
 * \param  views the views
 * \param  i     the current view index
 * \param  bp    the position of the current bit within the view
 * \param  sc    the share count
 */
int mpc_and_bit(BIT* a, BIT* b, BIT* r, view_t* views, int* i, unsigned bp, unsigned sc);

int mpc_and_bit_verify(BIT* a, BIT* b, BIT* r, view_t* views, int* i, unsigned bp, unsigned sc);

/**
 * Computes a ^= b on two secret shared bits according to
 * https://eprint.iacr.org/2016/163.pdf
 *
 * \param  a  the three shares of the first bit
 * \param  b  the three shares of the second bit
 * \param  sc the share count
 */
void mpc_xor_bit(BIT* a, BIT* b, unsigned sc);

/**
 * Reads a secret shared bit from a given vector
 *
 * \param out destination of the secret shared bit
 * \param vec the secret shared vector
 * \param n   the position of the bit
 * \param sc  the share count
 */
void mpc_read_bit(BIT* out, mzd_t** vec, rci_t n, unsigned sc);

/**
 * Writes a secret shared bit to a given vector
 *
 * \param vec the secret shared vector
 * \param n   the position of the bit
 * \param bit the secret shared bit
 * \param sc  the share count
 */
void mpc_write_bit(mzd_t** vec, rci_t n, BIT* bit, unsigned sc);
#endif

/**
 * Computes the addition in GF(2) of two secret shared
 * vectors according to https://eprint.iacr.org/2016/163.pdf
 *
 * \param  result the result of the computation
 * \param  first  the first operand
 * \param  second the second operand
 * \param  sc     the share count
 * \return        the result of the computation
 */
mzd_t** mpc_add(mzd_t** result, mzd_t** first, mzd_t** second, unsigned sc);

/**
 * Computes the addition in GF(2) of a secret shared
 * vector and a constant vector according to
 * https://eprint.iacr.org/2016/163.pdf
 *
 * \param  result the result of the computation
 * \param  first  the first operand
 * \param  second the second operand
 * \param  sc     the share count
 * \param  c      the callenge for verification (0 if in proving mode)
 * \return        the result of the computation
 */
mzd_t** mpc_const_add(mzd_t** result, mzd_t** first, mzd_t const* second, unsigned sc, unsigned c);

/**
 * Computes result = first * second in GF(2) of a
 * secret shared vector and a matrix according to
 * https://eprint.iacr.org/2016/163.pdf
 *
 * \param  result the result of the computation
 * \param  matrix the matrix
 * \param  vector the secret shared vector
 * \param  sc     the share count
 * \return        the result of the computation
 */
mzd_t** mpc_const_mat_mul(mzd_t** result, mzd_t const* matrix, mzd_t** vector, unsigned sc);

void mpc_const_addmat_mul_l(mzd_t** result, mzd_t const* matrix, mzd_t** vector, unsigned sc) __attribute__((nonnull));

/**
 * Computes result = first * second in GF(2) of a
 * secret shared vector and a matrix according to
 * https://eprint.iacr.org/2016/163.pdf
 *
 * \param  result the result of the computation
 * \param  matrix the matrix
 * \param  vector the secret shared vector
 * \param  sc     the share count
 * \return        the result of the computation
 */
mzd_t** mpc_const_mat_mul_l(mzd_t** result, mzd_t const* matrix, mzd_t** vector, unsigned sc);

/**
 * Deep copies a secret shared vector
 *
 * \param out the destination
 * \param in  the source
 * \param  sc    the share count
 *
 */
void mpc_copy(mzd_t** out, mzd_t* const* in, unsigned sc);

/**
 * Prints a secret shared vector
 *
 * \param shared_vec the vector
 */
void mpc_print(mzd_t** shared_vec);

/**
 * Frees a secret shared vector
 */
void mpc_free(mzd_t** vec, unsigned sc);

#endif
