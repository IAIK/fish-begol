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

#include "lowmc_pars.h"
#include "mpc.h"
#include "mzd_additional.h"
#include "randomness.h"

#include <m4ri/m4ri.h>
#include <stdbool.h>

static mask_t* prepare_masks(mask_t* mask, rci_t n, rci_t m) {
  mask->x0      = mzd_local_init(1, n);
  mask->x1      = mzd_local_init(1, n);
  mask->x2      = mzd_local_init(1, n);
  mask->mask    = mzd_local_init(1, n);

  const int bound = n - 3 * m;
  for (int i = 0; i < bound; ++i) {
    mzd_write_bit(mask->mask, 0, i, 1);
  }
  for (int i = bound; i < n; i += 3) {
    mzd_write_bit(mask->x0, 0, i, 1);
  }
  mzd_shift_left(mask->x1, mask->x0, 1);
  mzd_shift_left(mask->x2, mask->x0, 2);

  return mask;
}

static mzd_t* mzd_sample_matrix_word(rci_t n, rci_t k, rci_t rank, bool with_xor) {
  // use mzd_init for A since m4ri will work with it in mzd_echolonize
  // also, this function cannot be parallelized as mzd_echolonize will call
  // mzd_init and mzd_free at will causing various crashes.
  mzd_t* A = mzd_init(n, k);
  mzd_t* B = mzd_local_init(n, k);
  do {
    mzd_randomize_ssl(A);
    if (with_xor) {
      for (rci_t i = 0; i < n; i++) {
        mzd_xor_bits(A, n - i - 1, (k + i + 1) % k, 1, 1);
      }
    }
    mzd_local_copy(B, A);
  } while (mzd_echelonize(A, 0) != rank);
  mzd_free(A);
  return B;
};

/**
 * Samples the L matrix for the LowMC instance
 *
 * \param n the blocksize
 */
static mzd_t* mzd_sample_lmatrix(rci_t n) {
  return mzd_sample_matrix_word(n, n, n, false);
}

/**
 * Samples the K matrix for the LowMC instance
 * \param n the blocksize
 */
static mzd_t* mzd_sample_kmatrix(rci_t n, rci_t k) {
  return mzd_sample_matrix_word(n, k, MIN(n, k), true);
}

lowmc_t* lowmc_init(size_t m, size_t n, size_t r, size_t k) {
  lowmc_t* lowmc = calloc(sizeof(lowmc_t), 1);
  lowmc->m       = m;
  lowmc->n       = n;
  lowmc->r       = r;
  lowmc->k       = k;

  lowmc->k0_matrix = mzd_sample_kmatrix(k, n);
#ifdef NOSCR
  lowmc->k0_lookup = mzd_precompute_matrix_lookup(lowmc->k0_matrix);
#endif

  lowmc->rounds = calloc(sizeof(lowmc_round_t), r);
  for (unsigned int i = 0; i < r; ++i) {
    lowmc->rounds[i].l_matrix = mzd_sample_lmatrix(n);
    lowmc->rounds[i].k_matrix = mzd_sample_kmatrix(k, n);
    lowmc->rounds[i].constant = mzd_init_random_vector(n);

#ifdef NOSCR
    lowmc->rounds[i].l_lookup = mzd_precompute_matrix_lookup(lowmc->rounds[i].l_matrix);
    lowmc->rounds[i].k_lookup = mzd_precompute_matrix_lookup(lowmc->rounds[i].k_matrix);
#endif
  }

  if (!prepare_masks(&lowmc->mask, n, m)) {
    lowmc_free(lowmc);
    return NULL;
  }

  return lowmc;
}

lowmc_key_t* lowmc_keygen(lowmc_t* lowmc) {
  return mzd_init_random_vector(lowmc->k);
}

void lowmc_free(lowmc_t* lowmc) {
  for (unsigned i = 0; i < lowmc->r; ++i) {
#ifdef NOSCR
    mzd_local_free(lowmc->rounds[i].k_lookup);
    mzd_local_free(lowmc->rounds[i].l_lookup);
#endif
    mzd_local_free(lowmc->rounds[i].constant);
    mzd_local_free(lowmc->rounds[i].k_matrix);
    mzd_local_free(lowmc->rounds[i].l_matrix);
  }
#ifdef NOSCR
  mzd_local_free(lowmc->k0_lookup);
#endif
  mzd_local_free(lowmc->k0_matrix);
  free(lowmc->rounds);

  mzd_local_free(lowmc->mask.x0);
  mzd_local_free(lowmc->mask.x1);
  mzd_local_free(lowmc->mask.x2);
  mzd_local_free(lowmc->mask.mask);

  free(lowmc);
}

void lowmc_key_free(lowmc_key_t* lowmc_key) {
  mzd_local_free(lowmc_key);
}
