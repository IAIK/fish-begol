#include "lowmc_pars.h"
#include "mpc.h"
#include "mzd_additional.h"
#include "randomness.h"

#include <m4ri/m4ri.h>
#include <stdbool.h>

mask_t* prepare_masks(mask_t* mask, rci_t n, rci_t m) {
  if (0 != n % (8 * sizeof(word)))
    return 0;
  if (mask == 0)
    mask = (mask_t*)malloc(sizeof(mask_t));

  mask->x0   = mzd_local_init(1, n);
  mask->x1   = mzd_local_init(1, n);
  mask->x2   = mzd_local_init(1, n);
  mask->mask = mzd_local_init(1, n);

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

  lowmc->rounds = calloc(sizeof(lowmc_round_t), r);
  for (unsigned int i = 0; i < r; ++i) {
    lowmc->rounds[i].l_matrix = mzd_sample_lmatrix(n);
    lowmc->rounds[i].k_matrix = mzd_sample_kmatrix(k, n);
    lowmc->rounds[i].constant = mzd_init_random_vector(n);
  }

  prepare_masks(&lowmc->mask, n, m);

  return lowmc;
}

lowmc_key_t* lowmc_keygen(lowmc_t* lowmc) {
  return mzd_init_random_vector(lowmc->k);
}

void lowmc_free(lowmc_t* lowmc) {
  for (unsigned i = 0; i < lowmc->r; ++i) {
    mzd_local_free(lowmc->rounds[i].constant);
    mzd_local_free(lowmc->rounds[i].k_matrix);
    mzd_local_free(lowmc->rounds[i].l_matrix);
  }
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
