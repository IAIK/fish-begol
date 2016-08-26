#include "lowmc_pars.h"
#include "mpc.h"
#include "mzd_additional.h"
#include "randomness.h"

#include <m4ri/m4ri.h>
#include <stdbool.h>

mask_t *prepare_masks(mask_t *mask, rci_t n, rci_t m) {
  if(0 != n % (8 * sizeof(word)))
    return 0;
  if(mask == 0) 
    mask = (mask_t*)malloc(sizeof(mask_t));

  mask->x0   = mzd_init(1, n);
  mask->x1   = mzd_init(1, n);
  mask->x2   = mzd_init(1, n);
  mask->mask = mzd_init(1, n);

  for(int i = 0 ; i < n - 3 * m ; i++) {
    mzd_write_bit(mask->mask, 0, i, 1);
  }
  for(unsigned i = n - 3 * m; i < n ; i+=3) {
    mzd_write_bit(mask->x0, 0, i, 1);
  }
  mzd_shift_left(mask->x1, mask->x0, 1, 0);
  mzd_shift_left(mask->x2, mask->x0, 2, 0);

  return mask;
}

static mzd_t *mzd_sample_matrix_word(rci_t n, rci_t k, rci_t rank, bool with_xor) {
  mzd_t *A = mzd_init(n, k);
  mzd_t *B = mzd_init(n, k);
  do {
    mzd_randomize_ssl(A);
    if (with_xor) {
      for (rci_t i = 0; i < n; i++) {
        mzd_xor_bits(A, n - i - 1, (k + i + 1) % k, 1, 1);
      }
    }
    mzd_copy(B, A);
  } while (mzd_echelonize(A, 0) != rank);
  mzd_free(A);
  return B;
};

mzd_t *mzd_sample_lmatrix(rci_t n) {
  return mzd_sample_matrix_word(n, n, n, false);
}

mzd_t *mzd_sample_kmatrix(rci_t n, rci_t k) {
  rci_t r = (n < k) ? n : k;
  return mzd_sample_matrix_word(n, k, r, true);
}

lowmc_t *lowmc_init(size_t m, size_t n, size_t r, size_t k) {
  lowmc_t *lowmc = (lowmc_t*)malloc(sizeof(lowmc_t));
  lowmc->m = m;
  lowmc->n = n;
  lowmc->r = r;
  lowmc->k = k;

  lowmc->LMatrix = (mzd_t**)calloc(sizeof(mzd_t*),r);
  for(unsigned i=0; i<r; i++) {
    mzd_t *mat = mzd_sample_lmatrix(n);
    lowmc->LMatrix[i] = mzd_transpose(0, mat);
    mzd_free(mat);
  }

  lowmc->Constants = (mzd_t**)calloc(sizeof(mzd_t*),r);
  for(unsigned i=0; i<r; i++) {
    lowmc->Constants[i] = mzd_init_random_vector(n);
  }
  lowmc->KMatrix = (mzd_t**)calloc(sizeof(mzd_t*), r+1);
  for(unsigned i=0; i<r+1; i++) {
    mzd_t *mat = mzd_sample_kmatrix(n, k);
    lowmc->KMatrix[i] = mzd_transpose(0, mat);
    mzd_free(mat);
  }

  return lowmc;
}

lowmc_key_t *lowmc_keygen(lowmc_t *lowmc) {
  lowmc_key_t *lowmc_key = malloc(sizeof(lowmc_key_t));

  mzd_t* key = mzd_init_random_vector(lowmc->k);
  mzd_shared_init(lowmc_key, key);
  mzd_free(key);

  return lowmc_key;
}

void lowmc_free(lowmc_t *lowmc, lowmc_key_t *lowmc_key) {
  for(unsigned i=0; i<lowmc->r; i++) {
    mzd_free(lowmc->Constants[i]);
    mzd_free(lowmc->KMatrix[i]);
    mzd_free(lowmc->LMatrix[i]);
  }
  mzd_free(lowmc->KMatrix[lowmc->r]);
  free(lowmc->Constants);
  free(lowmc->LMatrix);
  free(lowmc->KMatrix);

  mzd_shared_free(lowmc_key);

  free(lowmc);
  free(lowmc_key);
}

void lowmc_secret_share(lowmc_t *lowmc, lowmc_key_t *lowmc_key) {
  mzd_shared_share(lowmc_key);
}
