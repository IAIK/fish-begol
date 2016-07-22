#ifndef LOWMC_PARS_H
#define LOWMC_PARS_H

#include "m4ri/m4ri.h" 

// Modifications to reference implementation
//
// mzd_t *key => mzd_t **key to account for secret shared keys
//
typedef struct {
  size_t m;
  size_t n;
  size_t r;
  size_t k;
  mzd_t **key;
  mzd_t **LMatrix;
  mzd_t **KMatrix;
  mzd_t **Constants;
  
} lowmc_t;

mzd_t *mzd_sample_lmatrix(rci_t n);
mzd_t *mzd_sample_kmatrix(rci_t n, rci_t k);
lowmc_t *lowmc_init(size_t m, size_t n, size_t r, size_t k);
void lowmc_free(lowmc_t *lowmc);
void lowmc_secret_share(lowmc_t *lowmc);

#endif
