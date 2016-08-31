#ifndef SIGNATURE_FIS_H
#define SIGNATURE_FIS_H

#include "signature_common.h"

typedef struct {
  lowmc_key_t* k;
} fis_private_key_t;

typedef struct {
  // pk = E_k(0)
  mzd_t* pk;
} fis_public_key_t;

void fis_create_key(public_parameters_t* pp, fis_private_key_t* private_key,
                           fis_public_key_t* public_key, clock_t* timings);

void fis_destroy_key(fis_private_key_t* private_key, fis_public_key_t* public_key);

proof_t* fis_prove(lowmc_t* lowmc, lowmc_key_t* lowmc_key, mzd_t* p, char *m, unsigned m_len, clock_t *timings);

int fis_verify(lowmc_t* lowmc, mzd_t* p, mzd_t* c, proof_t* prf, char *m, unsigned m_len, clock_t *timings);

#endif
