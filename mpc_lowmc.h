#ifndef MPC_LOWMC_H
#define MPC_LOWMC_H

#include "m4ri/m4ri.h"
#include "lowmc_pars.h"
#include "openssl/sha.h"

#define NUM_ROUNDS 137

typedef struct {
  mzd_t **s;
} view_t;

typedef struct {
  view_t **views;
  unsigned char ***keys;
  unsigned char ***r;
  unsigned char hashes[NUM_ROUNDS][3][SHA256_DIGEST_LENGTH];
  mzd_t ***y;
} proof_t;

typedef struct {
  mzd_t **x0m;
  mzd_t **x1m;
  mzd_t **x2m;
  mzd_t **r0m;
  mzd_t **r1m;
  mzd_t **r2m;
  mzd_t **x0s;
  mzd_t **r0s;
  mzd_t **x1s;
  mzd_t **r1s;
  mzd_t **t0;
  mzd_t **t1;
  mzd_t **t2;
} sbox_vars_t;

void free_proof(lowmc_t *lowmc, proof_t *proof);

/**
 * Initializes the views for the MPC execution of LowMC
 *
 * \param  lowmc the lowmc parameters
 * \return       an array containing the initialized views 
 */
mzd_t **mpc_init_views(lowmc_t *lowmc);

/**
 * Implements MPC LowMC encryption according to
 * https://eprint.iacr.org/2016/163.pdf
 *
 * \param  lowmc     the lowmc parameters
 * \param  lowmc_key the lowmc key
 * \param  p         the plaintext
 * \param  views     the views
 * \param  rvec      the randomness vector
 * \return           the ciphertext      
 */
mzd_t **mpc_lowmc_call(lowmc_t *lowmc, lowmc_key_t *lowmc_key, mzd_t *p, view_t *views, mzd_t ***rvec);

/**
 * Verifies a ZKBoo execution of a LowMC encryption
 * 
 * \param  lowmc     the lowmc parameters
 * \param  p         the plaintext
 * \param  views     the views
 * \param  rvec      the randomness vector
 * \return           0 on success and a value != 0 otherwise
 */
int mpc_lowmc_verify(lowmc_t *lowmc, mzd_t *p, view_t *views,  mzd_t ***rvec, int c);

#endif
