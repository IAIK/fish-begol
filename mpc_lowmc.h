#ifndef MPC_LOWMC_H
#define MPC_LOWMC_H

#include "m4ri/m4ri.h"
#include "lowmc_pars.h"

typedef struct {
  mzd_t *s[3];
} view_t, view_v_t;

//typedef struct {
//  mzd_t *s[3];
//} view_v_t;

typedef struct {
  view_v_t **views;
} proof_t;

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
