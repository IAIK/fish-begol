#ifndef MPC_LOWMC_H
#define MPC_LOWMC_H

#include "m4ri/m4ri.h"
#include "lowmc_pars.h"

typedef struct {
  mzd_t *s[3];
} view_t;

/**
 * Implements the MPC LowMC sbox according to
 * https://eprint.iacr.org/2016/163.pdf
 * 
 * \param out   the output of the sbox
 * \param in    the input to the sbox
 * \param m     the number of sboxes
 * \param views the views
 * \param i     the current view
 */
void mpc_sbox_layer(mzd_t **out, mzd_t **in, rci_t m, view_t *views, int *i, mzd_t **rvec, unsigned sc);

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
 * \param  lowmc the lowmc parameters
 * \param  p     the plaintext
 * \param  views the views
 * \return       the ciphertext      
 */
mzd_t **mpc_lowmc_call(lowmc_t *lowmc, lowmc_key_t *lowmc_key, mzd_t *p, view_t *views, mzd_t ***rvec, unsigned sc);

#endif
