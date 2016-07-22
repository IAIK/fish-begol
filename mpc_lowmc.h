#ifndef MPC_LOWMC_H
#define MPC_LOWMC_H

#include "m4ri/m4ri.h"
#include "lowmc_pars.h"

/**
 * Implements the MPC LowMC sbox according to
 * https://eprint.iacr.org/2016/163.pdf
 * 
 * \param out the output of the sbox
 * \param in  the input to the sbox
 * \param m   the number of sboxes
 */
void mpc_sbox_layer(mzd_t **out, mzd_t **in, rci_t m);

/**
 * Implements MPC LowMC encryption according to
 * https://eprint.iacr.org/2016/163.pdf
 *
 * \param  lowmc the lowmc parameters
 * \param  p     the plaintext
 * \return       the ciphertext      
 */
mzd_t **mpc_lowmc_call(lowmc_t *lowmc, mzd_t *p);

#endif
