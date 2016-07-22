#ifndef LOWMC_H
#define LOWMC_H

#include "m4ri/m4ri.h"
#include "lowmc_pars.h"

/**
 * Implements the LowMC sbox
 * 
 * \param out the output of the sbox
 * \param in  the input to the sbox
 * \param m   the number of sboxes
 */
void sbox_layer(mzd_t *out, mzd_t *in, rci_t m);

/**
 * Implements LowMC encryption 
 *
 * \param  lowmc the lowmc parameters
 * \param  p     the plaintext
 * \return       the ciphertext      
 */
mzd_t *lowmc_call(lowmc_t *lowmc, mzd_t *p);

#endif
