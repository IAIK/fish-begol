#ifndef MPC_LOWMC_H
#define MPC_LOWMC_H

#include "m4ri/m4ri.h"
#include "lowmc_pars.h"

void mpc_sbox_layer(mzd_t **out, mzd_t **in, rci_t m);
mzd_t **mpc_lowmc_call(lowmc_t *lowmc, mzd_t *p);

#endif
