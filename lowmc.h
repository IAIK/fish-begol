#ifndef LOWMC_H
#define LOWMC_H

#include "m4ri/m4ri.h"
#include "lowmc_pars.h"

void sbox_layer(mzd_t *out, mzd_t *in, rci_t m);
mzd_t *lowmc_call(lowmc_t *lowmc, mzd_t *p);

#endif
