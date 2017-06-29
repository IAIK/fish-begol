#ifndef SIGNATURE_COMMON_H
#define SIGNATURE_COMMON_H

#include <stdbool.h>
#include <time.h>

#include "lowmc_pars.h"
#include "mpc_lowmc.h"

typedef struct {
  // The LowMC instance.
  mpc_lowmc_t* lowmc;
} public_parameters_t;

bool create_instance(public_parameters_t* pp, int m, int n, int r, int k);

void destroy_instance(public_parameters_t* pp);

void init_view(mpc_lowmc_t const* lowmc, view_t* views[NUM_ROUNDS]);
void free_view(mpc_lowmc_t const* lowmc, view_t* views[NUM_ROUNDS]);

#endif
