#ifndef SIGNATURE_COMMON_H
#define SIGNATURE_COMMON_H

#include <time.h>

#include "lowmc_pars.h"
#include "mpc_lowmc.h"

#define TIMING_SCALE 1000000 / CLOCKS_PER_SEC;
//#define VERBOSE

typedef struct {
  // The LowMC instance.
  lowmc_t* lowmc;
} public_parameters_t;


void create_instance(public_parameters_t* pp, clock_t* timings, 
                            int m, int n, int r, int k);

void destroy_instance(public_parameters_t* pp);

void init_view(lowmc_t* lowmc, view_t* views[NUM_ROUNDS]);

#endif

