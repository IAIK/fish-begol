#ifndef SIGNATURE_COMMON_H
#define SIGNATURE_COMMON_H

#include <time.h>

#include "lowmc_pars.h"
#include "mpc_lowmc.h"

#define TIMING_SCALE 1000000 / CLOCKS_PER_SEC;
#define VERBOSE

typedef struct {
  // The LowMC instance.
  lowmc_t* lowmc;
} public_parameters_t;

void create_instance(public_parameters_t* pp, clock_t* timings, 
                            int m, int n, int r, int k);

void destroy_instance(public_parameters_t* pp);

proof_t* create_proof(proof_t* proof, lowmc_t* lowmc,
                      unsigned char hashes[NUM_ROUNDS][3][SHA256_DIGEST_LENGTH],
                      int ch[NUM_ROUNDS], unsigned char r[NUM_ROUNDS][3][4],
                      unsigned char keys[NUM_ROUNDS][3][16], mzd_t*** c_mpc,
                      view_t* views[NUM_ROUNDS]);

void init_view(lowmc_t* lowmc, view_t* views[NUM_ROUNDS]);

#endif

