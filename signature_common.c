#include "signature_common.h"
#include "lowmc_pars.h"

void create_instance(public_parameters_t* pp, clock_t* timings, 
                            int m, int n, int r, int k) {
#ifdef VERBOSE
  printf("Setup:\n");
#endif

  clock_t beginSetup = clock();
  pp->lowmc    = lowmc_init(m, n, r, k);
  timings[0]         = (clock() - beginSetup) * TIMING_SCALE;
#ifdef VERBOSE
  printf("LowMC setup                   %6lu\n", timings[0]);
#endif
}

void destroy_instance(public_parameters_t* pp) {
  lowmc_free(pp->lowmc);
  pp->lowmc = NULL;
}

void init_view(mpc_lowmc_t* mpc_lowmc, view_t* views[NUM_ROUNDS]) {
  const unsigned int size = 2 + mpc_lowmc->r;

#pragma omp parallel for
  for (unsigned int i = 0; i < NUM_ROUNDS; i++) {
    views[i] = calloc(size, sizeof(view_t*));

    views[i][0].s = calloc(3, sizeof(mzd_t*));
    for (unsigned m = 0; m < 3; m++) {
      views[i][0].s[m] = mzd_init(1, mpc_lowmc->k);
    }

    for (unsigned n = 1; n < size; n++) {
      views[i][n].s = (mzd_t**)malloc(3 * sizeof(mzd_t*));
      for (unsigned m = 0; m < 3; m++) {
        views[i][n].s[m] = mzd_init(1, mpc_lowmc->n);
      }
    }
  }
}
