#include "signature_common.h"
#include "lowmc_pars.h"
#include "timing.h"

void create_instance(public_parameters_t* pp, int m, int n, int r, int k) {
  TIME_FUNCTION;

  START_TIMING;
  pp->lowmc = lowmc_init(m, n, r, k);
  END_TIMING(timing_and_size->gen.lowmc_init);
}

void destroy_instance(public_parameters_t* pp) {
  lowmc_free(pp->lowmc);
  pp->lowmc = NULL;
}

void init_view(mpc_lowmc_t const* mpc_lowmc, view_t* views[NUM_ROUNDS]) {
  const unsigned int view_count = 2 + mpc_lowmc->r;

  unsigned char* buffer = calloc(view_count * NUM_ROUNDS, sizeof(view_t*) + 3 * sizeof(mzd_t*));

  for (unsigned int i = 0; i < NUM_ROUNDS; i++) {
    views[i] = (view_t*) buffer;
    buffer += view_count * sizeof(view_t*);

    views[i][0].s = (mzd_t**) buffer;
    buffer += 3 * sizeof(mzd_t*);
    for (unsigned m = 0; m < 3; m++) {
      views[i][0].s[m] = mzd_local_init(1, mpc_lowmc->k);
    }

    for (unsigned n = 1; n < view_count; n++) {
      views[i][n].s = (mzd_t**) buffer;
      buffer += 3 * sizeof(mzd_t*);
      for (unsigned m = 0; m < 3; m++) {
        views[i][n].s[m] = mzd_local_init(1, mpc_lowmc->n);
      }
    }
  }
}

void free_view(mpc_lowmc_t const* mpc_lowmc, view_t* views[NUM_ROUNDS]) {
  free(views[0]);
}
