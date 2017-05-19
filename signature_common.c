#include "signature_common.h"
#include "lowmc_pars.h"
#include "timing.h"

bool create_instance(public_parameters_t* pp, int m, int n, int r, int k) {
  TIME_FUNCTION;

  START_TIMING;
  pp->lowmc = lowmc_init(m, n, r, k);
  END_TIMING(timing_and_size->gen.lowmc_init);

  return pp->lowmc != NULL;
}

void destroy_instance(public_parameters_t* pp) {
  lowmc_free(pp->lowmc);
  pp->lowmc = NULL;
}

void init_view(mpc_lowmc_t const* mpc_lowmc, view_t* views[NUM_ROUNDS]) {
  const unsigned int view_count = 2 + mpc_lowmc->r;

  unsigned char* buffer = malloc((view_count * NUM_ROUNDS) * (sizeof(view_t)));

  for (unsigned int i = 0; i < NUM_ROUNDS; i++) {
    views[i] = (view_t*)buffer;
    buffer += view_count * sizeof(view_t);

    for (unsigned m = 0; m < SC_PROOF; ++m) {
      views[i][0].s[m] = mzd_local_init_ex(1, mpc_lowmc->k, false);
    }

    for (unsigned n = 1; n < view_count; n++) {
      for (unsigned m = 0; m < SC_PROOF; m++) {
        views[i][n].s[m] = mzd_local_init(1, mpc_lowmc->n);
      }
    }
  }
}

void free_view(mpc_lowmc_t const* mpc_lowmc, view_t* views[NUM_ROUNDS]) {
  (void)mpc_lowmc;
  free(views[0]);
}
