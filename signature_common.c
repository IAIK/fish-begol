/*
 * fish-begol - Implementation of the Fish and Begol signature schemes
 * Copyright (C) 2016 Graz University of Technology
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

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
