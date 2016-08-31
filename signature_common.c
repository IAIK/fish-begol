#include "signature_common.h"
#include "lowmc_pars.h"

void create_instance(public_parameters_t* pp, clock_t* timings, 
                            int m, int n, int r, int k) {
#ifdef VERBOSE
  printf("Setup:\n");
#endif

  clock_t beginSetup = clock();
  pp->lowmc          = lowmc_init(m, n, r, k);
  timings[0]         = (clock() - beginSetup) * TIMING_SCALE;
#ifdef VERBOSE
  printf("LowMC setup                   %6lu\n", timings[0]);
#endif

 
}

void destroy_instance(public_parameters_t* pp) {
  lowmc_free(pp->lowmc);
  pp->lowmc = NULL;
}

proof_t* create_proof(proof_t* proof, lowmc_t* lowmc,
                      unsigned char hashes[NUM_ROUNDS][3][SHA256_DIGEST_LENGTH],
                      int ch[NUM_ROUNDS], unsigned char r[NUM_ROUNDS][3][4],
                      unsigned char keys[NUM_ROUNDS][3][16], mzd_t*** c_mpc,
                      view_t* views[NUM_ROUNDS]) {
  proof->views   = (view_t**)malloc(NUM_ROUNDS * sizeof(view_t*));

  proof->r    = (unsigned char***)malloc(NUM_ROUNDS * sizeof(unsigned char**));
  proof->keys = (unsigned char***)malloc(NUM_ROUNDS * sizeof(unsigned char**));
  memcpy(proof->hashes, hashes, NUM_ROUNDS * 3 * SHA256_DIGEST_LENGTH * sizeof(char));

#pragma omp parallel for
  for (unsigned int i = 0; i < NUM_ROUNDS; i++) {
    unsigned int a = ch[i];
    unsigned int b = (a + 1) % 3;
    unsigned int c = (a + 2) % 3;

    proof->r[i]    = (unsigned char**)malloc(2 * sizeof(unsigned char*));
    proof->r[i][0] = (unsigned char*)malloc(4 * sizeof(unsigned char));
    proof->r[i][1] = (unsigned char*)malloc(4 * sizeof(unsigned char));
    memcpy(proof->r[i][0], r[i][a], 4 * sizeof(char));
    memcpy(proof->r[i][1], r[i][b], 4 * sizeof(char));

    proof->keys[i]    = (unsigned char**)malloc(2 * sizeof(unsigned char*));
    proof->keys[i][0] = (unsigned char*)malloc(16 * sizeof(unsigned char));
    proof->keys[i][1] = (unsigned char*)malloc(16 * sizeof(unsigned char));
    memcpy(proof->keys[i][0], keys[i][a], 16 * sizeof(char));
    memcpy(proof->keys[i][1], keys[i][b], 16 * sizeof(char));

    proof->views[i] = (view_t*)malloc((2 + lowmc->r) * sizeof(view_t));
    for (unsigned j = 0; j < 2 + lowmc->r; j++) {
      proof->views[i][j].s    = (mzd_t**)malloc(2 * sizeof(mzd_t*));
      proof->views[i][j].s[0] = views[i][j].s[a];
      proof->views[i][j].s[1] = views[i][j].s[b];
      mzd_free(views[i][j].s[c]);
    }
  }
  proof->y = c_mpc;

  return proof;
}

void init_view(lowmc_t* lowmc, view_t* views[NUM_ROUNDS]) {
  const unsigned int size = 2 + lowmc->r;

#pragma omp parallel for
  for (unsigned int i = 0; i < NUM_ROUNDS; i++) {
    views[i] = calloc(size, sizeof(view_t*));

    views[i][0].s = calloc(3, sizeof(mzd_t*));
    for (unsigned m = 0; m < 3; m++) {
      views[i][0].s[m] = mzd_init(1, lowmc->k);
    }

    for (unsigned n = 1; n < size; n++) {
      views[i][n].s = (mzd_t**)malloc(3 * sizeof(mzd_t*));
      for (unsigned m = 0; m < 3; m++) {
        views[i][n].s[m] = mzd_init(1, lowmc->n);
      }
    }
  }
}
