#include "hashing_util.h"
#include "lowmc.h"
#include "lowmc_pars.h"
#include "mpc.h"
#include "mpc_lowmc.h"
#include "mpc_test.h"
#include "multithreading.h"
#include "mzd_additional.h"
#include "randomness.h"

#include <inttypes.h>
#include <openssl/rand.h>
#include <time.h>

#define TIMING_ITERATIONS 1
#define TIMING_SCALE 1000 / CLOCKS_PER_SEC;
#define VERBOSE

typedef struct {
  // The LowMC instance.
  lowmc_t* lowmc;
} public_parameters_t;

typedef struct {
  lowmc_key_t* k;
  lowmc_key_t* s;
} private_key_t;

typedef struct {
  // pk = E_k(s)
  mzd_t* pk;
} public_key_t;

static void create_instance(public_parameters_t* pp, private_key_t* private_key,
                            public_key_t* public_key, clock_t* timings, 
                            int m, int n, int r, int k) {
#ifdef VERBOSE
  printf("Setup:\n");
#endif

  clock_t beginSetup = clock();
  lowmc_t* lowmc     = lowmc_init(m, n, r, k);
  timings[0] = (clock() - beginSetup) * TIMING_SCALE;
#ifdef VERBOSE
  printf("LowMC setup                   %4lu\n", timings[0]);
#endif

  clock_t beginKeygen      = clock();
  lowmc_key_t* lowmc_key_k = lowmc_keygen(lowmc);
  lowmc_key_t* lowmc_key_s = lowmc_keygen(lowmc);
  timings[1]               = (clock() - beginKeygen) * TIMING_SCALE;
#ifdef VERBOSE
  printf("LowMC key generation          %4lu\n", timings[1]);
#endif

  pp->lowmc      = lowmc;
  private_key->k = lowmc_key_k;
  private_key->s = lowmc_key_s;

  clock_t beginPubkey = clock();
  public_key->pk      = lowmc_call(lowmc, lowmc_key_k, lowmc_key_s->shared[0]);
  timings[2] = (clock() - beginPubkey) * TIMING_SCALE;
#ifdef VERBOSE
  printf("Public key computation        %4lu\n", timings[2]);
#endif
}

static void destroy_instance(public_parameters_t* pp, private_key_t* private_key,
                             public_key_t* public_key) {
  lowmc_free(pp->lowmc);
  pp->lowmc = NULL;

  lowmc_key_free(private_key->k);
  lowmc_key_free(private_key->s);
  private_key->k = NULL;
  private_key->s = NULL;

  mzd_free(public_key->pk);
  public_key->pk = NULL;
}

proof_t* fis_prove(lowmc_t* lowmc, lowmc_key_t* lowmc_key, mzd_t* p, clock_t *timings) {
#ifdef VERBOSE
  printf("Prove:\n");
#endif
  unsigned char r[NUM_ROUNDS][3][4];
  unsigned char keys[NUM_ROUNDS][3][16];

  // Generating keys
  clock_t beginRand = clock();
  if (RAND_bytes((unsigned char*)keys, sizeof(keys)) != 1) {
#ifdef VERBOSE
    printf("RAND_bytes failed crypto, aborting\n");
#endif
    return 0;
  }

  if (RAND_bytes((unsigned char*)r, sizeof(r)) != 1) {
#ifdef VERBOSE
    printf("RAND_bytes failed crypto, aborting\n");
#endif
    return 0;
  }

  mzd_t** rvec[NUM_ROUNDS][3];
#pragma omp parallel for
  for (unsigned i = 0; i < NUM_ROUNDS; i++) {
    rvec[i][0] = mzd_init_random_vectors_from_seed(keys[i][0], lowmc->n, lowmc->r);
    rvec[i][1] = mzd_init_random_vectors_from_seed(keys[i][1], lowmc->n, lowmc->r);
    rvec[i][2] = mzd_init_random_vectors_from_seed(keys[i][2], lowmc->n, lowmc->r);
  }
  timings[3] = (clock() - beginRand) * TIMING_SCALE;
#ifdef VERBOSE
  printf("MPC randomess generation      %4lu\n", timings[3]);
#endif

  clock_t beginShare = clock();
  view_t views[NUM_ROUNDS][2 + lowmc->r];
#pragma omp parallel for
  for (unsigned i = 0; i < NUM_ROUNDS; i++) {
    views[i][0].s = (mzd_t**)malloc(3 * sizeof(mzd_t*));
    for (unsigned m    = 0; m < 3; m++)
      views[i][0].s[m] = mzd_init(1, lowmc->k);
    for (unsigned n = 1; n < 2 + lowmc->r; n++) {
      views[i][n].s = (mzd_t**)malloc(3 * sizeof(mzd_t*));
      for (unsigned m    = 0; m < 3; m++)
        views[i][n].s[m] = mzd_init(1, lowmc->n);
    }
  }
  lowmc_secret_share(lowmc, lowmc_key);
  timings[4] = (clock() - beginShare) * TIMING_SCALE;
  
#ifdef VERBOSE
  printf("MPC secret sharing            %4lu\n", timings[4]);
#endif

  clock_t beginLowmc = clock();
  mzd_t*** c_mpc     = (mzd_t***)malloc(NUM_ROUNDS * sizeof(mzd_t**));
#pragma omp parallel for
  for (unsigned i    = 0; i < NUM_ROUNDS; i++)
    c_mpc[i]         = mpc_lowmc_call(lowmc, lowmc_key, p, views[i], rvec[i]);
  timings[5] = (clock() - beginLowmc) * TIMING_SCALE;
#ifdef VERBOSE
  printf("MPC LowMC encryption          %4lu\n", timings[5]);
#endif

  clock_t beginHash = clock();
  unsigned char hashes[NUM_ROUNDS][3][SHA256_DIGEST_LENGTH];
#pragma omp parallel for
  for (unsigned i = 0; i < NUM_ROUNDS; i++) {
    H(keys[i][0], c_mpc[i], views[i], 0, 2 + lowmc->r, r[i][0], hashes[i][0]);
    H(keys[i][1], c_mpc[i], views[i], 1, 2 + lowmc->r, r[i][1], hashes[i][1]);
    H(keys[i][2], c_mpc[i], views[i], 2, 2 + lowmc->r, r[i][2], hashes[i][2]);
  }
  timings[6] = (clock() - beginHash) * TIMING_SCALE;
#ifdef VERBOSE
  printf("Hashing views                 %4lu\n", timings[6]);
#endif

  clock_t beginCh = clock();
  int ch[NUM_ROUNDS];
  H3(hashes, ch);
  timings[7] = (clock() - beginCh) * TIMING_SCALE;
#ifdef VERBOSE
  printf("Generating challenge          %4lu\n", timings[7]);
#endif

  proof_t* proof = (proof_t*)malloc(sizeof(proof_t));
  proof->views   = (view_t**)malloc(NUM_ROUNDS * sizeof(view_t*));

  proof->r    = (unsigned char***)malloc(NUM_ROUNDS * sizeof(unsigned char**));
  proof->keys = (unsigned char***)malloc(NUM_ROUNDS * sizeof(unsigned char**));
  memcpy(proof->hashes, hashes, NUM_ROUNDS * 3 * SHA256_DIGEST_LENGTH * sizeof(char));

#pragma omp parallel for
  for (unsigned i = 0; i < NUM_ROUNDS; i++) {
    int a = ch[i];
    int b = (a + 1) % 3;
    int c = (a + 2) % 3;

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

#pragma omp parallel for
  for (unsigned j = 0; j < NUM_ROUNDS; j++) {
    for (unsigned i = 0; i < 3; i++)
      mpc_free(rvec[j][i], lowmc->r);
    for (unsigned i = 0; i < lowmc->r + 2; i++) {
      free(views[j][i].s);
    }
  }

#ifdef VERBOSE
  printf("\n");
#endif
  return proof;
}

int fis_verify(lowmc_t* lowmc, mzd_t* p, mzd_t* c, proof_t* prf, clock_t *timings) {
#ifdef VERBOSE
  printf("Verify:\n");
#endif
  clock_t beginCh = clock();
  int ch[NUM_ROUNDS];
  H3(prf->hashes, ch);
  timings[8] = (clock() - beginCh) * TIMING_SCALE;
#ifdef VERBOSE
  printf("Recomputing challenge         %4lu\n", timings[8]);
#endif

  clock_t beginHash = clock();
  unsigned char hash[SHA256_DIGEST_LENGTH];
  int hash_status = 0;
#pragma omp parallel for
  for (unsigned i = 0; i < NUM_ROUNDS; i++) {
    H(prf->keys[i][0], prf->y[i], prf->views[i], 0, 2 + lowmc->r, prf->r[i][0], hash);
    if (0 != memcmp(hash, prf->hashes[i][ch[i]], SHA256_DIGEST_LENGTH)) {
      hash_status = -1;
    }
    H(prf->keys[i][1], prf->y[i], prf->views[i], 1, 2 + lowmc->r, prf->r[i][1], hash);
    if (0 != memcmp(hash, prf->hashes[i][(ch[i] + 1) % 3], SHA256_DIGEST_LENGTH)) {
      hash_status = -1;
    }
  }
  timings[9] = (clock() - beginHash) * TIMING_SCALE;
#ifdef VERBOSE
  printf("Verifying hashes              %4lu\n", timings[9]);
#endif

  clock_t beginRec       = clock();
  int reconstruct_status = 0;
  for (int i = 0; i < NUM_ROUNDS; i++) {
    mzd_t* c_mpcr = mpc_reconstruct_from_share(prf->y[0]);
    if (mzd_cmp(c, c_mpcr) != 0)
      reconstruct_status = -1;
    mzd_free(c_mpcr);
  }
  timings[10] = (clock() - beginRec) * TIMING_SCALE;
#ifdef VERBOSE
  printf("Verifying output shares       %4lu\n", timings[10]);
#endif

  clock_t beginView       = clock();
  int output_share_status = 0;
  for (int i = 0; i < NUM_ROUNDS; i++)
    if (mzd_cmp(prf->y[i][ch[i]], prf->views[i][lowmc->r + 1].s[0]) ||
        mzd_cmp(prf->y[i][(ch[i] + 1) % 3], prf->views[i][lowmc->r + 1].s[1]))
      output_share_status = -1;
  timings[11] = (clock() - beginView) * TIMING_SCALE;
#ifdef VERBOSE
  printf("Reconstructing output views   %4lu\n", timings[11]);
#endif

  clock_t beginViewVrfy = clock();
  mzd_t** rv[2];
  int view_verify_status = 0;
  for (int i = 0; i < NUM_ROUNDS; i++) {
    rv[0] = mzd_init_random_vectors_from_seed(prf->keys[i][0], lowmc->n, lowmc->r);
    rv[1] = mzd_init_random_vectors_from_seed(prf->keys[i][1], lowmc->n, lowmc->r);

    mzd_t* c_ch[2];
    c_ch[0] = mzd_init(1, lowmc->n);
    c_ch[1] = mzd_init(1, lowmc->n);
    mzd_copy(c_ch[0], prf->views[i][lowmc->r + 1].s[0]);
    mzd_copy(c_ch[1], prf->views[i][lowmc->r + 1].s[1]);

    if (mpc_lowmc_verify(lowmc, p, prf->views[i], rv, ch[i]) ||
        mzd_cmp(c_ch[0], prf->views[i][1 + lowmc->r].s[0]) ||
        mzd_cmp(c_ch[1], prf->views[i][1 + lowmc->r].s[1])) {
      view_verify_status = -1;
    }

    mzd_free(c_ch[0]);
    mzd_free(c_ch[1]);
    mpc_free(rv[0], lowmc->r);
    mpc_free(rv[1], lowmc->r);
  }
  timings[12] = (clock() - beginViewVrfy) * TIMING_SCALE;
#ifdef VERBOSE
  printf("Verifying views               %4lu\n", timings[12]);
  printf("\n");

  if (hash_status)
    printf("[FAIL] Commitments did not open correctly\n");
  else
    printf("[ OK ] Commitments open correctly\n");

  if (output_share_status)
    printf("[FAIL] Output shares do not match\n");
  else
    printf("[ OK ] Output shares match.\n");

  if (reconstruct_status)
    printf("[FAIL] MPC ciphertext does not match reference implementation.\n");
  else
    printf("[ OK ] MPC ciphertext matches.\n");

  if (view_verify_status)
    printf("[FAIL] Proof does not match reconstructed views.\n");
  else
    printf("[ OK ] Proof matches reconstructed views.\n");
#endif

  return hash_status || output_share_status || reconstruct_status || view_verify_status;
}

typedef struct {
  proof_t proof_s;
  proof_t proof_p;
  mzd_shared_t shared_s[NUM_ROUNDS];
} signature_t;

static proof_t* create_proof(proof_t* proof, lowmc_t* lowmc,
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

static void free_signature(public_parameters_t* pp, signature_t* signature) {
  clear_proof(pp->lowmc, &signature->proof_p);
  clear_proof(pp->lowmc, &signature->proof_s);
  for (unsigned int i = 0; i < NUM_ROUNDS; ++i) {
    mzd_shared_clear(&signature->shared_s[i]);
  }

  free(signature);
}

static void init_view(lowmc_t* lowmc, view_t* views[NUM_ROUNDS]) {
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

static signature_t* bg_prove(public_parameters_t* pp, private_key_t* private_key, mzd_t* p, clock_t *timings) {
  lowmc_t* lowmc         = pp->lowmc;
#ifdef VERBOSE
  printf("Prove:\n");
#endif
  unsigned char r_p[NUM_ROUNDS][3][4];
  unsigned char keys_p[NUM_ROUNDS][3][16];
  unsigned char r_s[NUM_ROUNDS][3][4];
  unsigned char keys_s[NUM_ROUNDS][3][16];

  // Generating keys
  clock_t beginRand = clock();
  if (RAND_bytes((unsigned char*)keys_p, sizeof(keys_p)) != 1 ||
      RAND_bytes((unsigned char*)r_p, sizeof(r_p)) != 1 ||
      RAND_bytes((unsigned char*)keys_s, sizeof(keys_s)) != 1 ||
      RAND_bytes((unsigned char*)r_s, sizeof(r_s)) != 1) {
#ifdef VERBOSE
    printf("RAND_bytes failed crypto, aborting\n");
#endif
    return NULL;
  }

  mzd_t** rvec_p[NUM_ROUNDS][3];
  mzd_t** rvec_s[NUM_ROUNDS][3];
#pragma omp parallel for
  for (unsigned i = 0; i < NUM_ROUNDS; ++i) {
    for (unsigned int j = 0; j < 3; ++j) {
      rvec_p[i][j] = mzd_init_random_vectors_from_seed(keys_p[i][j], lowmc->n, lowmc->r);
      rvec_s[i][j] = mzd_init_random_vectors_from_seed(keys_s[i][j], lowmc->n, lowmc->r);
    }
  }
  timings[3] = (clock() - beginRand) * TIMING_SCALE;
#ifdef VERBOSE
  printf("MPC randomess generation      %4lu\n", timings[3]);
#endif

  clock_t beginShare = clock();
  view_t* views_p[NUM_ROUNDS];
  view_t* views_s[NUM_ROUNDS];

  init_view(lowmc, views_p);
  init_view(lowmc, views_s);

  lowmc_key_t lowmc_key_k = {0, NULL};
  mzd_shared_init(&lowmc_key_k, private_key->k->shared[0]);
  lowmc_secret_share(lowmc, &lowmc_key_k);

  signature_t* signature = calloc(1, sizeof(signature_t));
  #pragma omp parallel for
  for (unsigned i = 0; i < NUM_ROUNDS; ++i) {
    mzd_shared_init(&signature->shared_s[i], private_key->s->shared[0]);
    lowmc_secret_share(lowmc, &signature->shared_s[i]);
  }

  timings[4] = (clock() - beginShare) * TIMING_SCALE;
#ifdef VERBOSE
  printf("MPC secret sharing            %4lu\n", timings[4]);
#endif

  clock_t beginLowmc = clock();
  mzd_t*** c_mpc_p   = calloc(NUM_ROUNDS, sizeof(mzd_t**));
  mzd_t*** c_mpc_s   = calloc(NUM_ROUNDS, sizeof(mzd_t**));
#pragma omp parallel for
  for (unsigned i = 0; i < NUM_ROUNDS; ++i) {
    lowmc_key_t lowmc_key_s = {0, NULL};
    mzd_shared_copy(&lowmc_key_s, &signature->shared_s[i]);

    c_mpc_p[i] = mpc_lowmc_call(lowmc, &lowmc_key_s, p, views_p[i], rvec_p[i]);
    c_mpc_s[i] = mpc_lowmc_call_shared_p(lowmc, &lowmc_key_k, &lowmc_key_s, views_s[i], rvec_s[i]);

    mzd_shared_clear(&lowmc_key_s);
  }
  timings[5] = (clock() - beginLowmc) * TIMING_SCALE;
#ifdef VERBOSE
  printf("MPC LowMC encryption          %4lu\n", timings[5]);
#endif

  mzd_shared_clear(&lowmc_key_k);

  clock_t beginHash = clock();
  unsigned char hashes_p[NUM_ROUNDS][3][SHA256_DIGEST_LENGTH];
  unsigned char hashes_s[NUM_ROUNDS][3][SHA256_DIGEST_LENGTH];
#pragma omp parallel for
  for (unsigned i = 0; i < NUM_ROUNDS; ++i) {
    for (unsigned int j = 0; j < 3; ++j) {
      H(keys_p[i][j], c_mpc_p[i], views_p[i], j, 2 + lowmc->r, r_p[i][j], hashes_p[i][j]);
      H(keys_s[i][j], c_mpc_s[i], views_s[i], j, 2 + lowmc->r, r_s[i][j], hashes_s[i][j]);
    }
  }
  timings[6] = (clock() - beginHash) * TIMING_SCALE;
#ifdef VERBOSE
  printf("Hashing views                 %4lu\n", timings[6]);
#endif

  clock_t beginCh = clock();
  int ch[NUM_ROUNDS];
  H4(hashes_p, hashes_s, ch);
  timings[7] = (clock() - beginCh) * TIMING_SCALE;
#ifdef VERBOSE
  printf("Generating challenge          %4lu\n", timings[7]);
#endif

  create_proof(&signature->proof_p, lowmc, hashes_p, ch, r_p, keys_p, c_mpc_p, views_p);
  create_proof(&signature->proof_s, lowmc, hashes_s, ch, r_s, keys_s, c_mpc_s, views_s);

  for (unsigned int i = 0; i < NUM_ROUNDS; i++) {
    unsigned int a = ch[i];
    unsigned int b = (a + 1) % 3;
    unsigned int c = (a + 2) % 3;

    mzd_t* shared_p0 = signature->shared_s[i].shared[a];
    mzd_t* shared_p1 = signature->shared_s[i].shared[b];
    mzd_free(signature->shared_s[i].shared[c]);

    signature->shared_s[i].shared[0]   = shared_p0;
    signature->shared_s[i].shared[1]   = shared_p1;
    signature->shared_s[i].shared[2]   = NULL;
    signature->shared_s[i].share_count = 2;
  }

#pragma omp parallel for
  for (unsigned j = 0; j < NUM_ROUNDS; ++j) {
    for (unsigned i = 0; i < 3; ++i) {
      mpc_free(rvec_p[j][i], lowmc->r);
      mpc_free(rvec_s[j][i], lowmc->r);
    }
    for (unsigned i = 0; i < lowmc->r + 2; ++i) {
      free(views_p[j][i].s);
      free(views_s[j][i].s);
    }
    free(views_p[j]);
    free(views_s[j]);
  }

#ifdef VERBOSE
  printf("\n");
#endif
  return signature;
}

static int verify_hashes(lowmc_t* lowmc, proof_t* proof, int ch[NUM_ROUNDS]) {
  int hash_status = 0;
#pragma omp parallel for reduction(| : hash_status)
  for (unsigned i = 0; i < NUM_ROUNDS; ++i) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    H(proof->keys[i][0], proof->y[i], proof->views[i], 0, 2 + lowmc->r, proof->r[i][0], hash);
    if (0 != memcmp(hash, proof->hashes[i][ch[i]], SHA256_DIGEST_LENGTH)) {
      hash_status |= -1;
    }
    H(proof->keys[i][1], proof->y[i], proof->views[i], 1, 2 + lowmc->r, proof->r[i][1], hash);
    if (0 != memcmp(hash, proof->hashes[i][(ch[i] + 1) % 3], SHA256_DIGEST_LENGTH)) {
      hash_status |= -1;
    }
  }

  return hash_status;
}

typedef int (*verify_ptr)(lowmc_t* lowmc, mzd_t* p, mzd_shared_t* shared_p, view_t* views,
                          mzd_t** rv[2], int ch);

static int verify_with_p(lowmc_t* lowmc, mzd_t* p, mzd_shared_t* shared_p, view_t* views,
                         mzd_t** rv[2], int ch) {
  (void)shared_p;
  return mpc_lowmc_verify(lowmc, p, views, rv, ch);
}

static int verify_with_shared_p(lowmc_t* lowmc, mzd_t* p, mzd_shared_t* shared_p, view_t* views,
                                mzd_t** rv[2], int ch) {
  (void)p;
  return mpc_lowmc_verify_shared_p(lowmc, shared_p, views, rv, ch);
}

static int verify_views(lowmc_t* lowmc, mzd_t* p, mzd_shared_t shared_p[NUM_ROUNDS], proof_t* proof,
                        verify_ptr verify, int ch[NUM_ROUNDS]) {
  int view_verify_status = 0;

#pragma omp parallel for reduction(| : view_verify_status)
  for (unsigned int i = 0; i < NUM_ROUNDS; i++) {
    mzd_t** rv[2];
    rv[0] = mzd_init_random_vectors_from_seed(proof->keys[i][0], lowmc->n, lowmc->r);
    rv[1] = mzd_init_random_vectors_from_seed(proof->keys[i][1], lowmc->n, lowmc->r);

    mzd_t* c_ch[2];
    c_ch[0] = mzd_init(1, lowmc->n);
    c_ch[1] = mzd_init(1, lowmc->n);
    mzd_copy(c_ch[0], proof->views[i][lowmc->r + 1].s[0]);
    mzd_copy(c_ch[1], proof->views[i][lowmc->r + 1].s[1]);

    if (verify(lowmc, p, shared_p != NULL ? &shared_p[i] : NULL, proof->views[i], rv, ch[i]) ||
        mzd_cmp(c_ch[0], proof->views[i][1 + lowmc->r].s[0]) ||
        mzd_cmp(c_ch[1], proof->views[i][1 + lowmc->r].s[1])) {
      view_verify_status |= -1;
    }

    mzd_free(c_ch[0]);
    mzd_free(c_ch[1]);
    mpc_free(rv[0], lowmc->r);
    mpc_free(rv[1], lowmc->r);
  }

  return view_verify_status;
}

static int bg_verify(public_parameters_t* pp, public_key_t* pk, mzd_t* p, mzd_t* c,
                  signature_t* signature, clock_t *timings) {
  lowmc_t* lowmc   = pp->lowmc;
  proof_t* proof_p = &signature->proof_p;
  proof_t* proof_s = &signature->proof_s;
#ifdef VERBOSE
  printf("Verify:\n");
#endif
  clock_t beginCh = clock();
  int ch[NUM_ROUNDS];
  H4(proof_p->hashes, proof_s->hashes, ch);
  timings[8] = (clock() - beginCh) * TIMING_SCALE;
#ifdef VERBOSE
  printf("Recomputing challenge         %4lu\n", timings[8]);
#endif

  clock_t beginHash = clock();
  int hash_status   = 0;
  if (0 != verify_hashes(lowmc, proof_p, ch)) {
    hash_status = -1;
  }
  if (0 != verify_hashes(lowmc, proof_s, ch)) {
    hash_status = -1;
  }

  timings[9] = (clock() - beginHash) * TIMING_SCALE;
#ifdef VERBOSE
  printf("Verifying hashes              %4lu\n", timings[9]);
#endif

  clock_t beginRec       = clock();
  int reconstruct_status = 0;
  for (unsigned int i = 0; i < NUM_ROUNDS; i++) {
    mzd_t* c_mpcr = mpc_reconstruct_from_share(proof_p->y[i]);
    if (mzd_cmp(c, c_mpcr) != 0)
      reconstruct_status = -1;
    mzd_free(c_mpcr);

    c_mpcr = mpc_reconstruct_from_share(proof_s->y[i]);
    if (mzd_cmp(pk->pk, c_mpcr) != 0)
      reconstruct_status = -1;
    mzd_free(c_mpcr);
  }
  timings[10] = (clock() - beginRec) * TIMING_SCALE;
#ifdef VERBOSE
  printf("Verifying output shares       %4lu\n", timings[10]);
#endif

  clock_t beginView       = clock();
  int output_share_status = 0;
#pragma omp parallel for reduction(| : output_share_status)
  for (unsigned int i = 0; i < NUM_ROUNDS; i++) {
    if (mzd_cmp(proof_p->y[i][ch[i]], proof_p->views[i][lowmc->r + 1].s[0]) ||
        mzd_cmp(proof_p->y[i][(ch[i] + 1) % 3], proof_p->views[i][lowmc->r + 1].s[1]))
      output_share_status |= -1;
    if (mzd_cmp(proof_s->y[i][ch[i]], proof_s->views[i][lowmc->r + 1].s[0]) ||
        mzd_cmp(proof_s->y[i][(ch[i] + 1) % 3], proof_s->views[i][lowmc->r + 1].s[1]))
      output_share_status |= -1;
  }
  timings[11] = (clock() - beginView) * TIMING_SCALE;
#ifdef VERBOSE
  printf("Reconstructing output views   %4lu\n", timings[11]);
#endif

  clock_t beginViewVrfy  = clock();
  int view_verify_status = 0;
  if (0 != verify_views(lowmc, p, signature->shared_s, proof_p, verify_with_p, ch)) {
    view_verify_status = -1;
  }
  if (0 != verify_views(lowmc, p, signature->shared_s, proof_s, verify_with_shared_p, ch)) {
    view_verify_status = -1;
  }
  timings[12] = (clock() - beginViewVrfy) * TIMING_SCALE;
#ifdef VERBOSE
  printf("Verifying views               %4lu\n", timings[12]);
  printf("\n");

  if (hash_status)
    printf("[FAIL] Commitments did not open correctly\n");
  else
    printf("[ OK ] Commitments open correctly\n");

  if (output_share_status)
    printf("[FAIL] Output shares do not match\n");
  else
    printf("[ OK ] Output shares match.\n");

  if (reconstruct_status)
    printf("[FAIL] MPC ciphertext does not match reference implementation.\n");
  else
    printf("[ OK ] MPC ciphertext matches.\n");

  if (view_verify_status)
    printf("[FAIL] Proof does not match reconstructed views.\n");
  else
    printf("[ OK ] Proof matches reconstructed views.\n");
#endif

  return hash_status || output_share_status || reconstruct_status || view_verify_status;
}

void print_timings(clock_t timings[TIMING_ITERATIONS][13]) {
  for(unsigned i = 0 ; i < TIMING_ITERATIONS ; i++) {
    for(unsigned j = 0 ; j < 13 ; j++) {
      printf("%lu", timings[i][j]);
      if(j < 12) printf(",");
    }
    printf("\n");
  } 
}

void parse_args(int params[4], int argc, char **argv) {
  if(argc != 5) {
    printf("Usage ./mpc_lowmc [Number of SBoxes] [Blocksize] [Rounds] [Keysize]\n"); 
    exit(-1);
  }
  params[0] = atoi(argv[1]);
  params[1] = atoi(argv[2]);
  params[2] = atoi(argv[3]);
  params[3] = atoi(argv[4]);
}

int main(int argc, char** argv) {
  init_EVP();
  openmp_thread_setup();
 
  int args[4];
  parse_args(args, argc, argv);

#ifdef VERBOSE
  printf("Fiat-Shamir Signature:\n\n");
#endif

  clock_t timings_fis[TIMING_ITERATIONS][13];  

  for (int i = 0; i != TIMING_ITERATIONS; ++i) {
    public_parameters_t pp;
    private_key_t private_key;
    public_key_t public_key;

    create_instance(&pp, &private_key, &public_key, timings_fis[i], args[0], args[1], args[2], args[3]);

    mzd_t* p = mzd_init_random_vector(args[1]);

#ifdef VERBOSE
    clock_t beginRef = clock();
#endif
    mzd_t* c         = lowmc_call(pp.lowmc, private_key.s, p);
#ifdef VERBOSE
    clock_t deltaRef = (clock() - beginRef) * TIMING_SCALE;
    printf("LowMC reference encryption    %4lu\n", deltaRef);
    printf("\n");
#endif

    lowmc_key_t key = {0, NULL};
    mzd_shared_copy(&key, private_key.s);

    proof_t* prf = fis_prove(pp.lowmc, &key, p, timings_fis[i]);
    fis_verify(pp.lowmc, p, c, prf, timings_fis[i]);

    free_proof(pp.lowmc, prf);
    mzd_shared_clear(&key);
    mzd_free(p);
    mzd_free(c);

    destroy_instance(&pp, &private_key, &public_key);
  }

#ifndef VERBOSE
  print_timings(timings_fis);
#endif

#ifdef VERBOSE
  printf("BG Signature:\n\n");
#endif
  
  clock_t timings_bg[TIMING_ITERATIONS][13];

  for (int i = 0; i != TIMING_ITERATIONS; ++i) {
    public_parameters_t pp;
    private_key_t private_key;
    public_key_t public_key;

    create_instance(&pp, &private_key, &public_key, timings_bg[i], args[0], args[1], args[2], args[3]);

    mzd_t* p = mzd_init_random_vector(args[1]);

#ifdef VERBOSE
    clock_t beginRef = clock();
#endif
    mzd_t* c         = lowmc_call(pp.lowmc, private_key.s, p);
#ifdef VERBOSE
    clock_t deltaRef = (clock() - beginRef) * TIMING_SCALE;
    printf("LowMC reference encryption    %4lu\n", deltaRef);
    printf("\n");
#endif

    signature_t* signature = bg_prove(&pp, &private_key, p, timings_bg[i]);
    bg_verify(&pp, &public_key, p, c, signature, timings_bg[i]);

    free_signature(&pp, signature);

    mzd_free(p);
    mzd_free(c);

    destroy_instance(&pp, &private_key, &public_key);
  }

#ifndef VERBOSE
  print_timings(timings_bg);
#endif

  openmp_thread_cleanup();
  cleanup_EVP();
  return 0;
}
