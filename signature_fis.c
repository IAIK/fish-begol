#include "signature_fis.h"
#include "lowmc.h"
#include "hashing_util.h"
#include "mpc.h"

#include <openssl/rand.h>

void fis_create_key(public_parameters_t* pp, fis_private_key_t* private_key,
                           fis_public_key_t* public_key, clock_t* timings) {
  clock_t beginKeygen      = clock();
  private_key->k           = lowmc_keygen(pp->lowmc);
  timings[1]               = (clock() - beginKeygen) * TIMING_SCALE;
#ifdef VERBOSE
  printf("LowMC key generation          %6lu\n", timings[1]);
#endif
  
  clock_t beginPubkey = clock();
  mzd_t *p            = mzd_init(1, pp->lowmc->n);
  public_key->pk      = lowmc_call(pp->lowmc, private_key->k, p);
  mzd_free(p);
  timings[2]          = (clock() - beginPubkey) * TIMING_SCALE;
#ifdef VERBOSE
  printf("Public key computation        %6lu\n", timings[2]);
#endif
}

void fis_destroy_key(fis_private_key_t* private_key, fis_public_key_t* public_key) {
  lowmc_key_free(private_key->k);
  private_key->k = NULL;
 
  mzd_free(public_key->pk);
  public_key->pk = NULL;
}


proof_t* fis_prove(lowmc_t* lowmc, lowmc_key_t* lowmc_key, mzd_t* p, char *m, unsigned m_len, clock_t *timings) {
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
  printf("MPC randomess generation      %6lu\n", timings[3]);
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
  printf("MPC secret sharing            %6lu\n", timings[4]);
#endif

  clock_t beginLowmc = clock();
  mzd_t*** c_mpc     = (mzd_t***)malloc(NUM_ROUNDS * sizeof(mzd_t**));
#pragma omp parallel for
  for (unsigned i    = 0; i < NUM_ROUNDS; i++)
    c_mpc[i]         = mpc_lowmc_call(lowmc, lowmc_key, p, views[i], rvec[i]);
  timings[5] = (clock() - beginLowmc) * TIMING_SCALE;
#ifdef VERBOSE
  printf("MPC LowMC encryption          %6lu\n", timings[5]);
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
  printf("Hashing views                 %6lu\n", timings[6]);
#endif

  clock_t beginCh = clock();
  int ch[NUM_ROUNDS];
  H3(hashes, m, m_len, ch);
  timings[7] = (clock() - beginCh) * TIMING_SCALE;
#ifdef VERBOSE
  printf("Generating challenge          %6lu\n", timings[7]);
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

int fis_verify(lowmc_t* lowmc, mzd_t* p, mzd_t* c, proof_t* prf, char *m, unsigned m_len, clock_t *timings) {
#ifdef VERBOSE
  printf("Verify:\n");
#endif
  clock_t beginCh = clock();
  int ch[NUM_ROUNDS];
  H3(prf->hashes, m, m_len, ch);
  timings[8] = (clock() - beginCh) * TIMING_SCALE;
#ifdef VERBOSE
  printf("Recomputing challenge         %6lu\n", timings[8]);
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
  printf("Verifying hashes              %6lu\n", timings[9]);
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
  printf("Verifying output shares       %6lu\n", timings[10]);
#endif

  clock_t beginView       = clock();
  int output_share_status = 0;
  for (int i = 0; i < NUM_ROUNDS; i++)
    if (mzd_cmp(prf->y[i][ch[i]], prf->views[i][lowmc->r + 1].s[0]) ||
        mzd_cmp(prf->y[i][(ch[i] + 1) % 3], prf->views[i][lowmc->r + 1].s[1]))
      output_share_status = -1;
  timings[11] = (clock() - beginView) * TIMING_SCALE;
#ifdef VERBOSE
  printf("Reconstructing output views   %6lu\n", timings[11]);
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
  printf("Verifying views               %6lu\n", timings[12]);
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
