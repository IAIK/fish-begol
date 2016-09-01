#include "signature_bg.h" 
#include "lowmc.h"
#include "hashing_util.h"
#include "mpc.h"

#include <openssl/rand.h>

void bg_create_key(public_parameters_t* pp, bg_private_key_t* private_key,
                          bg_public_key_t* public_key, clock_t* timings) {
  clock_t beginKeygen      = clock();
  lowmc_key_t* lowmc_key_k = lowmc_keygen(pp->lowmc);
  lowmc_key_t* lowmc_key_s = lowmc_keygen(pp->lowmc);
  timings[1]               = (clock() - beginKeygen) * TIMING_SCALE;
#ifdef VERBOSE
  printf("LowMC key generation          %6lu\n", timings[1]);
#endif

  private_key->k = lowmc_key_k;
  private_key->s = lowmc_key_s;

  clock_t beginPubkey = clock();
  public_key->pk      = lowmc_call(pp->lowmc, lowmc_key_k, lowmc_key_s->shared[0]);
  timings[2]          = (clock() - beginPubkey) * TIMING_SCALE;
#ifdef VERBOSE
  printf("Public key computation        %6lu\n", timings[2]);
#endif
}

void bg_destroy_key(bg_private_key_t* private_key, bg_public_key_t* public_key) {
  lowmc_key_free(private_key->k);
  lowmc_key_free(private_key->s);
  private_key->k = NULL;
  private_key->s = NULL;

  mzd_free(public_key->pk);
  public_key->pk = NULL;
}

void bg_free_signature(public_parameters_t* pp, bg_signature_t* signature) {
  clear_proof(pp->lowmc, &signature->proof_p);
  clear_proof(pp->lowmc, &signature->proof_s);
  for (unsigned int i = 0; i < NUM_ROUNDS; ++i) {
    mzd_shared_clear(&signature->shared_s[i]);
  }

  free(signature);
}

bg_signature_t* bg_prove(public_parameters_t* pp, bg_private_key_t* private_key, mzd_t* p, clock_t *timings) {
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
  printf("MPC randomess generation      %6lu\n", timings[3]);
#endif

  clock_t beginShare = clock();
  view_t* views_p[NUM_ROUNDS];
  view_t* views_s[NUM_ROUNDS];

  init_view(lowmc, views_p);
  init_view(lowmc, views_s);

  lowmc_key_t lowmc_key_k = {0, NULL};
  mzd_shared_init(&lowmc_key_k, private_key->k->shared[0]);
  lowmc_secret_share(lowmc, &lowmc_key_k);

  bg_signature_t* signature = calloc(1, sizeof(bg_signature_t));
  #pragma omp parallel for
  for (unsigned i = 0; i < NUM_ROUNDS; ++i) {
    mzd_shared_init(&signature->shared_s[i], private_key->s->shared[0]);
    lowmc_secret_share(lowmc, &signature->shared_s[i]);
  }

  timings[4] = (clock() - beginShare) * TIMING_SCALE;
#ifdef VERBOSE
  printf("MPC secret sharing            %6lu\n", timings[4]);
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
  printf("MPC LowMC encryption          %6lu\n", timings[5]);
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
  printf("Hashing views                 %6lu\n", timings[6]);
#endif

  clock_t beginCh = clock();
  int ch[NUM_ROUNDS];
  bg_H3(hashes_p, hashes_s, ch);
  timings[7] = (clock() - beginCh) * TIMING_SCALE;
#ifdef VERBOSE
  printf("Generating challenge          %6lu\n", timings[7]);
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

int bg_verify(public_parameters_t* pp, bg_public_key_t* pk, mzd_t* p, mzd_t* c,
                  bg_signature_t* signature, clock_t *timings) {
  lowmc_t* lowmc   = pp->lowmc;
  proof_t* proof_p = &signature->proof_p;
  proof_t* proof_s = &signature->proof_s;
#ifdef VERBOSE
  printf("Verify:\n");
#endif
  clock_t beginCh = clock();
  int ch[NUM_ROUNDS];
  bg_H3(proof_p->hashes, proof_s->hashes, ch);
  timings[8] = (clock() - beginCh) * TIMING_SCALE;
#ifdef VERBOSE
  printf("Recomputing challenge         %6lu\n", timings[8]);
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
  printf("Verifying hashes              %6lu\n", timings[9]);
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
  printf("Verifying output shares       %6lu\n", timings[10]);
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
  printf("Reconstructing output views   %6lu\n", timings[11]);
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
