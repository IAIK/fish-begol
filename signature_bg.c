#include "signature_bg.h" 
#include "lowmc.h"
#include "hashing_util.h"
#include "mpc.h"
#include "io.h"
#include "randomness.h"
#include "timing.h"

unsigned bg_compute_sig_size(unsigned m, unsigned n, unsigned r, unsigned k) {
  unsigned first_view_size = k;
  unsigned full_view_size  = n;
  unsigned int_view_size   = 3 * m;
  unsigned views           = 2 * (r * int_view_size + first_view_size + 
                             full_view_size) + 3 * full_view_size;
  return (2 * NUM_ROUNDS * (8 * SHA256_DIGEST_LENGTH + 8 * 40 + views) + 
         full_view_size + ((NUM_ROUNDS + 3) / 4) + 7) / 8; 
}

unsigned char *bg_sig_to_char_array(public_parameters_t *pp, bg_signature_t *sig, unsigned *len) {
  unsigned len1 = 0;
  unsigned char* p1 = proof_to_char_array(pp->lowmc, &sig->proof_s, &len1, true);
  unsigned len2 = 0;
  unsigned char* p2 = proof_to_char_array(pp->lowmc, &sig->proof_p, &len2, false);
  unsigned char* c = mzd_to_char_array(sig->c, pp->lowmc->n / 8);

  *len = len1 + len2 + (pp->lowmc->n / 8);

  unsigned char *result = (unsigned char *)malloc(*len * sizeof(unsigned char));
  unsigned char *temp = result;
  memcpy(temp, p1, len1); temp += len1;
  memcpy(temp, p2, len2); temp += len2;
  memcpy(temp, c, pp->lowmc->n / 8);

  free(p1);
  free(p2);
  free(c);

  return result;
}

bg_signature_t *bg_sig_from_char_array(public_parameters_t *pp, unsigned char *data) {
  bg_signature_t *sig = (bg_signature_t*)malloc(sizeof(bg_signature_t));
  unsigned len = 0;
  proof_from_char_array(pp->lowmc, &sig->proof_s, data, &len, true); data += len;
  proof_from_char_array(pp->lowmc, &sig->proof_p, data, &len, false); data += len;
  sig->c = mzd_from_char_array(data, pp->lowmc->n / 8, pp->lowmc->n);

  return sig;
}

void bg_create_key(public_parameters_t* pp, bg_private_key_t* private_key,
                   bg_public_key_t* public_key) {
  TIME_FUNCTION;

  START_TIMING;
  lowmc_key_t* lowmc_key_k = lowmc_keygen(pp->lowmc);
  lowmc_key_t* lowmc_key_s = lowmc_keygen(pp->lowmc);

  private_key->k = lowmc_key_k;
  private_key->s = lowmc_key_s;
  END_TIMING(timing_and_size->gen.keygen);

  START_TIMING;
  public_key->pk = lowmc_call(pp->lowmc, lowmc_key_k, lowmc_key_s);

  END_TIMING(timing_and_size->gen.pubkey);
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

  free(signature);
}

static bg_signature_t* bg_prove(public_parameters_t* pp, bg_private_key_t* private_key, mzd_t* p) {
  TIME_FUNCTION;
  lowmc_t* lowmc                = pp->lowmc;
  const unsigned int view_count = lowmc->r + 2;

  unsigned char r_p[NUM_ROUNDS][3][4];
  unsigned char keys_p[NUM_ROUNDS][3][16];
  unsigned char r_s[NUM_ROUNDS][3][4];
  unsigned char keys_s[NUM_ROUNDS][3][16];
  unsigned char secret_sharing_key[16];

  // Generating keys
  START_TIMING;
  if (rand_bytes((unsigned char*)keys_p, sizeof(keys_p)) != 1 ||
      rand_bytes((unsigned char*)r_p, sizeof(r_p)) != 1 ||
      rand_bytes((unsigned char*)keys_s, sizeof(keys_s)) != 1 ||
      rand_bytes((unsigned char*)r_s, sizeof(r_s)) != 1 ||
      rand_bytes(secret_sharing_key, sizeof(secret_sharing_key)) != 1) {
#ifdef VERBOSE
    printf("rand_bytes failed crypto, aborting\n");
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
  END_TIMING(timing_and_size->sign.rand);

  START_TIMING;
  bg_signature_t* signature = calloc(1, sizeof(bg_signature_t));

  view_t* views_p[NUM_ROUNDS];
  view_t* views_s[NUM_ROUNDS];

  init_view(lowmc, views_p);
  init_view(lowmc, views_s);

  mpc_lowmc_key_t lowmc_key_k[NUM_ROUNDS] = {{0, NULL}};
  mpc_lowmc_key_t lowmc_key_s[NUM_ROUNDS] = {{0, NULL}};

  aes_prng_t* aes_prng = aes_prng_init(secret_sharing_key);
  #pragma omp parallel for
  for (unsigned i = 0; i < NUM_ROUNDS; ++i) {
    mzd_shared_init(&lowmc_key_s[i], private_key->s);
    mzd_shared_share_prng(&lowmc_key_s[i], aes_prng);

    mzd_shared_init(&lowmc_key_k[i], private_key->k);
    mzd_shared_share_prng(&lowmc_key_k[i], aes_prng);
  }
  aes_prng_free(aes_prng);
  END_TIMING(timing_and_size->sign.secret_sharing);

  START_TIMING;
  mzd_t*** c_mpc_p = calloc(NUM_ROUNDS, sizeof(mzd_t**));
  mzd_t*** c_mpc_s = calloc(NUM_ROUNDS, sizeof(mzd_t**));
#pragma omp parallel for
  for (unsigned i = 0; i < NUM_ROUNDS; ++i) {
    c_mpc_p[i] = mpc_lowmc_call(lowmc, &lowmc_key_s[i], p, views_p[i], rvec_p[i]);
    c_mpc_s[i] =
        mpc_lowmc_call_shared_p(lowmc, &lowmc_key_k[i], &lowmc_key_s[i], views_s[i], rvec_s[i]);
  }
  signature->c = mpc_reconstruct_from_share(c_mpc_p[0]);
  END_TIMING(timing_and_size->sign.lowmc_enc);

  START_TIMING;
  unsigned char hashes_p[NUM_ROUNDS][3][SHA256_DIGEST_LENGTH];
  unsigned char hashes_s[NUM_ROUNDS][3][SHA256_DIGEST_LENGTH];
#pragma omp parallel for
  for (unsigned i = 0; i < NUM_ROUNDS; ++i) {
    for (unsigned int j = 0; j < 3; ++j) {
      H(keys_p[i][j], c_mpc_p[i], views_p[i], j, view_count, r_p[i][j], hashes_p[i][j]);
      H(keys_s[i][j], c_mpc_s[i], views_s[i], j, view_count, r_s[i][j], hashes_s[i][j]);
    }
  }
  END_TIMING(timing_and_size->sign.views);

  START_TIMING;
  int ch[NUM_ROUNDS];
  bg_H3(hashes_p, hashes_s, ch);
  END_TIMING(timing_and_size->sign.challenge);

  create_proof(&signature->proof_p, lowmc, hashes_p, ch, r_p, keys_p, c_mpc_p, views_p);
  create_proof(&signature->proof_s, lowmc, hashes_s, ch, r_s, keys_s, c_mpc_s, views_s);

  for (unsigned i = 0; i < NUM_ROUNDS; ++i) {
    mzd_shared_clear(&lowmc_key_s[i]);
    mzd_shared_clear(&lowmc_key_k[i]);
  }


#pragma omp parallel for
  for (unsigned j = 0; j < NUM_ROUNDS; ++j) {
    for (unsigned i = 0; i < 3; ++i) {
      mpc_free(rvec_p[j][i], lowmc->r);
      mpc_free(rvec_s[j][i], lowmc->r);
    }
    for (unsigned i = 0; i < view_count; ++i) {
      free(views_p[j][i].s);
      free(views_s[j][i].s);
    }
    free(views_p[j]);
    free(views_s[j]);
  }

  return signature;
}

typedef int (*verify_ptr)(mpc_lowmc_t* lowmc, mzd_t* p, mzd_shared_t* shared_p, view_t* views,
                          mzd_t** rv[2], int ch);

static int verify_with_p(mpc_lowmc_t* lowmc, mzd_t* p, mzd_shared_t* shared_p, view_t* views,
                         mzd_t** rv[2], int ch) {
  (void)shared_p;
  return mpc_lowmc_verify(lowmc, p, views, rv, ch);
}

static int verify_with_shared_p(mpc_lowmc_t* lowmc, mzd_t* p, mzd_shared_t* shared_p, view_t* views,
                                mzd_t** rv[2], int ch) {
  (void)p;
  return mpc_lowmc_verify_shared_p(lowmc, shared_p, views, rv, ch);
}

static int verify_views(mpc_lowmc_t* lowmc, mzd_t* p, mzd_shared_t shared_p[NUM_ROUNDS],
                        proof_t* proof, verify_ptr verify, int ch[NUM_ROUNDS]) {
  int view_verify_status = 0;

#pragma omp parallel for reduction(| : view_verify_status)
  for (unsigned int i = 0; i < NUM_ROUNDS; i++) {
    mzd_t** rv[2];
    rv[0] = mzd_init_random_vectors_from_seed(proof->keys[i][0], lowmc->n, lowmc->r);
    rv[1] = mzd_init_random_vectors_from_seed(proof->keys[i][1], lowmc->n, lowmc->r);

    if (verify(lowmc, p, shared_p != NULL ? &shared_p[i] : NULL, proof->views[i], rv, ch[i])) {
      view_verify_status |= -1;
    }

    mpc_free(rv[0], lowmc->r);
    mpc_free(rv[1], lowmc->r);
  }

  return view_verify_status;
}

static int bg_proof_verify(public_parameters_t* pp, bg_public_key_t* pk, mzd_t* p,
                           bg_signature_t* signature) {
  TIME_FUNCTION;

  lowmc_t* lowmc                     = pp->lowmc;
  const unsigned int view_count      = lowmc->r + 2;
  const unsigned int last_view_index = lowmc->r + 1;
  proof_t* proof_p                   = &signature->proof_p;
  proof_t* proof_s                   = &signature->proof_s;

  START_TIMING;
  int ch[NUM_ROUNDS];
  unsigned char hash_p[NUM_ROUNDS][2][SHA256_DIGEST_LENGTH];
  unsigned char hash_s[NUM_ROUNDS][2][SHA256_DIGEST_LENGTH];

  for (unsigned i = 0; i < NUM_ROUNDS; i++) {
    H(proof_p->keys[i][0], proof_p->y[i], proof_p->views[i], 0, view_count, proof_p->r[i][0],
      hash_p[i][0]);
    H(proof_p->keys[i][1], proof_p->y[i], proof_p->views[i], 1, view_count, proof_p->r[i][1],
      hash_p[i][1]);

    H(proof_s->keys[i][0], proof_s->y[i], proof_s->views[i], 0, view_count, proof_s->r[i][0],
      hash_s[i][0]);
    H(proof_s->keys[i][1], proof_s->y[i], proof_s->views[i], 1, view_count, proof_s->r[i][1],
      hash_s[i][1]);
  }

  bg_H3_verify(hash_p, proof_p->hashes, hash_s, proof_s->hashes, proof_s->ch, ch);

  END_TIMING(timing_and_size->verify.challenge);

  START_TIMING;
  int reconstruct_status = 0;
  for (unsigned int i = 0; i < NUM_ROUNDS; i++) {
    mzd_t* c_mpcr = mpc_reconstruct_from_share(proof_p->y[i]);
    if (mzd_equal(signature->c, c_mpcr) != 0) {
      reconstruct_status = -1;
    }
    mzd_free(c_mpcr);

    c_mpcr = mpc_reconstruct_from_share(proof_s->y[i]);
    if (mzd_equal(pk->pk, c_mpcr) != 0) {
      reconstruct_status = -1;
    }
    mzd_free(c_mpcr);
  }
  END_TIMING(timing_and_size->verify.output_shares);

  START_TIMING;
  int output_share_status = 0;
#pragma omp parallel for reduction(| : output_share_status)
  for (unsigned int i = 0; i < NUM_ROUNDS; i++) {
    const unsigned int a = ch[i];
    const unsigned int b = (a + 1) % 3;

    if (mzd_equal(proof_p->y[i][a], proof_p->views[i][last_view_index].s[0]) ||
        mzd_equal(proof_p->y[i][b], proof_p->views[i][last_view_index].s[1]) ||
        mzd_equal(proof_s->y[i][a], proof_s->views[i][last_view_index].s[0]) ||
        mzd_equal(proof_s->y[i][b], proof_s->views[i][last_view_index].s[1])) {
      output_share_status |= -1;
    }
  }
  END_TIMING(timing_and_size->verify.output_views);

  START_TIMING;
  mzd_shared_t shared_s[NUM_ROUNDS] = {{0, NULL}};
  for (unsigned int i = 0; i < NUM_ROUNDS; i++) {
    mzd_shared_from_shares(&shared_s[i], proof_p->views[i][0].s, 2);
  }

  int view_verify_status = 0;
  if (verify_views(lowmc, p, shared_s, proof_p, verify_with_p, ch) ||
      verify_views(lowmc, p, shared_s, proof_s, verify_with_shared_p, ch)) {
    view_verify_status = -1;
  }

  for (unsigned int i = 0; i < NUM_ROUNDS; i++) {
    mzd_shared_clear(&shared_s[i]);
  }
  END_TIMING(timing_and_size->verify.verify);

#ifdef VERBOSE
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
  printf("\n");
#endif

  return output_share_status || reconstruct_status || view_verify_status;
}

bg_signature_t* bg_sign(public_parameters_t* pp, bg_private_key_t* private_key, mzd_t* m) {
  return bg_prove(pp, private_key, m);
}

int bg_verify(public_parameters_t* pp, bg_public_key_t* public_key, mzd_t* m, bg_signature_t* sig) {
  return bg_proof_verify(pp, public_key, m, sig);
}

