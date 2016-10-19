#include "signature_bg.h"
#include "hashing_util.h"
#include "io.h"
#include "lowmc.h"
#include "mpc.h"
#include "randomness.h"
#include "timing.h"

unsigned bg_compute_sig_size(unsigned m, unsigned n, unsigned r, unsigned k) {
  unsigned first_view_size = k;
  unsigned full_view_size  = n;
  unsigned int_view_size   = 3 * m;
  // views for mpc_and in sbox, intial view and last view
  unsigned views = 2 * (r * int_view_size + first_view_size + full_view_size);
  // commitment and r and seed
  unsigned int commitment = 8 * (COMMITMENT_LENGTH + 2 * (COMMITMENT_RAND_LENGTH + 16));
  unsigned int challenge  = (BG_NUM_ROUNDS + 3) / 4;

  return (2 * BG_NUM_ROUNDS * (commitment + views) + full_view_size + challenge + 7) / 8;
}

unsigned char* bg_sig_to_char_array(public_parameters_t* pp, bg_signature_t* sig, unsigned* len) {
  unsigned len1     = 0;
  unsigned char* p1 = proof_to_char_array(pp->lowmc, &sig->proof_s, &len1, true);
  unsigned len2     = 0;
  unsigned char* p2 = proof_to_char_array(pp->lowmc, &sig->proof_p, &len2, false);
  unsigned char* c  = mzd_to_char_array(sig->c, pp->lowmc->n / 8);

  *len = len1 + len2 + (pp->lowmc->n / 8);

  unsigned char* result = (unsigned char*)malloc(*len * sizeof(unsigned char));
  unsigned char* temp   = result;
  memcpy(temp, p1, len1);
  temp += len1;
  memcpy(temp, p2, len2);
  temp += len2;
  memcpy(temp, c, pp->lowmc->n / 8);

  free(p1);
  free(p2);
  free(c);

  return result;
}

bg_signature_t* bg_sig_from_char_array(public_parameters_t* pp, unsigned char* data) {
  bg_signature_t* sig = (bg_signature_t*)malloc(sizeof(bg_signature_t));
  unsigned len        = 0;
  proof_from_char_array(pp->lowmc, &sig->proof_s, data, &len, true);
  data += len;
  proof_from_char_array(pp->lowmc, &sig->proof_p, data, &len, false);
  data += len;
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

  mzd_local_free(public_key->pk);
  public_key->pk = NULL;
}

void bg_free_signature(public_parameters_t* pp, bg_signature_t* signature) {
  clear_proof(pp->lowmc, &signature->proof_p);
  clear_proof(pp->lowmc, &signature->proof_s);
  mzd_local_free(signature->c);

  free(signature);
}

static bg_signature_t* bg_prove(public_parameters_t* pp, bg_private_key_t* private_key, mzd_t* p) {
  TIME_FUNCTION;
  lowmc_t const* lowmc          = pp->lowmc;
  const unsigned int view_count = lowmc->r + 2;

  unsigned char r_p[BG_NUM_ROUNDS][3][COMMITMENT_RAND_LENGTH];
  unsigned char keys_p[BG_NUM_ROUNDS][3][16];
  unsigned char r_s[BG_NUM_ROUNDS][3][COMMITMENT_RAND_LENGTH];
  unsigned char keys_s[BG_NUM_ROUNDS][3][16];
  unsigned char secret_sharing_key[16];

  // Generating keys
  START_TIMING;
  if (rand_bytes((unsigned char*)keys_p, sizeof(keys_p)) != 1 ||
      rand_bytes((unsigned char*)r_p, sizeof(r_p)) != 1 ||
      rand_bytes((unsigned char*)keys_s, sizeof(keys_s)) != 1 ||
      rand_bytes((unsigned char*)r_s, sizeof(r_s)) != 1 ||
      rand_bytes((unsigned char*)secret_sharing_key, sizeof(secret_sharing_key)) != 1) {
#ifdef VERBOSE
    printf("rand_bytes failed crypto, aborting\n");
#endif
    return NULL;
  }

  mzd_t** rvec_p[BG_NUM_ROUNDS][3];
  mzd_t** rvec_s[BG_NUM_ROUNDS][3];
#pragma omp parallel for
  for (unsigned i = 0; i < BG_NUM_ROUNDS; ++i) {
    for (unsigned int j = 0; j < 3; ++j) {
      rvec_p[i][j] = mzd_init_random_vectors_from_seed(keys_p[i][j], lowmc->n, lowmc->r);
      rvec_s[i][j] = mzd_init_random_vectors_from_seed(keys_s[i][j], lowmc->n, lowmc->r);
    }
  }
  END_TIMING(timing_and_size->sign.rand);

  bg_signature_t* signature = calloc(1, sizeof(bg_signature_t));

  view_t* views_p[BG_NUM_ROUNDS];
  view_t* views_s[BG_NUM_ROUNDS];

  init_view(lowmc, views_p);
  init_view(lowmc, views_s);

  mpc_lowmc_key_t lowmc_key_k[BG_NUM_ROUNDS] = {MZD_SHARED_EMPTY};
  mpc_lowmc_key_t lowmc_key_s[BG_NUM_ROUNDS] = {MZD_SHARED_EMPTY};

  START_TIMING;
  aes_prng_t aes_prng;
  aes_prng_init(&aes_prng, secret_sharing_key);
  for (unsigned i = 0; i < BG_NUM_ROUNDS; ++i) {
    mzd_shared_init(&lowmc_key_s[i], private_key->s);
    mzd_shared_share_prng(&lowmc_key_s[i], &aes_prng);

    mzd_shared_init(&lowmc_key_k[i], private_key->k);
    mzd_shared_share_prng(&lowmc_key_k[i], &aes_prng);
  }
  aes_prng_clear(&aes_prng);
  END_TIMING(timing_and_size->sign.secret_sharing);

  mzd_t** c_mpc_p[BG_NUM_ROUNDS];
  mzd_t** c_mpc_s[BG_NUM_ROUNDS];

  START_TIMING;
#pragma omp parallel for
  for (unsigned i = 0; i < BG_NUM_ROUNDS; ++i) {
    c_mpc_p[i] = mpc_lowmc_call(lowmc, &lowmc_key_s[i], p, views_p[i], rvec_p[i]);
    c_mpc_s[i] =
        mpc_lowmc_call_shared_p(lowmc, &lowmc_key_k[i], &lowmc_key_s[i], views_s[i], rvec_s[i]);
  }
  signature->c = mpc_reconstruct_from_share(NULL, c_mpc_p[0]);
  END_TIMING(timing_and_size->sign.lowmc_enc);

  START_TIMING;
  unsigned char hashes_p[BG_NUM_ROUNDS][3][COMMITMENT_LENGTH];
  unsigned char hashes_s[BG_NUM_ROUNDS][3][COMMITMENT_LENGTH];
#pragma omp parallel for
  for (unsigned i = 0; i < BG_NUM_ROUNDS; ++i) {
    for (unsigned int j = 0; j < 3; ++j) {
      H(keys_p[i][j], c_mpc_p[i], views_p[i], j, view_count, r_p[i][j], hashes_p[i][j]);
      H(keys_s[i][j], c_mpc_s[i], views_s[i], j, view_count, r_s[i][j], hashes_s[i][j]);
    }
  }
  END_TIMING(timing_and_size->sign.views);

  START_TIMING;
  unsigned char ch[BG_NUM_ROUNDS];
  bg_H3(hashes_p, hashes_s, ch);
  END_TIMING(timing_and_size->sign.challenge);

  create_proof(&signature->proof_p, lowmc, hashes_p, ch, r_p, keys_p, views_p);
  create_proof(&signature->proof_s, lowmc, hashes_s, ch, r_s, keys_s, views_s);

  for (unsigned i = 0; i < BG_NUM_ROUNDS; ++i) {
    mzd_shared_clear(&lowmc_key_s[i]);
    mzd_shared_clear(&lowmc_key_k[i]);
  }

  for (unsigned j = 0; j < BG_NUM_ROUNDS; ++j) {
    for (unsigned i = 0; i < 3; ++i) {
      mzd_local_free_multiple(rvec_s[j][i]);
      free(rvec_s[j][i]);
      mzd_local_free_multiple(rvec_p[j][i]);
      free(rvec_p[j][i]);
    }

    mpc_free(c_mpc_p[j], 3);
    mpc_free(c_mpc_s[j], 3);
  }

  free_view(lowmc, views_p);
  free_view(lowmc, views_s);

  return signature;
}

static int verify_views(mpc_lowmc_t const* lowmc, mzd_t const* p, proof_t const* proof_p,
                        proof_t const* proof_s, unsigned char ch[BG_NUM_ROUNDS]) {
  int view_verify_status = 0;

#pragma omp parallel for reduction(| : view_verify_status)
  for (unsigned int i = 0; i < BG_NUM_ROUNDS; i++) {
    mzd_shared_t shared_s = MZD_SHARED_EMPTY;
    mzd_shared_from_shares(&shared_s, proof_p->views[i][0].s, 2);

    mzd_t** rv_p[2];
    mzd_t** rv_s[2];
    rv_p[0] = mzd_init_random_vectors_from_seed(proof_p->keys[i][0], lowmc->n, lowmc->r);
    rv_p[1] = mzd_init_random_vectors_from_seed(proof_p->keys[i][1], lowmc->n, lowmc->r);
    rv_s[0] = mzd_init_random_vectors_from_seed(proof_s->keys[i][0], lowmc->n, lowmc->r);
    rv_s[1] = mzd_init_random_vectors_from_seed(proof_s->keys[i][1], lowmc->n, lowmc->r);

    if (mpc_lowmc_verify(lowmc, p, proof_p->views[i], rv_p, ch[i]) ||
        mpc_lowmc_verify_shared_p(lowmc, &shared_s, proof_s->views[i], rv_s, ch[i])) {
      view_verify_status |= -1;
    }

    mzd_local_free_multiple(rv_s[1]);
    free(rv_s[1]);
    mzd_local_free_multiple(rv_s[0]);
    free(rv_s[0]);
    mzd_local_free_multiple(rv_p[1]);
    free(rv_p[1]);
    mzd_local_free_multiple(rv_p[0]);
    free(rv_p[0]);

    mzd_shared_clear(&shared_s);
  }

  return view_verify_status;
}

static int bg_proof_verify(public_parameters_t* pp, bg_public_key_t* pk, mzd_t* p,
                           bg_signature_t* signature) {
  TIME_FUNCTION;

  lowmc_t const* lowmc               = pp->lowmc;
  const unsigned int view_count      = lowmc->r + 2;
  const unsigned int last_view_index = lowmc->r + 1;
  proof_t* proof_p                   = &signature->proof_p;
  proof_t* proof_s                   = &signature->proof_s;

  START_TIMING;
  unsigned char ch[BG_NUM_ROUNDS];
  unsigned char hash_p[BG_NUM_ROUNDS][2][COMMITMENT_LENGTH];
  unsigned char hash_s[BG_NUM_ROUNDS][2][COMMITMENT_LENGTH];

  mzd_t* ys_p[NUM_ROUNDS][3];
  mzd_t* ys_s[NUM_ROUNDS][3];

  mzd_t* y_free_p[NUM_ROUNDS];
  mzd_t* y_free_s[NUM_ROUNDS];
  mzd_local_init_multiple(y_free_p, NUM_ROUNDS, 1, lowmc->n);
  mzd_local_init_multiple(y_free_s, NUM_ROUNDS, 1, lowmc->n);

#pragma omp parallel for
  for (unsigned i = 0; i < BG_NUM_ROUNDS; ++i) {
    unsigned int a_i = getChAt(proof_s->ch, i);
    unsigned int b_i = (a_i + 1) % 3;
    unsigned int c_i = (a_i + 2) % 3;

    ys_s[i][a_i] = proof_s->views[i][last_view_index].s[0];
    ys_s[i][b_i] = proof_s->views[i][last_view_index].s[1];
    ys_s[i][c_i] = pk->pk;

    ys_p[i][a_i] = proof_p->views[i][last_view_index].s[0];
    ys_p[i][b_i] = proof_p->views[i][last_view_index].s[1];
    ys_p[i][c_i] = signature->c;

    ys_s[i][c_i] = mpc_reconstruct_from_share(y_free_s[i], ys_s[i]);
    ys_p[i][c_i] = mpc_reconstruct_from_share(y_free_p[i], ys_p[i]);

    H(proof_p->keys[i][0], ys_p[i], proof_p->views[i], 0, view_count, proof_p->r[i][0],
      hash_p[i][0]);
    H(proof_p->keys[i][1], ys_p[i], proof_p->views[i], 1, view_count, proof_p->r[i][1],
      hash_p[i][1]);

    H(proof_s->keys[i][0], ys_s[i], proof_s->views[i], 0, view_count, proof_s->r[i][0],
      hash_s[i][0]);
    H(proof_s->keys[i][1], ys_s[i], proof_s->views[i], 1, view_count, proof_s->r[i][1],
      hash_s[i][1]);
  }

  bg_H3_verify(hash_p, proof_p->hashes, hash_s, proof_s->hashes, proof_s->ch, ch);

  END_TIMING(timing_and_size->verify.challenge);

  int reconstruct_status  = 0;
  int output_share_status = 0;
  int view_verify_status  = 0;

  // TODO: probably unnecessary now
  START_TIMING;
#pragma omp parallel for reduction(| : reconstruct_status) reduction(| : output_share_status)
  for (unsigned int i = 0; i < BG_NUM_ROUNDS; ++i) {
    mzd_t* c_mpcr = mpc_reconstruct_from_share(NULL, ys_p[i]);
    if (mzd_equal(signature->c, c_mpcr) != 0) {
      reconstruct_status |= -1;
    }

    c_mpcr = mpc_reconstruct_from_share(c_mpcr, ys_s[i]);
    if (mzd_equal(pk->pk, c_mpcr) != 0) {
      reconstruct_status |= -1;
    }
    mzd_local_free(c_mpcr);
  }
  END_TIMING(timing_and_size->verify.output_shares);

  mzd_local_free_multiple(y_free_s);
  mzd_local_free_multiple(y_free_p);

  // TODO: probably unnecessary now
  START_TIMING;
#pragma omp parallel for reduction(| : output_share_status)
  for (unsigned int i = 0; i < BG_NUM_ROUNDS; ++i) {
    const unsigned int a = ch[i];
    const unsigned int b = (a + 1) % 3;

    if (mzd_equal(ys_p[i][a], proof_p->views[i][last_view_index].s[0]) ||
        mzd_equal(ys_p[i][b], proof_p->views[i][last_view_index].s[1]) ||
        mzd_equal(ys_s[i][a], proof_s->views[i][last_view_index].s[0]) ||
        mzd_equal(ys_s[i][b], proof_s->views[i][last_view_index].s[1])) {
      output_share_status |= -1;
    }
  }
  END_TIMING(timing_and_size->verify.output_views);

  START_TIMING;
  view_verify_status = verify_views(lowmc, p, proof_p, proof_s, ch);
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
