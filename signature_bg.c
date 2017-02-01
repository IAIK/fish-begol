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
  unsigned char* p1 = proof_to_char_array(pp->lowmc, &sig->proof_c, &len1, true);
  unsigned len2     = 0;
  unsigned char* p2 = proof_to_char_array(pp->lowmc, &sig->proof_y, &len2, false);
  unsigned char* c  = mzd_to_char_array(sig->y, pp->lowmc->n / 8);

  *len = len1 + len2 + (pp->lowmc->n / 8);

  unsigned char* result = malloc(*len * sizeof(unsigned char));
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
  bg_signature_t* sig = malloc(sizeof(bg_signature_t));
  unsigned int len    = 0;
  proof_from_char_array(pp->lowmc, &sig->proof_c, data, &len, true);
  data += len;
  proof_from_char_array(pp->lowmc, &sig->proof_y, data, &len, false);
  data += len;
  sig->y = mzd_from_char_array(data, pp->lowmc->n / 8, pp->lowmc->n);

  return sig;
}

bool bg_create_key(public_parameters_t* pp, bg_private_key_t* private_key,
                   bg_public_key_t* public_key) {
  TIME_FUNCTION;

  START_TIMING;
  lowmc_key_t* lowmc_key_s = lowmc_keygen(pp->lowmc);

  private_key->s = lowmc_key_s;
  END_TIMING(timing_and_size->gen.keygen);

  if (!private_key->s) {
    return false;
  }

  private_key->beta = public_key->beta = mzd_local_init(1, pp->lowmc->n);
  if (!private_key->beta) {
    return false;
  }

  START_TIMING;
  public_key->c = lowmc_call(pp->lowmc, lowmc_key_s, public_key->beta);
  END_TIMING(timing_and_size->gen.pubkey);

  return public_key->c != NULL;
}

void bg_destroy_key(bg_private_key_t* private_key, bg_public_key_t* public_key) {
  lowmc_key_free(private_key->s);
  private_key->s    = NULL;
  private_key->beta = NULL;

  mzd_local_free(public_key->c);
  mzd_local_free(public_key->beta);
  public_key->beta = NULL;
  public_key->c    = NULL;
}

void bg_free_signature(public_parameters_t* pp, bg_signature_t* signature) {
  clear_proof(pp->lowmc, &signature->proof_c);
  clear_proof(pp->lowmc, &signature->proof_y);
  mzd_local_free(signature->y);

  free(signature);
}

static bg_signature_t* bg_prove(public_parameters_t* pp, bg_private_key_t* private_key, mzd_t* p) {
  if (mzd_local_equal(p, private_key->beta) == 0) {
#ifdef VERBOSE
    printf("p == beta, aborting\n");
#endif
    return NULL;
  }

  TIME_FUNCTION;
  lowmc_t const* lowmc          = pp->lowmc;
  const unsigned int view_count = lowmc->r + 2;

  unsigned char r_y[BG_NUM_ROUNDS][3][COMMITMENT_RAND_LENGTH];
  unsigned char keys_y[BG_NUM_ROUNDS][3][16];
  unsigned char r_c[BG_NUM_ROUNDS][3][COMMITMENT_RAND_LENGTH];
  unsigned char keys_c[BG_NUM_ROUNDS][3][16];
  unsigned char secret_sharing_key[16];

  // Generating keys
  START_TIMING;
  if (rand_bytes((unsigned char*)keys_y, sizeof(keys_y)) != 1 ||
      rand_bytes((unsigned char*)r_y, sizeof(r_y)) != 1 ||
      rand_bytes((unsigned char*)keys_c, sizeof(keys_c)) != 1 ||
      rand_bytes((unsigned char*)r_c, sizeof(r_c)) != 1 ||
      rand_bytes((unsigned char*)secret_sharing_key, sizeof(secret_sharing_key)) != 1) {
#ifdef VERBOSE
    printf("rand_bytes failed crypto, aborting\n");
#endif
    return NULL;
  }

  mzd_t** rvec_y[BG_NUM_ROUNDS][3];
  mzd_t** rvec_c[BG_NUM_ROUNDS][3];
#pragma omp parallel for
  for (unsigned int i = 0; i < BG_NUM_ROUNDS; ++i) {
    for (unsigned int j = 0; j < 3; ++j) {
      rvec_y[i][j] = mzd_init_random_vectors_from_seed(keys_y[i][j], lowmc->n, lowmc->r);
      rvec_c[i][j] = mzd_init_random_vectors_from_seed(keys_c[i][j], lowmc->n, lowmc->r);
    }
  }
  END_TIMING(timing_and_size->sign.rand);

  bg_signature_t* signature = calloc(1, sizeof(bg_signature_t));

  view_t* views_y[BG_NUM_ROUNDS];
  view_t* views_c[BG_NUM_ROUNDS];

  init_view(lowmc, views_y);
  init_view(lowmc, views_c);

  mpc_lowmc_key_t lowmc_key_s[BG_NUM_ROUNDS] = {MZD_SHARED_EMPTY};

  START_TIMING;
  aes_prng_t aes_prng;
  aes_prng_init(&aes_prng, secret_sharing_key);
  for (unsigned i = 0; i < BG_NUM_ROUNDS; ++i) {
    mzd_shared_init(&lowmc_key_s[i], private_key->s);
    mzd_shared_share_prng(&lowmc_key_s[i], &aes_prng);
  }
  aes_prng_clear(&aes_prng);
  END_TIMING(timing_and_size->sign.secret_sharing);

  mzd_t** c_mpc_y[BG_NUM_ROUNDS];
  mzd_t** c_mpc_c[BG_NUM_ROUNDS];

  START_TIMING;
#pragma omp parallel for
  for (unsigned int i = 0; i < BG_NUM_ROUNDS; ++i) {
    c_mpc_y[i] = mpc_lowmc_call(lowmc, &lowmc_key_s[i], p, true, views_y[i], rvec_y[i]);
    c_mpc_c[i] =
        mpc_lowmc_call(lowmc, &lowmc_key_s[i], private_key->beta, true, views_c[i], rvec_c[i]);
  }
  signature->y = mpc_reconstruct_from_share(NULL, c_mpc_y[0]);
  mzd_t* c     = mpc_reconstruct_from_share(NULL, c_mpc_c[0]);
  END_TIMING(timing_and_size->sign.lowmc_enc);

  START_TIMING;
  unsigned char hashes_y[BG_NUM_ROUNDS][3][COMMITMENT_LENGTH];
  unsigned char hashes_c[BG_NUM_ROUNDS][3][COMMITMENT_LENGTH];
#pragma omp parallel for
  for (unsigned int i = 0; i < BG_NUM_ROUNDS; ++i) {
    for (unsigned int j = 0; j < 3; ++j) {
      H(keys_y[i][j], c_mpc_y[i], views_y[i], j, view_count, r_y[i][j], hashes_y[i][j]);
      H(keys_c[i][j], c_mpc_c[i], views_c[i], j, view_count, r_c[i][j], hashes_c[i][j]);
    }
  }
  END_TIMING(timing_and_size->sign.views);

  START_TIMING;
  unsigned char ch[BG_NUM_ROUNDS];
  bg_H3(private_key->beta, c, p, signature->y, hashes_y, hashes_c, ch);
  END_TIMING(timing_and_size->sign.challenge);

  mzd_local_free(c);

  create_proof(&signature->proof_y, lowmc, hashes_y, ch, r_y, keys_y, views_y);
  create_proof(&signature->proof_c, lowmc, hashes_c, ch, r_c, keys_c, views_c);

  for (unsigned i = 0; i < BG_NUM_ROUNDS; ++i) {
    mzd_shared_clear(&lowmc_key_s[i]);
  }

  for (unsigned j = 0; j < BG_NUM_ROUNDS; ++j) {
    for (unsigned i = 0; i < 3; ++i) {
      mzd_local_free_multiple(rvec_c[j][i]);
      free(rvec_c[j][i]);
      mzd_local_free_multiple(rvec_y[j][i]);
      free(rvec_y[j][i]);
    }

    mpc_free(c_mpc_c[j], 3);
    mpc_free(c_mpc_y[j], 3);
  }

  free_view(lowmc, views_c);
  free_view(lowmc, views_y);

  return signature;
}

static int verify_views(mpc_lowmc_t const* lowmc, mzd_t const* p, mzd_t const* beta,
                        proof_t const* proof_y, proof_t const* proof_c,
                        unsigned char ch[BG_NUM_ROUNDS]) {
  int view_verify_status = 0;

#pragma omp parallel for reduction(| : view_verify_status)
  for (unsigned int i = 0; i < BG_NUM_ROUNDS; ++i) {
    mzd_t** rv_y[2];
    mzd_t** rv_c[2];
    rv_y[0] = mzd_init_random_vectors_from_seed(proof_y->keys[i][0], lowmc->n, lowmc->r);
    rv_y[1] = mzd_init_random_vectors_from_seed(proof_y->keys[i][1], lowmc->n, lowmc->r);
    rv_c[0] = mzd_init_random_vectors_from_seed(proof_c->keys[i][0], lowmc->n, lowmc->r);
    rv_c[1] = mzd_init_random_vectors_from_seed(proof_c->keys[i][1], lowmc->n, lowmc->r);

    if (mpc_lowmc_verify(lowmc, p, true, proof_y->views[i], rv_y, ch[i]) ||
        mpc_lowmc_verify(lowmc, beta, true, proof_c->views[i], rv_c, ch[i])) {
      view_verify_status |= -1;
    }

    mzd_local_free_multiple(rv_c[1]);
    free(rv_c[1]);
    mzd_local_free_multiple(rv_c[0]);
    free(rv_c[0]);
    mzd_local_free_multiple(rv_y[1]);
    free(rv_y[1]);
    mzd_local_free_multiple(rv_y[0]);
    free(rv_y[0]);
  }

  return view_verify_status;
}

static int bg_proof_verify(public_parameters_t* pp, bg_public_key_t* pk, mzd_t* p,
                           bg_signature_t* signature) {
  TIME_FUNCTION;

  if (mzd_local_equal(p, pk->beta) == 0) {
#ifdef VERBOSE
    printf("p == beta, aborting\n");
#endif
    return -1;
  }

  lowmc_t const* lowmc               = pp->lowmc;
  const unsigned int view_count      = lowmc->r + 2;
  const unsigned int last_view_index = lowmc->r + 1;
  proof_t* proof_y                   = &signature->proof_y;
  proof_t* proof_c                   = &signature->proof_c;

  START_TIMING;
  unsigned char ch[BG_NUM_ROUNDS];
  unsigned char hash_y[BG_NUM_ROUNDS][2][COMMITMENT_LENGTH];
  unsigned char hash_c[BG_NUM_ROUNDS][2][COMMITMENT_LENGTH];

  mzd_t* ys_y[NUM_ROUNDS][3] = {{NULL}};
  mzd_t* ys_c[NUM_ROUNDS][3] = {{NULL}};

  mzd_t* y_free_y[NUM_ROUNDS] = {NULL};
  mzd_t* y_free_c[NUM_ROUNDS] = {NULL};
  mzd_local_init_multiple(y_free_y, NUM_ROUNDS, 1, lowmc->n);
  mzd_local_init_multiple(y_free_c, NUM_ROUNDS, 1, lowmc->n);

#pragma omp parallel for
  for (unsigned int i = 0; i < BG_NUM_ROUNDS; ++i) {
    const unsigned int a_i = getChAt(proof_c->ch, i);
    const unsigned int b_i = (a_i + 1) % 3;
    const unsigned int c_i = (a_i + 2) % 3;

    ys_c[i][a_i] = proof_c->views[i][last_view_index].s[0];
    ys_c[i][b_i] = proof_c->views[i][last_view_index].s[1];
    ys_c[i][c_i] = pk->c;

    ys_y[i][a_i] = proof_y->views[i][last_view_index].s[0];
    ys_y[i][b_i] = proof_y->views[i][last_view_index].s[1];
    ys_y[i][c_i] = signature->y;

    ys_c[i][c_i] = mpc_reconstruct_from_share(y_free_c[i], ys_c[i]);
    ys_y[i][c_i] = mpc_reconstruct_from_share(y_free_y[i], ys_y[i]);

    H(proof_y->keys[i][0], ys_y[i], proof_y->views[i], 0, view_count, proof_y->r[i][0],
      hash_y[i][0]);
    H(proof_y->keys[i][1], ys_y[i], proof_y->views[i], 1, view_count, proof_y->r[i][1],
      hash_y[i][1]);

    H(proof_c->keys[i][0], ys_c[i], proof_c->views[i], 0, view_count, proof_c->r[i][0],
      hash_c[i][0]);
    H(proof_c->keys[i][1], ys_c[i], proof_c->views[i], 1, view_count, proof_c->r[i][1],
      hash_c[i][1]);
  }

  bg_H3_verify(pk->beta, pk->c, p, signature->y, hash_y, proof_y->hashes, hash_c, proof_c->hashes,
               proof_c->ch, ch);

  END_TIMING(timing_and_size->verify.challenge);

  int reconstruct_status  = 0;
  int output_share_status = 0;
  int view_verify_status  = 0;

  // TODO: probably unnecessary now
  START_TIMING;
#pragma omp parallel for reduction(| : reconstruct_status)
  for (unsigned int i = 0; i < BG_NUM_ROUNDS; ++i) {
    mzd_t* c_mpcr = mpc_reconstruct_from_share(NULL, ys_y[i]);
    if (mzd_local_equal(signature->y, c_mpcr) != 0) {
      reconstruct_status |= -1;
    }

    c_mpcr = mpc_reconstruct_from_share(c_mpcr, ys_c[i]);
    if (mzd_local_equal(pk->c, c_mpcr) != 0) {
      reconstruct_status |= -1;
    }
    mzd_local_free(c_mpcr);
  }
  END_TIMING(timing_and_size->verify.output_shares);

  // TODO: probably unnecessary now
  START_TIMING;
#pragma omp parallel for reduction(| : output_share_status)
  for (unsigned int i = 0; i < BG_NUM_ROUNDS; ++i) {
    const unsigned int a = ch[i];
    const unsigned int b = (a + 1) % 3;

    if (mzd_local_equal(ys_y[i][a], proof_y->views[i][last_view_index].s[0]) ||
        mzd_local_equal(ys_y[i][b], proof_y->views[i][last_view_index].s[1]) ||
        mzd_local_equal(ys_c[i][a], proof_c->views[i][last_view_index].s[0]) ||
        mzd_local_equal(ys_c[i][b], proof_c->views[i][last_view_index].s[1])) {
      output_share_status |= -1;
    }
  }
  END_TIMING(timing_and_size->verify.output_views);

  mzd_local_free_multiple(y_free_c);
  mzd_local_free_multiple(y_free_y);

  START_TIMING;
  view_verify_status = verify_views(lowmc, p, pk->beta, proof_y, proof_c, ch);
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
