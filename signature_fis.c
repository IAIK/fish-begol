#include "signature_fis.h"
#include "hashing_util.h"
#include "lowmc.h"
#include "mpc.h"
#include "mpc_lowmc.h"
#include "randomness.h"
#include "timing.h"

unsigned fis_compute_sig_size(unsigned m, unsigned n, unsigned r, unsigned k) {
  unsigned first_view_size = k;
  unsigned full_view_size  = n;
  unsigned int_view_size   = 3 * m;
  // views for mpc_and in sbox, intial view and last view + shared ciphertexts
  unsigned views = 2 * (r * int_view_size + first_view_size + full_view_size) + 3 * full_view_size;
  // commitment and r and seed
  unsigned int commitment = 8 * (COMMITMENT_LENGTH + 2 * (COMMITMENT_RAND_LENGTH + 16));
  unsigned int challenge  = (FIS_NUM_ROUNDS + 3) / 4;

  return (FIS_NUM_ROUNDS * (commitment + views) + full_view_size + challenge + 7) / 8;
}

unsigned char* fis_sig_to_char_array(public_parameters_t* pp, fis_signature_t* sig, unsigned* len) {
  return proof_to_char_array(pp->lowmc, sig->proof, len, true);
}

fis_signature_t* fis_sig_from_char_array(public_parameters_t* pp, unsigned char* data) {
  unsigned len         = 0;
  fis_signature_t* sig = (fis_signature_t*)malloc(sizeof(fis_signature_t));
  sig->proof           = proof_from_char_array(pp->lowmc, 0, data, &len, true);
  return sig;
}

void fis_create_key(public_parameters_t* pp, fis_private_key_t* private_key,
                    fis_public_key_t* public_key) {
  TIME_FUNCTION;

  START_TIMING;
  private_key->k = lowmc_keygen(pp->lowmc);
  END_TIMING(timing_and_size->gen.keygen);

  START_TIMING;
  mzd_t* p       = mzd_local_init(1, pp->lowmc->n);
  public_key->pk = lowmc_call(pp->lowmc, private_key->k, p);
  mzd_local_free(p);
  END_TIMING(timing_and_size->gen.pubkey);
}

void fis_destroy_key(fis_private_key_t* private_key, fis_public_key_t* public_key) {
  lowmc_key_free(private_key->k);
  private_key->k = NULL;

  mzd_local_free(public_key->pk);
  public_key->pk = NULL;
}

static proof_t* fis_prove(mpc_lowmc_t* lowmc, lowmc_key_t* lowmc_key, mzd_t* p, char* m,
                          unsigned m_len) {
  TIME_FUNCTION;

  const unsigned int view_count = lowmc->r + 2;

  unsigned char r[FIS_NUM_ROUNDS][3][COMMITMENT_RAND_LENGTH];
  unsigned char keys[FIS_NUM_ROUNDS][3][16];
  unsigned char secret_sharing_key[16];

  // Generating keys
  START_TIMING;
  if (rand_bytes((unsigned char*)keys, sizeof(keys)) != 1 ||
      rand_bytes((unsigned char*)r, sizeof(r)) != 1 ||
      rand_bytes(secret_sharing_key, sizeof(secret_sharing_key)) != 1) {
#ifdef VERBOSE
    printf("rand_bytes failed crypto, aborting\n");
#endif
    return 0;
  }

  mzd_t** rvec[FIS_NUM_ROUNDS][3];
#pragma omp parallel for
  for (unsigned i = 0; i < FIS_NUM_ROUNDS; i++) {
    rvec[i][0] = mzd_init_random_vectors_from_seed(keys[i][0], lowmc->n, lowmc->r);
    rvec[i][1] = mzd_init_random_vectors_from_seed(keys[i][1], lowmc->n, lowmc->r);
    rvec[i][2] = mzd_init_random_vectors_from_seed(keys[i][2], lowmc->n, lowmc->r);
  }
  END_TIMING(timing_and_size->sign.rand);

  view_t* views[FIS_NUM_ROUNDS];
  init_view(lowmc, views);

  START_TIMING;
  aes_prng_t aes_prng;
  aes_prng_init(&aes_prng, secret_sharing_key);

  mzd_shared_t s[FIS_NUM_ROUNDS];
  for (unsigned int i = 0; i < FIS_NUM_ROUNDS; ++i) {
    mzd_shared_init(&s[i], lowmc_key);
    mzd_shared_share_prng(&s[i], &aes_prng);
  }
  aes_prng_clear(&aes_prng);
  END_TIMING(timing_and_size->sign.secret_sharing);

  START_TIMING;
  mzd_t*** c_mpc = (mzd_t***)malloc(FIS_NUM_ROUNDS * sizeof(mzd_t**));
#pragma omp parallel for
  for (unsigned i = 0; i < FIS_NUM_ROUNDS; i++) {
    c_mpc[i] = mpc_lowmc_call(lowmc, &s[i], p, views[i], rvec[i]);
  }
  END_TIMING(timing_and_size->sign.lowmc_enc);

  START_TIMING;
  unsigned char hashes[FIS_NUM_ROUNDS][3][COMMITMENT_LENGTH];
#pragma omp parallel for
  for (unsigned i = 0; i < FIS_NUM_ROUNDS; ++i) {
    H(keys[i][0], c_mpc[i], views[i], 0, view_count, r[i][0], hashes[i][0]);
    H(keys[i][1], c_mpc[i], views[i], 1, view_count, r[i][1], hashes[i][1]);
    H(keys[i][2], c_mpc[i], views[i], 2, view_count, r[i][2], hashes[i][2]);
  }
  END_TIMING(timing_and_size->sign.views);

  START_TIMING;
  unsigned char ch[FIS_NUM_ROUNDS];
  fis_H3(hashes, m, m_len, ch);
  END_TIMING(timing_and_size->sign.challenge);

  proof_t* proof = create_proof(0, lowmc, hashes, ch, r, keys, c_mpc, views);

  for (unsigned j = 0; j < FIS_NUM_ROUNDS; j++) {
    mzd_shared_clear(&s[j]);
    for (unsigned i = 0; i < 3; i++) {
      mzd_local_free_multiple(rvec[j][i]);
      free(rvec[j][i]);
    }
  }

  free_view(lowmc, views);

  return proof;
}

static int fis_proof_verify(mpc_lowmc_t const* lowmc, mzd_t const* p, mzd_t const* c,
                            proof_t const* prf, const char* m, unsigned m_len) {
  TIME_FUNCTION;

  const unsigned int view_count      = lowmc->r + 2;
  const unsigned int last_view_index = lowmc->r + 1;

  START_TIMING;
  unsigned char ch[FIS_NUM_ROUNDS];
  unsigned char hash[FIS_NUM_ROUNDS][2][COMMITMENT_LENGTH];
#pragma omp parallel for
  for (unsigned i = 0; i < FIS_NUM_ROUNDS; ++i) {
    // TODO: reconstruct y from challenge and last view
    H(prf->keys[i][0], prf->y[i], prf->views[i], 0, view_count, prf->r[i][0], hash[i][0]);
    H(prf->keys[i][1], prf->y[i], prf->views[i], 1, view_count, prf->r[i][1], hash[i][1]);
  }
  fis_H3_verify(hash, prf->hashes, prf->ch, m, m_len, ch);
  END_TIMING(timing_and_size->verify.challenge);

  int reconstruct_status  = 0;
  int output_share_status = 0;
  int view_verify_status  = 0;

  START_TIMING;
#pragma omp parallel for reduction(| : reconstruct_status) reduction(| : view_verify_status)
  for (unsigned int i = 0; i < FIS_NUM_ROUNDS; ++i) {
    mzd_t* c_mpcr = mpc_reconstruct_from_share(prf->y[i]);
    if (mzd_cmp(c, c_mpcr) != 0) {
      reconstruct_status |= -1;
    }
    mzd_local_free(c_mpcr);
  }
  END_TIMING(timing_and_size->verify.output_shares);

  START_TIMING;
#pragma omp parallel for reduction(| : output_share_status)
  for (unsigned int i = 0; i < FIS_NUM_ROUNDS; ++i) {
    if (mzd_cmp(prf->y[i][ch[i]], prf->views[i][last_view_index].s[0]) ||
        mzd_cmp(prf->y[i][(ch[i] + 1) % 3], prf->views[i][last_view_index].s[1])) {
      output_share_status |= -1;
    }
  }
  END_TIMING(timing_and_size->verify.output_views);

  START_TIMING;
#pragma omp parallel for reduction(| : view_verify_status)
  for (unsigned int i = 0; i < FIS_NUM_ROUNDS; ++i) {
    mzd_t** rv[2];
    rv[0] = mzd_init_random_vectors_from_seed(prf->keys[i][0], lowmc->n, lowmc->r);
    rv[1] = mzd_init_random_vectors_from_seed(prf->keys[i][1], lowmc->n, lowmc->r);

    if (mpc_lowmc_verify(lowmc, p, prf->views[i], rv, ch[i])) {
      view_verify_status |= -1;
    }

    mzd_local_free_multiple(rv[1]);
    free(rv[1]);
    mzd_local_free_multiple(rv[0]);
    free(rv[0]);
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

fis_signature_t* fis_sign(public_parameters_t* pp, fis_private_key_t* private_key, char* m) {
  fis_signature_t* sig = (fis_signature_t*)malloc(sizeof(fis_signature_t));
  mzd_t* p             = mzd_local_init(1, pp->lowmc->n);
  sig->proof           = fis_prove(pp->lowmc, private_key->k, p, m, strlen(m));
  mzd_local_free(p);
  return sig;
}

int fis_verify(public_parameters_t* pp, fis_public_key_t* public_key, char* m,
               fis_signature_t* sig) {
  mzd_t* p = mzd_local_init(1, pp->lowmc->n);
  int res  = fis_proof_verify(pp->lowmc, p, public_key->pk, sig->proof, m, strlen(m));
  mzd_local_free(p);
  return res;
}

void fis_free_signature(public_parameters_t* pp, fis_signature_t* signature) {
  free_proof(pp->lowmc, signature->proof);
  free(signature);
}
