#include "signature_fis.h"
#include "lowmc.h"
#include "hashing_util.h"
#include "mpc.h"
#include "mpc_lowmc.h"
#include "randomness.h"
#include "timing.h"

unsigned fis_compute_sig_size(unsigned m, unsigned n, unsigned r, unsigned k) {
  unsigned first_view_size = k;
  unsigned full_view_size  = n;
  unsigned int_view_size   = 3 * m;
  unsigned views           = 2 * (r * int_view_size + first_view_size + 
                             full_view_size) + 3 * full_view_size;
  return (NUM_ROUNDS * (8 * SHA256_DIGEST_LENGTH + 8 * 40 + views) + 
         ((NUM_ROUNDS + 3) / 4) + 7) / 8; 
}

unsigned char *fis_sig_to_char_array(public_parameters_t *pp, fis_signature_t *sig, unsigned *len) {
  return proof_to_char_array(pp->lowmc, sig->proof, len, true);
}

fis_signature_t *fis_sig_from_char_array(public_parameters_t *pp, unsigned char *data) {
  unsigned len = 0;
  fis_signature_t *sig = (fis_signature_t*)malloc(sizeof(fis_signature_t));
  sig->proof = proof_from_char_array(pp->lowmc, 0, data, &len, true);
  return sig;
}


void fis_create_key(public_parameters_t* pp, fis_private_key_t* private_key,
                           fis_public_key_t* public_key) {
  TIME_FUNCTION;

  START_TIMING;
  private_key->k           = lowmc_keygen(pp->lowmc);
  END_TIMING(timing_and_size->gen.keygen);

  START_TIMING;
  mzd_t *p            = mzd_init(1, pp->lowmc->n);
  public_key->pk      = lowmc_call(pp->lowmc, private_key->k, p);
  mzd_free(p);
  END_TIMING(timing_and_size->gen.pubkey);
}

void fis_destroy_key(fis_private_key_t* private_key, fis_public_key_t* public_key) {
  lowmc_key_free(private_key->k);
  private_key->k = NULL;

  mzd_free(public_key->pk);
  public_key->pk = NULL;
}

static proof_t* fis_prove(mpc_lowmc_t* lowmc, lowmc_key_t* lowmc_key, mzd_t* p, char *m, unsigned m_len) {
  TIME_FUNCTION;

  unsigned char r[NUM_ROUNDS][3][4];
  unsigned char keys[NUM_ROUNDS][3][16];
  unsigned char secret_sharing_key[16];

  // Generating keys
  START_TIMING;
  if (rand_bytes((unsigned char*)keys, sizeof(keys)) != 1 || rand_bytes((unsigned char*)r, sizeof(r)) != 1 || rand_bytes(secret_sharing_key, sizeof(secret_sharing_key)) != 1) {
#ifdef VERBOSE
    printf("rand_bytes failed crypto, aborting\n");
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
  END_TIMING(timing_and_size->sign.rand);

  START_TIMING;
  view_t *views[NUM_ROUNDS];
  init_view(lowmc, views);

  aes_prng_t* aes_prng = aes_prng_init(secret_sharing_key);
  mzd_shared_t s[NUM_ROUNDS];
  for(int i = 0 ; i < NUM_ROUNDS ; i++) {
    mzd_shared_init(&s[i], lowmc_key);
    mzd_shared_share_prng(&s[i], aes_prng);
  }
  aes_prng_free(aes_prng);
  END_TIMING(timing_and_size->sign.secret_sharing);

  START_TIMING;
  mzd_t*** c_mpc     = (mzd_t***)malloc(NUM_ROUNDS * sizeof(mzd_t**));
#pragma omp parallel for
  for (unsigned i    = 0; i < NUM_ROUNDS; i++)
    c_mpc[i]         = mpc_lowmc_call(lowmc, &s[i], p, views[i], rvec[i]);
  END_TIMING(timing_and_size->sign.lowmc_enc);

  START_TIMING;
  unsigned char hashes[NUM_ROUNDS][3][SHA256_DIGEST_LENGTH];
#pragma omp parallel for
  for (unsigned i = 0; i < NUM_ROUNDS; i++) {
    H(keys[i][0], c_mpc[i], views[i], 0, 2 + lowmc->r, r[i][0], hashes[i][0]);
    H(keys[i][1], c_mpc[i], views[i], 1, 2 + lowmc->r, r[i][1], hashes[i][1]);
    H(keys[i][2], c_mpc[i], views[i], 2, 2 + lowmc->r, r[i][2], hashes[i][2]);
  }
  END_TIMING(timing_and_size->sign.views);

  START_TIMING;
  int ch[NUM_ROUNDS];
  fis_H3(hashes, m, m_len, ch);
  END_TIMING(timing_and_size->sign.challenge);

  proof_t* proof = create_proof(0, lowmc, hashes, ch, r, keys, c_mpc, views);

#pragma omp parallel for
  for (unsigned j = 0; j < NUM_ROUNDS; j++) {
    mzd_shared_clear(&s[j]);
    for (unsigned i = 0; i < 3; i++)
      mpc_free(rvec[j][i], lowmc->r);
    for (unsigned i = 0; i < lowmc->r + 2; i++) {
      free(views[j][i].s);
    }
  }

  return proof;
}

static int fis_proof_verify(mpc_lowmc_t* lowmc, mzd_t* p, mzd_t* c, proof_t* prf, char *m, unsigned m_len) {
  TIME_FUNCTION;

  START_TIMING;
  int ch[NUM_ROUNDS];
  unsigned char hash[NUM_ROUNDS][2][SHA256_DIGEST_LENGTH];
#pragma omp parallel for
  for (unsigned i = 0; i < NUM_ROUNDS; i++) {
    H(prf->keys[i][0], prf->y[i], prf->views[i], 0, 2 + lowmc->r, prf->r[i][0], hash[i][0]);
    H(prf->keys[i][1], prf->y[i], prf->views[i], 1, 2 + lowmc->r, prf->r[i][1], hash[i][1]);
  }
  fis_H3_verify(hash, prf->hashes, prf->ch, m, m_len, ch);
  END_TIMING(timing_and_size->verify.challenge);

  START_TIMING;
  int reconstruct_status = 0;
  for (int i = 0; i < NUM_ROUNDS; i++) {
    mzd_t* c_mpcr = mpc_reconstruct_from_share(prf->y[0]);
    if (mzd_cmp(c, c_mpcr) != 0)
      reconstruct_status = -1;
    mzd_free(c_mpcr);
  }
  END_TIMING(timing_and_size->verify.output_shares);

  START_TIMING;
  int output_share_status = 0;
  for (int i = 0; i < NUM_ROUNDS; i++)
    if (mzd_cmp(prf->y[i][ch[i]], prf->views[i][lowmc->r + 1].s[0]) ||
        mzd_cmp(prf->y[i][(ch[i] + 1) % 3], prf->views[i][lowmc->r + 1].s[1]))
      output_share_status = -1;
  END_TIMING(timing_and_size->verify.output_views);

  START_TIMING;
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

fis_signature_t *fis_sign(public_parameters_t* pp, fis_private_key_t* private_key, char *m) {
  fis_signature_t *sig = (fis_signature_t*)malloc(sizeof(fis_signature_t));
  mzd_t *p = mzd_init(1, pp->lowmc->n);
  sig->proof = fis_prove(pp->lowmc, private_key->k, p, m, strlen(m));
  mzd_free(p);
  return sig;
}

int fis_verify(public_parameters_t* pp, fis_public_key_t *public_key, char *m, fis_signature_t *sig) {
  mzd_t *p = mzd_init(1, pp->lowmc->n);
  int res = fis_proof_verify(pp->lowmc, p, public_key->pk, sig->proof, m, strlen(m));
  mzd_free(p);
  return res;
}

void fis_free_signature(public_parameters_t* pp, fis_signature_t *signature) {
  free_proof(pp->lowmc, signature->proof);
  free(signature);
}


