#include "mpc_test.h"
#include "lowmc_pars.h"
#include "lowmc.h"
#include "mpc_lowmc.h"
#include "mzd_additional.h"
#include "mpc.h"
#include "time.h"
#include "openssl/rand.h"
#include "openssl/sha.h"
#include "randomness.h"
#include "hashing_util.h"

proof_t *prove(lowmc_t *lowmc, lowmc_key_t *lowmc_key, mzd_t *p) { 
  clock_t beginRef = clock(); 
  mzd_t *c         = lowmc_call(lowmc, lowmc_key, p);
  clock_t deltaRef = clock() - beginRef;
  printf("LowMC reference encryption    %4lums\n", deltaRef * 1000 / CLOCKS_PER_SEC);

  unsigned char r[NUM_ROUNDS][3][4];
  unsigned char keys[NUM_ROUNDS][3][16];

  //Generating keys
  clock_t beginCrypto = clock(), deltaCrypto;
  if(RAND_bytes((unsigned char*) keys, NUM_ROUNDS * 3 * 16) != 1) {
    printf("RAND_bytes failed crypto, aborting\n");
    return 0;
  }

  if(RAND_bytes((unsigned char*) r, NUM_ROUNDS * 3 * 4) != 1) {
    printf("RAND_bytes failed crypto, aborting\n");
    return 0;
  }
  deltaCrypto = clock() - beginCrypto;
  int inMilliCrypto = deltaCrypto * 1000 / CLOCKS_PER_SEC;

  clock_t beginRand = clock();
  mzd_t **rvec[NUM_ROUNDS][3];
  #pragma omp parallel for
  for(unsigned i = 0 ; i < NUM_ROUNDS ; i++) {
    rvec[i][0] = mzd_init_random_vectors_from_seed(keys[i][0], lowmc->n, lowmc->r);
    rvec[i][1] = mzd_init_random_vectors_from_seed(keys[i][1], lowmc->n, lowmc->r);
    rvec[i][2] = mzd_init_random_vectors_from_seed(keys[i][2], lowmc->n, lowmc->r);
  }
  clock_t deltaRand = clock() - beginRand;
  printf("MPC randomess generation      %4lums\n", deltaRand * 1000 / CLOCKS_PER_SEC);

  clock_t beginShare = clock();  
  view_t views[NUM_ROUNDS][2 + lowmc->r];
  #pragma omp parallel for
  for(unsigned i = 0 ; i < NUM_ROUNDS ; i++)
    for(unsigned n = 0 ; n < 2 + lowmc->r ; n++) {
      views[i][n].s = (mzd_t**)malloc(3 * sizeof(mzd_t*));
      for(unsigned m = 0 ; m < 3 ; m++)
        views[i][n].s[m] = mzd_init(lowmc->n, 1);
    }
  lowmc_secret_share(lowmc, lowmc_key);
  clock_t deltaShare = clock() - beginShare;
  printf("MPC secret sharing            %4lums\n", deltaShare * 1000 / CLOCKS_PER_SEC);
  
  clock_t beginLowmc = clock();
  mzd_t **c_mpc[NUM_ROUNDS];
  #pragma omp parallel for
  for(unsigned i = 0 ; i < NUM_ROUNDS ; i++)
    c_mpc[i] = mpc_lowmc_call(lowmc, lowmc_key, p, views[i], rvec[i]);
  clock_t deltaLowmc = clock() - beginLowmc;
  printf("MPC LowMC encryption          %4lums\n", deltaLowmc * 1000 / CLOCKS_PER_SEC);
  
  clock_t beginHash = clock();
  unsigned char hashes[NUM_ROUNDS][3][SHA256_DIGEST_LENGTH];
  #pragma omp parallel for
  for(unsigned i = 0 ; i < NUM_ROUNDS ; i++) {
    H(keys[i][0], views[i], 0, 2 + lowmc->r, r[i][0], hashes[i][0]);
    H(keys[i][1], views[i], 1, 2 + lowmc->r, r[i][1], hashes[i][1]);
    H(keys[i][2], views[i], 2, 2 + lowmc->r, r[i][2], hashes[i][2]);
  }
  clock_t deltaHash = clock() - beginHash;
  printf("Hashing views                 %4lums\n", deltaHash * 1000 / CLOCKS_PER_SEC);

  clock_t beginCh = clock();
  int ch[NUM_ROUNDS];
  H3(hashes, ch);
  clock_t deltaCh = clock() - beginCh;
  printf("Generating challenge          %4lums\n", deltaCh * 1000 / CLOCKS_PER_SEC);

  mzd_t *c_mpcr  = mpc_reconstruct_from_share(c_mpc[0]); 
  printf("\n");
  
  if(mzd_cmp(c, c_mpcr) == 0)
    printf("[ OK ] MPC ciphertext matches with reference implementation.\n");
  else
    printf("[FAIL] MPC ciphertext does not match reference implementation.\n");

  proof_t *proof = (proof_t*)malloc(sizeof(proof_t));

  proof->views = (view_t**)malloc(NUM_ROUNDS * sizeof(view_t*));
  
  proof->r = (unsigned char***)malloc(NUM_ROUNDS * sizeof(unsigned char**));
  proof->keys = (unsigned char***)malloc(NUM_ROUNDS * sizeof(unsigned char**));
  proof->hashes = (unsigned char***)malloc(NUM_ROUNDS * sizeof(unsigned char**));
    
  proof->ch = (unsigned*)malloc(NUM_ROUNDS * sizeof(unsigned));
  memcpy(proof->ch, ch, NUM_ROUNDS * sizeof(unsigned));

  for(unsigned i = 0 ; i < NUM_ROUNDS ; i++) { 
    int a = ch[i];
    int b = (a + 1) % 3;

    proof->r[i] = (unsigned char**)malloc(2 * sizeof(unsigned char*));
    proof->r[i][0] = (unsigned char*)malloc(4 * sizeof(unsigned char));
    proof->r[i][1] = (unsigned char*)malloc(4 * sizeof(unsigned char));
    memcpy(proof->r[i][0], r[i][a], 4 * sizeof(char));
    memcpy(proof->r[i][1], r[i][b], 4 * sizeof(char));

    proof->keys[i] = (unsigned char**)malloc(2 * sizeof(unsigned char*));
    proof->keys[i][0] = (unsigned char*)malloc(16 * sizeof(unsigned char));
    proof->keys[i][1] = (unsigned char*)malloc(16 * sizeof(unsigned char));
    memcpy(proof->keys[i][0], keys[i][a], 16 * sizeof(char));
    memcpy(proof->keys[i][1], keys[i][b], 16 * sizeof(char));

    proof->hashes[i] = (unsigned char**)malloc(2 * sizeof(unsigned char*));
    proof->hashes[i][0] = (unsigned char*)malloc(SHA256_DIGEST_LENGTH * sizeof(unsigned char));
    proof->hashes[i][1] = (unsigned char*)malloc(SHA256_DIGEST_LENGTH * sizeof(unsigned char));
    memcpy(proof->hashes[i][0], hashes[i][a], SHA256_DIGEST_LENGTH * sizeof(char));
    memcpy(proof->hashes[i][1], hashes[i][b], SHA256_DIGEST_LENGTH * sizeof(char));
   
    proof->views[i] = (view_t*)malloc((2 + lowmc->r) * sizeof(view_t));
    for(unsigned j = 0 ; j < 2 + lowmc->r ; j++) {
      proof->views[i][j].s = (mzd_t**)malloc(2 * sizeof(mzd_t*));
      proof->views[i][j].s[0] = views[i][j].s[a];
      proof->views[i][j].s[1] = views[i][j].s[b];
      //mzd_free(views[i][j].s[(ch[i] + 2) % 3]);
    }
  }

  mzd_free(c);
  mzd_free(c_mpcr);

  #pragma omp parallel for
  for(unsigned j = 0 ; j < NUM_ROUNDS ; j++) {
    mpc_free(c_mpc[j], 3);
    for(unsigned i  = 0 ; i < 3 ; i++) 
      mpc_free(rvec[j][i], lowmc->r);
  }

  return proof;
}

int verify(lowmc_t *lowmc, mzd_t *p, proof_t *prf) {
  clock_t beginHash = clock();
  unsigned char hash[SHA256_DIGEST_LENGTH];
  #pragma omp parallel for
  for(unsigned i = 0 ; i < NUM_ROUNDS ; i++) {
    H(prf->keys[i][0], prf->views[i], 0, 2 + lowmc->r, prf->r[i][0], hash);
    if(0 != memcmp(hash, prf->hashes[i][0], SHA256_DIGEST_LENGTH)) {
      printf("Error verifying hash\n");
      exit(-1);
    } 
    H(prf->keys[i][1], prf->views[i], 1, 2 + lowmc->r, prf->r[i][1], hash);
    if(0 != memcmp(hash, prf->hashes[i][1], SHA256_DIGEST_LENGTH)) {
      printf("Error verifying hash\n");
      exit(-1);
    }
  }
  clock_t deltaHash = clock() - beginHash;
  printf("Verifying hashes              %4lums\n", deltaHash * 1000 / CLOCKS_PER_SEC);

  mzd_t **rv[NUM_ROUNDS][2];
  rv[0][0] = mzd_init_random_vectors_from_seed(prf->keys[0][0], lowmc->n, lowmc->r);
  rv[0][1] = mzd_init_random_vectors_from_seed(prf->keys[0][1], lowmc->n, lowmc->r);
  
  mzd_t *c_ch = mzd_init(lowmc->n, 1);
  mzd_copy(c_ch, prf->views[0][lowmc->r + 1].s[0]);

  if(!mpc_lowmc_verify(lowmc, p, prf->views[0], rv[0], prf->ch[0]) && mzd_cmp(c_ch, prf->views[0][1 + lowmc->r].s[0]) == 0)
    printf("[ OK ] Share %d matches with reconstructed share in proof verification.\n", prf->ch[0]);
  else
    printf("[FAIL] Verification failed.\n");   
  
  mzd_free(c_ch);
}

int main(int argc, char **argv) {
  init_EVP();
  
  clock_t beginSetup = clock();
  lowmc_t *lowmc     = lowmc_init(63, 256, 12, 128);
  clock_t deltaSetup = clock() - beginSetup;
  printf("LowMC setup                   %4lums\n", deltaSetup * 1000 / CLOCKS_PER_SEC);

  clock_t beginKeygen    = clock();
  lowmc_key_t *lowmc_key = lowmc_keygen(lowmc);
  clock_t deltaKeygen    = clock() - beginKeygen;
  printf("LowMC key generation          %4lums\n", deltaKeygen * 1000 / CLOCKS_PER_SEC);

  mzd_t *p = mzd_init_random_vector(256);  

  proof_t *prf = prove(lowmc, lowmc_key, p); 
  
  verify(lowmc, p, prf);
  
  
  lowmc_free(lowmc, lowmc_key);
  mzd_free(p);

  cleanup_EVP();
  return 0;
}
