#include "mpc_test.h"
#include "lowmc_pars.h"
#include "lowmc.h"
#include "mpc_lowmc.h"
#include "mzd_additional.h"
#include "mpc.h"
#include "time.h"
#include "openssl/rand.h"
#include "randomness.h"

#define NUM_ROUNDS 1

proof_t *prove(lowmc_t *lowmc, lowmc_key_t *lowmc_key, mzd_t *p) { 
  clock_t beginRef = clock(); 
  mzd_t *c         = lowmc_call(lowmc, lowmc_key, p);
  clock_t deltaRef = clock() - beginRef;
  printf("LowMC reference encryption    %4lums\n", deltaRef * 1000 / CLOCKS_PER_SEC);

 
  unsigned char rs[NUM_ROUNDS][3][4];
  unsigned char keys[NUM_ROUNDS][3][16];

  //Generating keys
  clock_t beginCrypto = clock(), deltaCrypto;
  if(RAND_bytes((unsigned char*) keys, NUM_ROUNDS * 3 * 16) != 1) {
    printf("RAND_bytes failed crypto, aborting\n");
    return 0;
  }

  if(RAND_bytes((unsigned char*) rs, NUM_ROUNDS * 3 * 4) != 1) {
    printf("RAND_bytes failed crypto, aborting\n");
    return 0;
  }
  deltaCrypto = clock() - beginCrypto;
  int inMilliCrypto = deltaCrypto * 1000 / CLOCKS_PER_SEC;

  clock_t beginRand = clock();
  mzd_t **rvec[NUM_ROUNDS][3];
  for(unsigned i = 0 ; i < NUM_ROUNDS ; i++) {
    rvec[i][0] = mzd_init_random_vectors_from_seed(keys[i][0], lowmc->n, lowmc->r);
    rvec[i][1] = mzd_init_random_vectors_from_seed(keys[i][1], lowmc->n, lowmc->r);
    rvec[i][2] = mzd_init_random_vectors_from_seed(keys[i][2], lowmc->n, lowmc->r);
  }
  clock_t deltaRand = clock() - beginRand;
  printf("MPC randomess generation      %4lums\n", deltaRand * 1000 / CLOCKS_PER_SEC);

  clock_t beginShare = clock();  
  view_t views[NUM_ROUNDS][2 + lowmc->r];
  for(unsigned i = 0 ; i < NUM_ROUNDS ; i++)
    for(unsigned n = 0 ; n < 2 + lowmc->r ; n++)
      for(unsigned m = 0 ; m < 3 ; m++)
        views[i][n].s[m] = mzd_init(lowmc->n, 1);
  lowmc_secret_share(lowmc, lowmc_key);
  clock_t deltaShare = clock() - beginShare;
  printf("MPC secret sharing            %4lums\n", deltaShare * 1000 / CLOCKS_PER_SEC);
  
  clock_t beginLowmc = clock();
  mzd_t **c_mpc = mpc_lowmc_call(lowmc, lowmc_key, p, views[0], rvec[0]);
  clock_t deltaLowmc = clock() - beginLowmc;
  printf("MPC LowMC encryption          %4lums\n", deltaLowmc * 1000 / CLOCKS_PER_SEC);
  
  mzd_t *c_mpcr  = mpc_reconstruct_from_share(c_mpc); 
  printf("\n");
  
  if(mzd_cmp(c, c_mpcr) == 0)
    printf("[ OK ] MPC ciphertext matches with reference implementation.\n");
  else
    printf("[FAIL] MPC ciphertext does not match reference implementation.\n");

  if(!mpc_lowmc_verify(lowmc, p, views[0], rvec[0], views[0][0]) && mzd_cmp(c_mpc[0], views[0][1 + lowmc->r].s[0]) == 0)
    printf("[ OK ] First share matches with reconstructed share in proof verification.\n");
  else
    printf("[FAIL] Verification failed.\n");   
 
  mzd_free(p);
  mzd_free(c);
  mpc_free(c_mpc, 3);
  mzd_free(c_mpcr);

  for(unsigned j = 0 ; j < NUM_ROUNDS ; j++) 
    for(unsigned i  = 0 ; i < 3 ; i++) 
      mpc_free(rvec[j][i], lowmc->r);
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

  prove(lowmc, lowmc_key, p); 
  
  
  
  lowmc_free(lowmc, lowmc_key);
   
  //test_mpc_share();
  //test_mpc_add();

  cleanup_EVP();
  return 0;
}
