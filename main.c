#include "mpc_test.h"
#include "lowmc_pars.h"
#include "lowmc.h"
#include "mpc_lowmc.h"
#include "mzd_additional.h"
#include "mpc.h"
#include "time.h"

int main(int argc, char **argv) {
  lowmc_t *lowmc         = lowmc_init(63, 256, 12, 128);
  lowmc_key_t *lowmc_key = lowmc_keygen(lowmc);
  mzd_t *p               = mzd_init_random_vector(256); 
  mzd_t *c               = lowmc_call(lowmc, lowmc_key, p);


  view_t views[2 + lowmc->r];

  clock_t beginRand = clock();
  mzd_t ***rvec = (mzd_t***)malloc(lowmc->r * sizeof(mzd_t**));
  for(unsigned i = 0 ; i < lowmc->r ; i++)
    rvec[i] = mpc_init_random_vector(lowmc->n, 3);
  clock_t deltaRand = clock() - beginRand;
  printf("Randomess generated...%lums\n", deltaRand * 1000 / CLOCKS_PER_SEC);

  lowmc_secret_share(lowmc, lowmc_key);
  clock_t beginLowmc = clock();
  mzd_t **c_mpc  = mpc_lowmc_call(lowmc, lowmc_key, p, views, rvec, 3);
  clock_t deltaLowmc = clock() - beginLowmc;

  printf("Secret shared LowMC execution...%lums\n", deltaLowmc * 1000 / CLOCKS_PER_SEC);
  mzd_t *c_mpcr  = mpc_reconstruct_from_share(c_mpc); 

  //todo replace views[0] with view where one slot is actually missing.
  view_t viewsVrfy[2 + lowmc->r];
  mpc_lowmc_verify(lowmc, p, viewsVrfy, rvec, views[0]);
  
  if(mzd_cmp(c, c_mpcr) == 0)
    printf("Ciphertext matches with reference implementation.\n");

  if(mzd_cmp(c_mpc[0], viewsVrfy[1 + lowmc->r].s[0]) == 0)
    printf("First share matches with reconstructed share in proof verification.\n");

  mzd_free(p);
  mzd_free(c);
  mpc_free(c_mpc, 3);
  mzd_free(c_mpcr);
  for(unsigned i  = 0 ; i < lowmc->r ; i++) 
    mpc_free(rvec[i], 3);
  free(rvec);

  lowmc_free(lowmc, lowmc_key);
   
  //test_mpc_share();
  //test_mpc_add();
  
  return 0;
}
