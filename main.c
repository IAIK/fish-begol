#include "mpc_test.h"
#include "lowmc_pars.h"
#include "lowmc.h"
#include "mpc_lowmc.h"
#include "mzd_additional.h"
#include "mpc.h"

int main(int argc, char **argv) {
  lowmc_t *lowmc = lowmc_init(63, 256, 12, 128);
  mzd_t *p       = mzd_init_random_vector(256); 
  mzd_t *c       = lowmc_call(lowmc, p);
  view_t views[2 + lowmc->r];
  mzd_t **c_mpc  = mpc_lowmc_call(lowmc, p, views, 3);
  mzd_t *c_mpcr  = mpc_reconstruct_from_share(c_mpc); 

  if(mzd_cmp(c, c_mpcr) == 0)
    printf("Success.\n");

  mzd_free(p);
  mzd_free(c);
  mpc_free(c_mpc);
  mzd_free(c_mpcr);

  lowmc_free(lowmc);
   
  //test_mpc_share();
  //test_mpc_add();
  
  return 0;
}
