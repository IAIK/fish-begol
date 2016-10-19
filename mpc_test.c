#include "mpc_test.h"
#include "m4ri/m4ri.h"
#include "mpc.h"
#include "mzd_additional.h"

void test_mpc_share() {
  mzd_t* t1    = mzd_init_random_vector(10);
  mzd_t** s1   = mpc_init_share_vector(t1);
  mzd_t* t1cmb = mpc_reconstruct_from_share(NULL, s1);

  if (mzd_cmp(t1, t1cmb) == 0)
    printf("Share test successful.\n");

  mzd_local_free(t1);
  for (unsigned i = 0; i < 3; i++)
    mzd_local_free(s1[i]);
  mzd_local_free(t1cmb);
}

void test_mpc_add() {
  mzd_t* t1  = mzd_init_random_vector(10);
  mzd_t* t2  = mzd_init_random_vector(10);
  mzd_t* res = mzd_add(0, t1, t2);

  mzd_t** s1   = mpc_init_share_vector(t1);
  mzd_t** s2   = mpc_init_share_vector(t2);
  mzd_t** ress = mpc_init_empty_share_vector(10, 3);
  mpc_add(ress, s1, s2, 3);

  mzd_t* cmp = mpc_reconstruct_from_share(NULL, ress);

  if (mzd_cmp(res, cmp) == 0)
    printf("Shared add test successful.\n");

  mzd_local_free(t1);
  mzd_local_free(t2);
  mzd_local_free(res);
  for (unsigned i = 0; i < 3; i++) {
    mzd_local_free(s1[i]);
    mzd_local_free(s2[i]);
    mzd_local_free(ress[i]);
  }
  mzd_local_free(cmp);
}
