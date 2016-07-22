#include "mpc_lowmc.h"
#include "mzd_additional.h"
#include "mpc.h"
#include "lowmc_pars.h"

void mpc_sbox_layer(mzd_t **out, mzd_t **in, rci_t m) {
  mpc_copy(out, in);
  mzd_t **rvec = mpc_init_random_vector(in[0]->nrows);
  for(rci_t n=out[0]->nrows-3*m; n<out[0]->nrows; n+=3) {
    BIT* x0 = mpc_read_bit(in, n+0);
    BIT* x1 = mpc_read_bit(in, n+1);
    BIT* x2 = mpc_read_bit(in, n+2);
    BIT* r0  = mpc_read_bit(rvec, n+0);
    BIT* r1  = mpc_read_bit(rvec, n+1);    
    BIT* r2  = mpc_read_bit(rvec, n+2);
    
    // fix memory leaks due to nested calls
    mpc_write_bit(out, n+0, mpc_xor_bit(mpc_and_bit(x1,x2,r0), x0));
    mpc_write_bit(out, n+1, mpc_xor_bit(mpc_xor_bit(mpc_and_bit(x0,x2,r1),x0),x1));
    mpc_write_bit(out, n+2, mpc_xor_bit(mpc_xor_bit(mpc_xor_bit(mpc_and_bit(x0,x1,r2),x0), x1), x2));
  }
}

mzd_t **mpc_lowmc_call(lowmc_t *lowmc, mzd_t *p) {
  lowmc_secret_share(lowmc);

  mzd_t **c = mpc_init_empty_share_vector(lowmc->n);

  mzd_t **x = mpc_init_plain_share_vector(p);
  mzd_t **y = mpc_init_empty_share_vector(lowmc->n);
  mzd_t **z = mpc_init_empty_share_vector(lowmc->n);

  mpc_const_mat_addmul(x, lowmc->KMatrix[0], lowmc->key);

  for(int i=0; i<lowmc->r; i++) {
    mpc_sbox_layer(y, x, lowmc->m);
    mpc_const_mat_mul(z, lowmc->LMatrix[i], y);
    mpc_const_add(z, z, lowmc->Constants[i]);
    mpc_const_mat_addmul(z, lowmc->KMatrix[i+1], lowmc->key);
    mpc_copy(x, z);
  }

  mpc_copy(c, x);

  mpc_free(z);
  mpc_free(y);
  mpc_free(x);
  return c;
}

