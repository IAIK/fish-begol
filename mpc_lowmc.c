#include "mpc_lowmc.h"
#include "mzd_additional.h"
#include "mpc.h"
#include "lowmc_pars.h"

void mpc_sbox_layer(mzd_t **out, mzd_t **in, rci_t m, View *views, int *i) {
  mpc_copy(out, in);
  mzd_t **rvec = mpc_init_random_vector(in[0]->nrows);
  for(rci_t n=out[0]->nrows-3*m; n<out[0]->nrows; n+=3) {
    BIT* x0 = mpc_read_bit(in, n+0);
    BIT* x1 = mpc_read_bit(in, n+1);
    BIT* x2 = mpc_read_bit(in, n+2);
    BIT* r0  = mpc_read_bit(rvec, n+0);
    BIT* r1  = mpc_read_bit(rvec, n+1);    
    BIT* r2  = mpc_read_bit(rvec, n+2);
     
    BIT tmp1[3] = {x1[0], x1[1], x1[2] };
    mpc_and_bit(tmp1,x2,r0);
    mpc_xor_bit(tmp1, x0);
    mpc_write_bit(out, n+0, tmp1);

    BIT tmp2[3] = { x0[0], x0[1], x0[2] };
    mpc_and_bit(tmp2,x2,r1);
    mpc_xor_bit(tmp2,x0);
    mpc_xor_bit(tmp2,x1);
    mpc_write_bit(out, n+1, tmp2);

    BIT tmp3[3] = {x0[0], x0[1], x0[2] };
    mpc_and_bit(tmp3,x1,r2);
    mpc_xor_bit(tmp3,x0);
    mpc_xor_bit(tmp3, x1);
    mpc_xor_bit(tmp3, x2);
    mpc_write_bit(out, n+2, tmp3);

    free(x0);
    free(x1);
    free(x2);
    free(r0);
    free(r1);
    free(r2);
  }
  mpc_free(rvec);

  // TODO: is it enough to store this view here?
  views[*i].s[0] = out[0];
  views[*i].s[1] = out[1];
  views[*i].s[2] = out[2];
  views[*i].r[0] = rvec[0];
  views[*i].r[1] = rvec[1];
  views[*i].r[2] = rvec[2];
  (*i)++;
}

mzd_t **mpc_lowmc_call(lowmc_t *lowmc, mzd_t *p, View *views) {
  int vcnt = 0;
  lowmc_secret_share(lowmc);
  
  views[vcnt].s[0] = lowmc->key[0];
  views[vcnt].s[1] = lowmc->key[1];
  views[vcnt].s[2] = lowmc->key[2];
  views[vcnt].r[0] = 0;
  views[vcnt].r[1] = 0;
  views[vcnt].r[2] = 0;   
  vcnt++;

  mzd_t **c = mpc_init_empty_share_vector(lowmc->n);

  mzd_t **x = mpc_init_empty_share_vector(lowmc->n);
  mzd_t **y = mpc_init_empty_share_vector(lowmc->n);
  mzd_t **z = mpc_init_empty_share_vector(lowmc->n);

  mpc_const_mat_mul(x, lowmc->KMatrix[0], lowmc->key);
  mpc_const_add(x, x, p);

  for(int i=0; i<lowmc->r; i++) {
    mpc_sbox_layer(y, x, lowmc->m, views, &vcnt);
    mpc_const_mat_mul(z, lowmc->LMatrix[i], y);
    mpc_const_add(z, z, lowmc->Constants[i]);
    mzd_t **t = mpc_init_empty_share_vector(lowmc->n);
    mpc_const_mat_mul(t, lowmc->KMatrix[i+1], lowmc->key);
    mpc_add(z, z, t);
    mpc_free(t);
    mpc_copy(x, z);
  }

  views[vcnt].s[0] = lowmc->key[0];
  views[vcnt].s[1] = lowmc->key[1];
  views[vcnt].s[2] = lowmc->key[2];
  views[vcnt].r[0] = 0;
  views[vcnt].r[1] = 0;
  views[vcnt].r[2] = 0;

  mpc_copy(c, x);

  mpc_free(z);
  mpc_free(y);
  mpc_free(x);
  return c;
}

