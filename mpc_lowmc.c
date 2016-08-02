#include "mpc_lowmc.h"
#include "mzd_additional.h"
#include "mpc.h"
#include "lowmc_pars.h"

void mpc_sbox_layer(mzd_t **out, mzd_t **in, rci_t m, view_t *views, int *i, int sc) {
  mpc_copy(out, in, sc);
  // TODO move randomness to method signature
  mzd_t **rvec = mpc_init_random_vector(in[0]->nrows, sc);
  for(rci_t n=out[0]->nrows-3*m; n<out[0]->nrows; n+=3) {
    BIT* x0 = mpc_read_bit(in, n+0, sc);
    BIT* x1 = mpc_read_bit(in, n+1, sc);
    BIT* x2 = mpc_read_bit(in, n+2, sc);
    BIT* r0  = mpc_read_bit(rvec, n+0, sc);
    BIT* r1  = mpc_read_bit(rvec, n+1, sc);    
    BIT* r2  = mpc_read_bit(rvec, n+2, sc);
     
    BIT tmp1[sc]; 
    for(unsigned i = 0 ; i < sc ; i++)
      tmp1[i] = x1[i];
    mpc_and_bit(tmp1,x2,r0, sc);
    mpc_xor_bit(tmp1, x0, sc);
    mpc_write_bit(out, n+0, tmp1, sc);

    BIT tmp2[sc];
    for(unsigned i = 0 ; i < sc ; i++)
      tmp2[i] = x0[i];
    mpc_and_bit(tmp2,x2,r1, sc);
    mpc_xor_bit(tmp2,x0, sc);
    mpc_xor_bit(tmp2,x1, sc);
    mpc_write_bit(out, n+1, tmp2, sc);

    BIT tmp3[sc]; 
    for(unsigned i = 0 ; i < sc ; i++)
      tmp3[i] = x0[i];
    mpc_and_bit(tmp3,x1,r2, sc);
    mpc_xor_bit(tmp3,x0, sc);
    mpc_xor_bit(tmp3, x1, sc);
    mpc_xor_bit(tmp3, x2, sc);
    mpc_write_bit(out, n+2, tmp3, sc);

    free(x0);
    free(x1);
    free(x2);
    free(r0);
    free(r1);
    free(r2);
  }
  mpc_free(rvec);

  for(unsigned j = 0 ; j < sc ; j++) {
    views[*i].s[j] = out[j];
    views[*i].r[j] = rvec[j];
  }
  (*i)++;
}

mzd_t **mpc_lowmc_call(lowmc_t *lowmc, mzd_t *p, view_t *views, unsigned sc) {
  int vcnt = 0;
  lowmc_secret_share(lowmc);
  
  for(unsigned i = 0 ; i < sc ; i++) {
    views[vcnt].s[i] = lowmc->key[i];
    views[vcnt].r[i] = 0; 
  }  
  vcnt++;

  mzd_t **c = mpc_init_empty_share_vector(lowmc->n, sc);

  mzd_t **x = mpc_init_empty_share_vector(lowmc->n, sc);
  mzd_t **y = mpc_init_empty_share_vector(lowmc->n, sc);
  mzd_t **z = mpc_init_empty_share_vector(lowmc->n, sc);

  mpc_const_mat_mul(x, lowmc->KMatrix[0], lowmc->key, sc);
  mpc_const_add(x, x, p, sc);

  for(int i=0; i<lowmc->r; i++) {
    mpc_sbox_layer(y, x, lowmc->m, views, &vcnt, sc);
    mpc_const_mat_mul(z, lowmc->LMatrix[i], y, sc);
    mpc_const_add(z, z, lowmc->Constants[i], sc);
    mzd_t **t = mpc_init_empty_share_vector(lowmc->n, sc);
    mpc_const_mat_mul(t, lowmc->KMatrix[i+1], lowmc->key, sc);
    mpc_add(z, z, t);
    mpc_free(t);
    mpc_copy(x, z, sc);
  }

  for(unsigned i = 0 ; i < sc ; i++) {
    views[vcnt].s[i] = c[i];  
    views[vcnt].r[i] = 0;
  }

  mpc_copy(c, x, sc);

  mpc_free(z);
  mpc_free(y);
  mpc_free(x);
  return c;
}

unsigned mpc_lowmc_verify(lowmc_t *lowmc, mzd_t *p, view_t *views) {
  // TODO remove key from lowmc struct
  
}

