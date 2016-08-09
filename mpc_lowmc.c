#include "mpc_lowmc.h"
#include "mzd_additional.h"
#include "mpc.h"
#include "lowmc_pars.h"

int _mpc_sbox_layer(mzd_t **out, mzd_t **in, rci_t m, view_t *views, int *i, mzd_t **rvec, unsigned sc, int (*andBitPtr)(BIT*, BIT*, BIT*, view_t*, int*, unsigned, unsigned)) {
  mpc_copy(out, in, sc);
  for(rci_t n=out[0]->nrows-3*m; n<out[0]->nrows; n+=3) {
    BIT* x0 = mpc_read_bit(in, n+0, sc);
    BIT* x1 = mpc_read_bit(in, n+1, sc);
    BIT* x2 = mpc_read_bit(in, n+2, sc);
    BIT* r0  = mpc_read_bit(rvec, n+0, sc);
    BIT* r1  = mpc_read_bit(rvec, n+1, sc);    
    BIT* r2  = mpc_read_bit(rvec, n+2, sc);
     
    BIT tmp1[sc], tmp2[sc], tmp3[sc]; 
    for(unsigned m = 0 ; m < sc ; m++) {
      tmp1[m] = x1[m];
      tmp2[m] = x0[m];
      tmp3[m] = x0[m];
    }
    if(andBitPtr(tmp1, x2, r0, views, i, n, sc) ||
       andBitPtr(tmp2, x2, r1, views, i, n + 1, sc) ||
       andBitPtr(tmp3, x1, r2, views, i, n + 2, sc)) {
      return -1;
    }

    mpc_xor_bit(tmp1, x0, sc);
    mpc_write_bit(out, n + 0, tmp1, sc);
  
    mpc_xor_bit(tmp2, x0, sc);
    mpc_xor_bit(tmp2, x1, sc);
    mpc_write_bit(out, n + 1, tmp2, sc);
 
    mpc_xor_bit(tmp3, x0, sc);
    mpc_xor_bit(tmp3, x1, sc);
    mpc_xor_bit(tmp3, x2, sc);
    mpc_write_bit(out, n + 2, tmp3, sc);

    free(x0);
    free(x1);
    free(x2);
    free(r0);
    free(r1);
    free(r2);
  }

  (*i)++;
  return 0;
}

mzd_t **_mpc_lowmc_call(lowmc_t *lowmc, lowmc_key_t *lowmc_key, mzd_t *p, view_t *views, mzd_t ***rvec, unsigned sc, int (*andBitPtr)(BIT*, BIT*, BIT*, view_t*, int*, unsigned, unsigned), int *status) {
  int vcnt = 0;
  
  for(unsigned i = 0 ; i < sc ; i++) {
    views[vcnt].s[i] = lowmc_key->key[i];
  }  
  vcnt++;

  mzd_t **c = mpc_init_empty_share_vector(lowmc->n, sc);

  mzd_t **x = mpc_init_empty_share_vector(lowmc->n, sc);
  mzd_t **y = mpc_init_empty_share_vector(lowmc->n, sc);
  mzd_t **z = mpc_init_empty_share_vector(lowmc->n, sc);

  mpc_const_mat_mul(x, lowmc->KMatrix[0], lowmc_key->key, sc);
  mpc_const_add(x, x, p, sc);

  mzd_t *r[3];
  for(unsigned i=0; i<lowmc->r; i++) {  
    r[0] = rvec[0][i];
    r[1] = rvec[1][i];
    r[2] = rvec[2][i]; 
    if(_mpc_sbox_layer(y, x, lowmc->m, views, &vcnt, r, sc, andBitPtr)) {
      *status = -1;
      return 0;
    }
    mpc_const_mat_mul(z, lowmc->LMatrix[i], y, sc);
    mpc_const_add(z, z, lowmc->Constants[i], sc);
    mzd_t **t = mpc_init_empty_share_vector(lowmc->n, sc);
    mpc_const_mat_mul(t, lowmc->KMatrix[i+1], lowmc_key->key, sc);
    mpc_add(z, z, t, sc);
    mpc_free(t, sc);
    mpc_copy(x, z, sc);
  }

  for(unsigned i = 0 ; i < sc ; i++) 
    views[vcnt].s[i] = c[i];  
  
  mpc_copy(c, x, sc);

  mpc_free(z, sc);
  mpc_free(y, sc);
  mpc_free(x, sc);
  return c;
}

mzd_t **mpc_lowmc_call(lowmc_t *lowmc, lowmc_key_t *lowmc_key, mzd_t *p, view_t *views, mzd_t ***rvec) {
  return _mpc_lowmc_call(lowmc, lowmc_key, p, views, rvec, 3, &mpc_and_bit, 0); 
}

mzd_t **_mpc_lowmc_call_verify(lowmc_t *lowmc, lowmc_key_t *lowmc_key, mzd_t *p, view_t *views, mzd_t ***rvec, int *status) {
  return _mpc_lowmc_call(lowmc, lowmc_key, p, views, rvec, 2, &mpc_and_bit_verify, status); 
}

int mpc_lowmc_verify(lowmc_t *lowmc, mzd_t *p, view_t *views,  mzd_t ***rvec, view_t v0) {
  //initialize two key shares from v0
  lowmc_key_t *lowmc_key = (lowmc_key_t*)malloc(sizeof(lowmc_key));
  lowmc_key->key = (mzd_t**)malloc(2 * sizeof(mzd_t*));
  lowmc_key->key[0] = v0.s[0];
  lowmc_key->key[1] = v0.s[1];  
  lowmc_key->sharecount = 2;
  
  int status = 0;
  mzd_t ** v = _mpc_lowmc_call_verify(lowmc, lowmc_key, p, views, rvec, &status);
  if(v)
    mpc_free(v, 2);
  
  return status;
}

