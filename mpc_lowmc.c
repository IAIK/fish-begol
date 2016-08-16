#include "mpc_lowmc.h"
#include "mzd_additional.h"
#include "mpc.h"
#include "lowmc_pars.h"

int _mpc_sbox_layer_bitsliced(mzd_t **out, mzd_t **in, rci_t m, view_t *views, int *i, mzd_t **rvec, unsigned sc, 
    mzd_t** (*andPtr)(mzd_t **, mzd_t **, mzd_t **, mzd_t**, view_t*, int*, unsigned, unsigned, mzd_t**), mask_t *mask, sbox_vars_t *vars) {
  if(in[0]->ncols - 3 * m < 2) {
    printf("Bitsliced implementation requires in->ncols - 3 * m >= 2\n");
    return 0;
  }

  mpc_copy(out, in, sc);
  mpc_and_const(out, out, mask->mask, sc);

  mpc_and_const(vars->x0m, in, mask->x0, sc);
  mpc_and_const(vars->x1m, in, mask->x1, sc);   
  mpc_and_const(vars->x2m, in, mask->x2, sc);   
  mpc_and_const(vars->r0m, rvec, mask->x0, sc);
  mpc_and_const(vars->r1m, rvec, mask->x1, sc);   
  mpc_and_const(vars->r2m, rvec, mask->x2, sc);   

  mpc_shift_left(vars->x0s, vars->x0m, 2, 0, sc);
  mpc_shift_left(vars->r0s, vars->r0m, 2, 0, sc);
  
  mpc_shift_left(vars->x1s, vars->x1m, 1, 0, sc);
  mpc_shift_left(vars->r1s, vars->r1m, 1, 0, sc);

  andPtr(vars->r0m, vars->x0s, vars->x1s, vars->r2m, views, i, 0, sc, vars->v);  
  andPtr(vars->r2m, vars->x1s, vars->x2m, vars->r0s, views, i, 2, sc, vars->v);
  andPtr(vars->r1m, vars->x0s, vars->x2m, vars->r1s, views, i, 1, sc, vars->v);

  mpc_xor(vars->r2m, vars->r2m, vars->x0s, sc);
 
  mpc_xor(vars->r1m, vars->r1m, vars->x0s, sc);
  mpc_xor(vars->r1m, vars->r1m, vars->x1s, sc);

  mpc_xor(vars->r0m, vars->r0m, vars->x0s, sc);
  mpc_xor(vars->r0m, vars->r0m, vars->x1s, sc);
  mpc_xor(vars->r0m, vars->r0m, vars->x2m, sc);

  mpc_shift_right(vars->x0s, vars->r2m, 2, 0, sc);
  mpc_shift_right(vars->x1s, vars->r1m, 1, 0, sc);

  mpc_xor(out, out, vars->r0m, sc);
  mpc_xor(out, out, vars->x0s, sc);
  mpc_xor(out, out, vars->x1s, sc);

  (*i)++;
  return 0;
}

int _mpc_sbox_layer(mzd_t **out, mzd_t **in, rci_t m, view_t *views, int *i, mzd_t **rvec, unsigned sc, int (*andBitPtr)(BIT*, BIT*, BIT*, view_t*, int*, unsigned, unsigned)) {
  mpc_copy(out, in, sc);
  for(rci_t n=out[0]->ncols-3*m; n<out[0]->ncols; n+=3) {
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

mzd_t **_mpc_lowmc_call(lowmc_t *lowmc, lowmc_key_t *lowmc_key, mzd_t *p, view_t *views, mzd_t ***rvec, unsigned sc, unsigned ch, int (*andBitPtr)(BIT*, BIT*, BIT*, view_t*, int*, unsigned, unsigned), int *status) {
  int vcnt = 0;
  
  for(unsigned i = 0 ; i < sc ; i++) 
    mzd_copy(views[vcnt].s[i], lowmc_key->key[i]);
  vcnt++;

  mzd_t **c = mpc_init_empty_share_vector(lowmc->n, sc);

  mzd_t **x = mpc_init_empty_share_vector(lowmc->n, sc);
  mzd_t **y = mpc_init_empty_share_vector(lowmc->n, sc);
  mzd_t **z = mpc_init_empty_share_vector(lowmc->n, sc);

  mpc_const_mat_mul(x, lowmc->KMatrix[0], lowmc_key->key, sc);
  mpc_const_add(x, x, p, sc, ch);

  mzd_t *r[3];
  for(unsigned i = 0 ; i < lowmc->r ; i++) {  
    for(unsigned j = 0 ; j < sc ; j++)
      r[j] = rvec[j][i]; 
    if(_mpc_sbox_layer(y, x, lowmc->m, views, &vcnt, r, sc, andBitPtr)) {
      *status = -1;
      return 0;
    }
    mpc_const_mat_mul(z, lowmc->LMatrix[i], y, sc);
    mpc_const_add(z, z, lowmc->Constants[i], sc, ch);
    mzd_t **t = mpc_init_empty_share_vector(lowmc->n, sc);
    mpc_const_mat_mul(t, lowmc->KMatrix[i+1], lowmc_key->key, sc);
    mpc_add(z, z, t, sc);
    mpc_free(t, sc);
    mpc_copy(x, z, sc);
  }
  mpc_copy(c, x, sc);
  mpc_copy(views[vcnt].s, c, sc); 

  mpc_free(z, sc);
  mpc_free(y, sc);
  mpc_free(x, sc);
  return c;
}

mzd_t **_mpc_lowmc_call_bitsliced(lowmc_t *lowmc, lowmc_key_t *lowmc_key, mzd_t *p, view_t *views, mzd_t ***rvec, unsigned sc, unsigned ch, 
    mzd_t** (*andPtr)(mzd_t **, mzd_t **, mzd_t **, mzd_t**, view_t*, int*, unsigned, unsigned, mzd_t**), int *status) {
  int vcnt = 0;
  
  for(unsigned i = 0 ; i < sc ; i++) 
    mzd_copy(views[vcnt].s[i], lowmc_key->key[i]);
  vcnt++;

  mzd_t **c = mpc_init_empty_share_vector(lowmc->n, sc);

  mzd_t **x = mpc_init_empty_share_vector(lowmc->n, sc);
  mzd_t **y = mpc_init_empty_share_vector(lowmc->n, sc);
  mzd_t **z = mpc_init_empty_share_vector(lowmc->n, sc);

  mpc_const_mat_mul(x, lowmc->KMatrix[0], lowmc_key->key, sc);
  mpc_const_add(x, x, p, sc, ch);

  mask_t *mask = prepare_masks(0, lowmc->n, lowmc->m);
  sbox_vars_t *vars = sbox_vars_init(0, lowmc->n, sc);
  
  mzd_t **t = mpc_init_empty_share_vector(lowmc->n, sc);

  mzd_t *r[3];
  for(unsigned i = 0 ; i < lowmc->r ; i++) {  
    for(unsigned j = 0 ; j < sc ; j++)
      r[j] = rvec[j][i]; 
    if(_mpc_sbox_layer_bitsliced(y, x, lowmc->m, views, &vcnt, r, sc, andPtr, mask, vars)) {
      *status = -1;
      return 0;
    }
    mpc_const_mat_mul(z, lowmc->LMatrix[i], y, sc);
    mpc_const_add(z, z, lowmc->Constants[i], sc, ch);
    mpc_const_mat_mul(t, lowmc->KMatrix[i+1], lowmc_key->key, sc);
    mpc_add(z, z, t, sc);
    mpc_copy(x, z, sc);
  }
  mpc_free(t, sc);
  mpc_copy(c, x, sc);
  mpc_copy(views[vcnt].s, c, sc); 

  mzd_free(mask->x0);
  mzd_free(mask->x1);
  mzd_free(mask->x2);
  mzd_free(mask->mask);
  free(mask);
  mpc_free(vars->x0m, sc);
  mpc_free(vars->x1m, sc);
  mpc_free(vars->x2m, sc);
  mpc_free(vars->r0m, sc);
  mpc_free(vars->r1m, sc);
  mpc_free(vars->r2m, sc);
  mpc_free(vars->x0s, sc);
  mpc_free(vars->r0s, sc);
  mpc_free(vars->x1s, sc);
  mpc_free(vars->r1s, sc);
  mpc_free(vars->v, sc);
  free(vars);

  mpc_free(z, sc);
  mpc_free(y, sc);
  mpc_free(x, sc);
  return c;
}

mzd_t **mpc_lowmc_call(lowmc_t *lowmc, lowmc_key_t *lowmc_key, mzd_t *p, view_t *views, mzd_t ***rvec) {
  //return _mpc_lowmc_call(lowmc, lowmc_key, p, views, rvec, 3, 0, &mpc_and_bit, 0); 
  return _mpc_lowmc_call_bitsliced(lowmc, lowmc_key, p, views, rvec, 3, 0, &mpc_and, 0); 
}

mzd_t **_mpc_lowmc_call_verify(lowmc_t *lowmc, lowmc_key_t *lowmc_key, mzd_t *p, view_t *views, mzd_t ***rvec, int *status, int c) {
  return _mpc_lowmc_call(lowmc, lowmc_key, p, views, rvec, 2, c, &mpc_and_bit_verify, status); 
  //return _mpc_lowmc_call_bitsliced(lowmc, lowmc_key, p, views, rvec, 2, 0, &mpc_and_verify, 0); 
}

int mpc_lowmc_verify(lowmc_t *lowmc, mzd_t *p, view_t *views, mzd_t ***rvec, int c) {
  //initialize two key shares from v0
  lowmc_key_t *lowmc_key = (lowmc_key_t*)malloc(sizeof(lowmc_key));
  lowmc_key->key = (mzd_t**)malloc(2 * sizeof(mzd_t*));
  lowmc_key->key[0] = mzd_init(1, lowmc->k);
  lowmc_key->key[1] = mzd_init(1, lowmc->k);
  mzd_copy(lowmc_key->key[0], views[0].s[0]);
  mzd_copy(lowmc_key->key[1], views[0].s[1]);  
  lowmc_key->sharecount = 2;
  
  int status = 0;
  mzd_t **v = _mpc_lowmc_call_verify(lowmc, lowmc_key, p, views, rvec, &status, c);
  if(v)
    mpc_free(v, 2);

  mzd_free(lowmc_key->key[0]);
  mzd_free(lowmc_key->key[1]);
  free(lowmc_key);

  return status;
}

sbox_vars_t *sbox_vars_init(sbox_vars_t *vars, rci_t n, unsigned sc) {
  if(vars == 0) 
    vars = (sbox_vars_t*)malloc(sizeof(sbox_vars_t));
  
  vars->x0m = mpc_init_empty_share_vector(n, sc); 
  vars->x1m = mpc_init_empty_share_vector(n, sc); 
  vars->x2m = mpc_init_empty_share_vector(n, sc); 
  vars->r0m = mpc_init_empty_share_vector(n, sc); 
  vars->r1m = mpc_init_empty_share_vector(n, sc); 
  vars->r2m = mpc_init_empty_share_vector(n, sc); 
  vars->x0s = mpc_init_empty_share_vector(n, sc); 
  vars->x1s = mpc_init_empty_share_vector(n, sc); 
  vars->r0s = mpc_init_empty_share_vector(n, sc); 
  vars->r1s = mpc_init_empty_share_vector(n, sc); 
  vars->v   = mpc_init_empty_share_vector(n, sc); 

  return vars;
}


void free_proof(lowmc_t *lowmc, proof_t *proof) {
  for(unsigned i = 0 ; i < NUM_ROUNDS ; i++) {
    mpc_free(proof->y[i], 3);
    for(unsigned j = 0 ; j < 2 + lowmc->r ; j++) {
      mzd_free(proof->views[i][j].s[0]);
      mzd_free(proof->views[i][j].s[1]);
      free(proof->views[i][j].s);
    }
    free(proof->views[i]);
  
    free(proof->keys[i][0]);
    free(proof->keys[i][1]);
    free(proof->keys[i]);

    free(proof->r[i][0]);
    free(proof->r[i][1]);
    free(proof->r[i]);
  }
  free(proof->y);
  free(proof->views);
  free(proof->keys);
  free(proof->r);
 
  free(proof);

 
}


