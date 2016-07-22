#include "lowmc.h"
#include <bitset>

mzd_t *mpc_add(mzd_t **result, mzd_t **first, mzd_t **second) {
  for(unsigned i = 0; i < 3 ; i++)
    mzd_add(result[i], first[i], second[i]);
}

mzd_t *mpc_const_add(mzd_t **result, mzd_t **first, mzd_t *second) {
  for(unsigned i = 0; i < 3 ; i++) 
    mzd_add(result[i], first[i], second);
}

mzd_t *mpc_const_mat_addmul(mzd_t** result, mzd_t *matrix, mzd_t **vector) {
  for(unsigned i = 0; i < 3 ; i++)
    mzd_addmul(result[i], matrix, vector[i], 0);
}

mzd_t *mpc_const_mat_mul(mzd_t** result, mzd_t *matrix, mzd_t **vector) {
  for(unsigned i = 0; i < 3 ; i++)
    mzd_mul(result[i], matrix, vector[i], 0);
}

void mpc_copy(mzd_t** out, mzd_t **in) {
  for(unsigned i = 0; i < 3 ; i++)
    mzd_copy(out[i], in[i]);
}

// Uses the Grain LSFR as self-shrinking generator to create pseudorandom bits
bool getrandbit () {
  static std::bitset<80> state; //Keeps the 80 bit LSFR state
  bool tmp = 0;
  //If state has not been initialized yet
  if (state.none ()) {
    state.set (); //Initialize with all bits set
    //Throw the first 160 bits away
    for (unsigned i = 0; i < 160; ++i) {
      //Update the state
      tmp =  state[0] ^ state[13] ^ state[23] ^ state[38] ^ state[51] ^ state[62];
      state >>= 1;
      state[79] = tmp;
    }
  }
  //choice records whether the first bit is 1 or 0.
  //The second bit is produced if the first bit is 1.
  bool choice = false;
  do {
    //Update the state
    tmp =  state[0] ^ state[13] ^ state[23] ^ state[38] ^ state[51] ^ state[62];
    state >>= 1;
    state[79] = tmp;
    choice = tmp;
    tmp =  state[0] ^ state[13] ^ state[23] ^ state[38] ^ state[51] ^ state[62];
    state >>= 1;
    state[79] = tmp;
  } while (!choice);
  return tmp;
}

mzd_t *mzd_init_random_vector(rci_t n) {
  mzd_t *A = mzd_init(n,1);
  for(rci_t i=0; i<n; i++)
    mzd_write_bit(A, n-i-1, 0, getrandbit());
  return A;
}

mzd_t *mpc_reconstruct_from_share(mzd_t** shared_vec) {
  mzd_t *res = mzd_add(0, shared_vec[0], shared_vec[1]);
  mzd_add(res, res, shared_vec[2]);
  return res;
} 

void mpc_print(mzd_t **shared_vec) {
  mzd_t *r = mpc_reconstruct_from_share(shared_vec);
  mzd_print(r);
  mzd_free(r);
}

void mpc_free(mzd_t **vec) {
  mzd_free(vec[0]);
  mzd_free(vec[1]);
  mzd_free(vec[2]);
}

mzd_t **mpc_init_empty_share_vector(rci_t n) {
  mzd_t **s = (mzd_t**)malloc(3 * sizeof(mzd_t*));
  s[0] = mzd_init(n, 1);
  s[1] = mzd_init(n, 1);
  s[2] = mzd_init(n, 1);

  return s;
}

mzd_t **mpc_init_random_vector(rci_t n) {
  mzd_t **s = (mzd_t**)malloc(3 * sizeof(mzd_t*));
  s[0] = mzd_init_random_vector(n);
  s[1] = mzd_init_random_vector(n);
  s[2] = mzd_init_random_vector(n);

  return s;
}

mzd_t **mpc_init_plain_share_vector(mzd_t *v) {
  mzd_t **s = (mzd_t**)malloc(3 * sizeof(mzd_t*));
  s[0] = mzd_init_random_vector(v->nrows);
  s[1] = mzd_init_random_vector(v->nrows);
  s[2] = mzd_init(v->nrows, 1);

  mzd_copy(s[0], v);
  mzd_copy(s[1], v);
  mzd_copy(s[2], v);

  return s;
}

mzd_t **mpc_init_share_vector(mzd_t *v) {
  mzd_t **s = (mzd_t**)malloc(3 * sizeof(mzd_t*));
  s[0] = mzd_init_random_vector(v->nrows);
  s[1] = mzd_init_random_vector(v->nrows);
  s[2] = mzd_init(v->nrows, 1);
  mzd_add(s[2], s[0], s[1]);
  mzd_add(s[2], s[2], v);

  return s;
}

mzd_t *mzd_sample_lmatrix(rci_t n) {
  mzd_t *A = mzd_init(n,n);
  mzd_t *B = mzd_init(n,n);
  do {
    for(rci_t i=0; i<n; i++) {
      for(rci_t j=0; j<n; j++)
        mzd_write_bit(A, n-i-1, n-j-1, getrandbit());
      //mzd_xor_bits(A, n-i-1, n-i-1, 1, 1);
    }
    mzd_copy(B, A);
  } while(mzd_echelonize(A, 0) != n);
  mzd_free(A);
  return B;
};

mzd_t *mzd_sample_kmatrix(rci_t n, rci_t k) {
  mzd_t *A = mzd_init(n, k);
  mzd_t *B = mzd_init(n, k);

  rci_t r = (n<k) ? n : k;

  do {
    for(rci_t i=0; i<n; i++) {
      for(rci_t j=0; j<k; j++)
        mzd_write_bit(A, n-i-1, k-j-1, getrandbit());
      mzd_xor_bits(A, n-i-1, (k+i+1)%k, 1, 1);
    }
    mzd_copy(B, A);
  } while(mzd_echelonize(A, 0) != r);
  mzd_free(A);
  return B;
};

BIT* mpc_and_bit(BIT* a, BIT* b, BIT* r) {
  BIT* wp = (BIT*)malloc(3 * sizeof(BIT));
  for(unsigned i = 0 ; i < 3 ; i++) {
    unsigned j = (i + 1) % 3;
    wp[i] = (a[i] & b[i]) ^ (a[j] & b[i]) ^ (a[i] & b[j]) ^ r[i] ^ r[j];
  }
  return wp;
}

BIT* mpc_xor_bit(BIT* a, BIT* b) {
  BIT* wp = (BIT*)malloc(3 * sizeof(BIT));
  for(unsigned i = 0 ; i < 3 ; i++) {
    wp[i] = a[i] ^ b[i];
  }
  return wp;
}

BIT *mpc_read_bit(mzd_t **vec, rci_t n) {
  BIT *bit = (BIT*)malloc(3 * sizeof(BIT));
  bit[0] = mzd_read_bit(vec[0], n, 0);
  bit[1] = mzd_read_bit(vec[1], n, 0);
  bit[2] = mzd_read_bit(vec[2], n, 0);

  return bit;
}

void mpc_write_bit(mzd_t **vec, rci_t n, BIT *bit) {
  mzd_write_bit(vec[0], n, 0, bit[0]);
  mzd_write_bit(vec[1], n, 0, bit[1]);
  mzd_write_bit(vec[2], n, 0, bit[2]);
}

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

void sbox_layer(mzd_t *out, mzd_t *in, rci_t m) {
  mzd_copy(out, in);
  for(rci_t n=out->nrows-3*m; n<out->nrows; n+=3) {
    word x0 = mzd_read_bit(in, n+0, 0);
    word x1 = mzd_read_bit(in, n+1, 0);
    word x2 = mzd_read_bit(in, n+2, 0);

    mzd_write_bit(out, n+0, 0, x1&x2 ^ x0);
    mzd_write_bit(out, n+1, 0, x0&x2 ^ x0 ^ x1);
    mzd_write_bit(out, n+2, 0, x0&x1 ^ x0 ^ x1 ^ x2);
  }
}

lowmc_t *lowmc_init(size_t m, size_t n, size_t r, size_t k) {
  lowmc_t *lowmc = (lowmc_t*)malloc(sizeof(lowmc_t));
  lowmc->m = m;
  lowmc->n = n;
  lowmc->r = r;
  lowmc->k = k;

  lowmc->LMatrix = (mzd_t**)calloc(sizeof(mzd_t*),r);
  for(int i=0; i<r; i++)
    lowmc->LMatrix[i] = mzd_sample_lmatrix(n);

  lowmc->Constants = (mzd_t**)calloc(sizeof(mzd_t*),r);
  for(int i=0; i<r; i++) {
    lowmc->Constants[i] = mzd_init_random_vector(n);
  }
  lowmc->KMatrix = (mzd_t**)calloc(sizeof(mzd_t*), r+1);
  for(int i=0; i<r+1; i++) {
    lowmc->KMatrix[i] = mzd_sample_kmatrix(n, k);
  }

  lowmc->key = (mzd_t**)malloc(sizeof(mzd_t*));
  lowmc->key[0] = mzd_init_random_vector(k);
  return lowmc;
}

void lowmc_secret_share(lowmc_t *lowmc) {
  lowmc->key = (mzd_t**)realloc(lowmc->key, 3 * sizeof(mzd_t*));
  
  lowmc->key[1] = mzd_init_random_vector(lowmc->k);
  lowmc->key[2] = mzd_init_random_vector(lowmc->k);
  
  mzd_add(lowmc->key[0], lowmc->key[0], lowmc->key[1]);
  mzd_add(lowmc->key[0], lowmc->key[0], lowmc->key[2]);
}

mzd_t *lowmc_call(lowmc_t *lowmc, mzd_t *p) {
  mzd_t *c = mzd_init(lowmc->n,1);

  mzd_t *x = mzd_init(lowmc->n,1);
  mzd_t *y = mzd_init(lowmc->n,1);
  mzd_t *z = mzd_init(lowmc->n,1);

  mzd_copy(x, p);
  mzd_addmul(x, lowmc->KMatrix[0], lowmc->key[0], 0);

  for(int i=0; i<lowmc->r; i++) {
    sbox_layer(y, x, lowmc->m);
    mzd_mul(z, lowmc->LMatrix[i], y, 0);
    mzd_add(z, z, lowmc->Constants[i]);
    mzd_addmul(z, lowmc->KMatrix[i+1], lowmc->key[0], 0);
    mzd_copy(x, z);
  }
 
  mzd_copy(c, x);

  mzd_free(z);
  mzd_free(y);
  mzd_free(x);
  return c;
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

void lowmc_free(lowmc_t *lowmc) {
  for(int i=0; i<lowmc->r; i++) {
    mzd_free(lowmc->Constants[i]);
    mzd_free(lowmc->KMatrix[i]);
    mzd_free(lowmc->LMatrix[i]);
  }
  mzd_free(lowmc->KMatrix[lowmc->r]);
  free(lowmc->Constants);
  free(lowmc->LMatrix);
  free(lowmc->KMatrix);
  free(lowmc);
}

void test_mpc_share() {
  mzd_t *t1    = mzd_init_random_vector(10);
  mzd_t **s1   = mpc_init_share_vector(t1);
  mzd_t *t1cmb = mpc_reconstruct_from_share(s1); 

  if(mzd_cmp(t1, t1cmb) == 0)
    printf("Share test successful.\n");  

  mzd_free(t1);
  for(unsigned i = 0 ; i < 3 ; i++)
    mzd_free(s1[i]);
  mzd_free(t1cmb);
}

void test_mpc_add() {
  mzd_t *t1 = mzd_init_random_vector(10);
  mzd_t *t2 = mzd_init_random_vector(10);
  mzd_t *res = mzd_add(0, t1, t2);

  mzd_t **s1 = mpc_init_share_vector(t1);
  mzd_t **s2 = mpc_init_share_vector(t2);
  mzd_t **ress = mpc_init_empty_share_vector(10);
  mpc_add(ress, s1, s2);
  
  mzd_t *cmp = mpc_reconstruct_from_share(ress);

  if(mzd_cmp(res, cmp) == 0)
    printf("Shared add test successful.\n");

  mzd_free(t1);
  mzd_free(t2);
  mzd_free(res);
  for(unsigned i = 0 ; i < 3 ; i++) {
    mzd_free(s1[i]);
    mzd_free(s2[i]);
    mzd_free(ress[i]);
  }
  mzd_free(cmp);
}

int main(int argc, char **argv) {
  lowmc_t *lowmc = lowmc_init(63, 256, 12, 128);
  mzd_t *p       = mzd_init_random_vector(256); 
  mzd_t *c       = lowmc_call(lowmc, p);
  mzd_t **c_mpc  = mpc_lowmc_call(lowmc, p);
  mzd_t *c_mpcr  = mpc_reconstruct_from_share(c_mpc); 
 
  

  if(mzd_cmp(c, c_mpcr) == 0)
    printf("Success.\n");

  test_mpc_share();
  test_mpc_add();
  
//  mzd_t *c_mpc = mpc_lowmc_call(lowmc, p);

  return 0;
}




