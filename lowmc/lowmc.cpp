#include "lowmc.h"
#include <bitset>

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

  lowmc->key = mzd_init_random_vector(k);
  return lowmc;
}

mzd_t *lowmc_call(lowmc_t *lowmc, mzd_t *p) {
  mzd_t *c = mzd_init(lowmc->n,1);

  mzd_t *x = mzd_init(lowmc->n,1);
  mzd_t *y = mzd_init(lowmc->n,1);
  mzd_t *z = mzd_init(lowmc->n,1);

  mzd_copy(x, p);
  mzd_addmul(x, lowmc->KMatrix[0], lowmc->key, 0);

  for(int i=0; i<lowmc->r; i++) {
    sbox_layer(y, x, lowmc->m);
    mzd_mul(z, lowmc->LMatrix[i], y, 0);
    mzd_add(z, z, lowmc->Constants[i]);
    mzd_addmul(z, lowmc->KMatrix[i+1], lowmc->key, 0);
    mzd_copy(x, z);
  }
  mzd_copy(c, x);

  mzd_free(z);
  mzd_free(y);
  mzd_free(x);
  return c;
}

int main(int argc, char **argv) {
  lowmc_t *lowmc = lowmc_init(63, 256, 12, 128);
  mzd_t *p       = mzd_init_random_vector(256); 
  mzd_t *c       = lowmc_call(lowmc, p);
  return 0;
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
