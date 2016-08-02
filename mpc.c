#include "mpc.h"
#include "mzd_additional.h"

void mpc_and_bit(BIT* a, BIT* b, BIT* r, unsigned sc) {
  BIT* wp = (BIT*)malloc(sc * sizeof(BIT));
  for(unsigned i = 0 ; i < sc ; i++) {
    unsigned j = (i + 1) % 3;
    wp[i] = (a[i] & b[i]) ^ (a[j] & b[i]) ^ (a[i] & b[j]) ^ r[i] ^ r[j];
  }
  for(unsigned i = 0 ; i < sc ; i++) 
    a[i] = wp[i];
  free(wp);
}

void mpc_xor_bit(BIT* a, BIT* b, unsigned sc) {
  for(unsigned i = 0 ; i < sc ; i++) {
    a[i] ^= b[i];
  }
}

BIT *mpc_read_bit(mzd_t **vec, rci_t n, unsigned sc) {
  BIT *bit = (BIT*)malloc(sc * sizeof(BIT));
  for(int i = 0 ; i < sc ; i++)
    bit[i] = mzd_read_bit(vec[i], n, 0);

  return bit;
}

void mpc_write_bit(mzd_t **vec, rci_t n, BIT *bit, unsigned sc) {
  for(unsigned i = 0 ; i < sc ; i++)
    mzd_write_bit(vec[i], n, 0, bit[i]);
}

mzd_t **mpc_add(mzd_t **result, mzd_t **first, mzd_t **second) {
  if(result == 0)
    result = mpc_init_empty_share_vector(first[0]->nrows, 3);
  for(unsigned i = 0; i < 3 ; i++)
    mzd_add(result[i], first[i], second[i]);
  return result;
}

mzd_t **mpc_const_add(mzd_t **result, mzd_t **first, mzd_t *second, unsigned sc) {
  if(result == 0)
    result = mpc_init_empty_share_vector(first[0]->nrows, sc);
  mzd_add(result[0], first[0], second);
  return result;
}

mzd_t **mpc_const_mat_addmul(mzd_t** result, mzd_t *matrix, mzd_t **vector) {
  if(result == 0)
    result = mpc_init_empty_share_vector(vector[0]->nrows, 3);
  for(unsigned i = 0; i < 3 ; i++)
    mzd_addmul(result[i], matrix, vector[i], 0);
  return result;
}

mzd_t **mpc_const_mat_mul(mzd_t** result, mzd_t *matrix, mzd_t **vector, unsigned sc) {
  if(result == 0)
    result = mpc_init_empty_share_vector(vector[0]->nrows, sc);
  for(unsigned i = 0; i < sc ; i++)
    mzd_mul(result[i], matrix, vector[i], 0);
  return result;
}

void mpc_copy(mzd_t** out, mzd_t **in, unsigned sc) {
  for(unsigned i = 0; i < sc ; i++)
    mzd_copy(out[i], in[i]);
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
  free(vec);
}

mzd_t **mpc_init_empty_share_vector(rci_t n, unsigned sc) {
  mzd_t **s = (mzd_t**)malloc(3 * sizeof(mzd_t*));
  for(unsigned i = 0 ; i < sc ; i++)
    s[i] = mzd_init(n, 1);
  return s;
}

mzd_t **mpc_init_random_vector(rci_t n, unsigned sc) {
  mzd_t **s = (mzd_t**)malloc(3 * sizeof(mzd_t*));
  for(unsigned i = 0 ; i < sc ; i++)
    s[i] = mzd_init_random_vector(n);
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
