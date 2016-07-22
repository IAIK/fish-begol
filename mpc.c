#include "mpc.h"
#include "mzd_additional.h"

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
