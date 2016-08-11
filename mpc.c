#include "mpc.h"
#include "mzd_additional.h"

void mpc_set(mzd_t **res, mzd_t **src, unsigned sc) {
  for(int i = 0 ; i < sc ; i++) {
    mzd_free(res[i]);
    res[i] = src[i];
  } 
}

void mpc_shift_right(mzd_t**res, mzd_t **val, unsigned count, word carry, unsigned sc) {
  for(unsigned i = 0 ; i < sc ; i++) 
    mzd_shift_right(res[i], val[i], count, 0);
}

void mpc_shift_left(mzd_t **res, mzd_t **val, unsigned count, word carry, unsigned sc) {
  for(unsigned i = 0 ; i < sc ; i++) 
    mzd_shift_left(res[i], val[i], count, 0);
}

mzd_t **mpc_and_const(mzd_t **res, mzd_t **first, mzd_t *second, unsigned sc) {
  if(res == 0) 
    res = (mzd_t**)calloc(sizeof(mzd_t*), 3);
  for(unsigned i = 0 ; i < sc ; i++) 
    res[i] = mzd_and(res[i], first[i], second);
  return res;
}

mzd_t **mpc_xor(mzd_t **res, mzd_t **first, mzd_t **second, unsigned sc) {
  if(res == 0) 
    res = (mzd_t**)calloc(sizeof(mzd_t*), 3);
  for(unsigned i = 0 ; i < sc ; i++) 
    res[i] = mzd_xor(res[i], first[i], second[i]);
  return res;
}

mzd_t **mpc_and(mzd_t **res, mzd_t **first, mzd_t **second, mzd_t **r, view_t *views, int *i, unsigned viewshift,  unsigned sc, mzd_t** buffer) {
  if(res == 0) 
    res = (mzd_t**)calloc(sizeof(mzd_t*), 3);
  for(unsigned m = 0 ; m < sc ; m++) {
    unsigned j = (m + 1) % 3;
    res[m] = mzd_and(res[m], first[m], second[m]);
    
    mzd_t *b = mzd_and(0, first[j], second[m]);
    mzd_t *c = mzd_and(0, first[m], second[j]);
 
    mzd_xor(res[m], res[m], b);
    mzd_xor(res[m], res[m], c);
    mzd_xor(res[m], res[m], r[m]);
    mzd_xor(res[m], res[m], r[j]);
    
    mzd_free(b);
    mzd_free(c);
  }
  mpc_shift_right(buffer, res, viewshift, 0, sc);
  mpc_xor(views[*i].s, views[*i].s, buffer, sc);
  return res;
}

mzd_t **mpc_and_verify(mzd_t **res, mzd_t **first, mzd_t **second, mzd_t **r, view_t *views, int *i, unsigned viewshift,  unsigned sc, mzd_t** buffer) {
  if(res == 0) 
    res = (mzd_t**)calloc(sizeof(mzd_t*), 3);
  for(unsigned m = 0 ; m < sc ; m++) {
    unsigned j = (m + 1) % 3;
    res[m] = mzd_and(res[m], first[m], second[m]);
    
    mzd_t *b = mzd_and(0, first[j], second[m]);
    mzd_t *c = mzd_and(0, first[m], second[j]);

    mzd_xor(res[m], res[m], b);
    mzd_xor(res[m], res[m], c);
    mzd_xor(res[m], res[m], r[m]);
    mzd_xor(res[m], res[m], r[j]);

    mzd_free(b);
    mzd_free(c);
  }
  mpc_xor(views[*i].s, views[*i].s, res, sc);
  return res;
}

int mpc_and_bit(BIT* a, BIT* b, BIT* r, view_t *views, int *i, unsigned bp, unsigned sc) {
  BIT* wp = (BIT*)malloc(sc * sizeof(BIT));
  for(unsigned m = 0 ; m < sc ; m++) {
    unsigned j = (m + 1) % 3;
    wp[m] = (a[m] & b[m]) ^ (a[j] & b[m]) ^ (a[m] & b[j]) ^ r[m] ^ r[j];
  }
  for(unsigned m = 0 ; m < sc ; m++) 
    a[m] = wp[m];
  mpc_write_bit(views[*i].s, bp, a, sc);
  free(wp);
  return 0;
}

int mpc_and_bit_verify(BIT* a, BIT* b, BIT* r, view_t *views, int *i, unsigned bp, unsigned sc) {
  BIT* wp = (BIT*)malloc(sc * sizeof(BIT));
  for(unsigned m = 0 ; m < sc - 1 ; m++) {
    unsigned j = m + 1;
    wp[m] = (a[m] & b[m]) ^ (a[j] & b[m]) ^ (a[m] & b[j]) ^ r[m] ^ r[j];
  }
  for(unsigned m = 0 ; m < sc - 1 ; m++) {
    a[m] = wp[m];
    if(a[m] != mzd_read_bit(views[*i].s[m], 0, bp)) {
      return -1;
    }
  }
  a[sc - 1] = mzd_read_bit(views[*i].s[sc - 1], 0, bp);
  free(wp);
  return 0;
}

void mpc_xor_bit(BIT* a, BIT* b, unsigned sc) {
  for(unsigned i = 0 ; i < sc ; i++) {
    a[i] ^= b[i];
  }
}

BIT *mpc_read_bit(mzd_t **vec, rci_t n, unsigned sc) {
  BIT *bit = (BIT*)malloc(sc * sizeof(BIT));
  for(unsigned i = 0 ; i < sc ; i++)
    bit[i] = mzd_read_bit(vec[i], 0, n);

  return bit;
}

void mpc_write_bit(mzd_t **vec, rci_t n, BIT *bit, unsigned sc) {
  for(unsigned i = 0 ; i < sc ; i++)
    mzd_write_bit(vec[i], 0, n, bit[i]);
}

mzd_t **mpc_add(mzd_t **result, mzd_t **first, mzd_t **second, unsigned sc) {
  if(result == 0)
    result = mpc_init_empty_share_vector(first[0]->ncols, sc);
  for(unsigned i = 0; i < sc ; i++)
    mzd_add(result[i], first[i], second[i]);
  return result;
}

mzd_t **mpc_const_add(mzd_t **result, mzd_t **first, mzd_t *second, unsigned sc, unsigned c) {
  if(result == 0)
    result = mpc_init_empty_share_vector(first[0]->ncols, sc);
  if(c == 0)
    mzd_add(result[0], first[0], second);
  else if(c == sc)
    mzd_add(result[sc - 1], first[sc - 1], second);
  return result;
}

mzd_t **mpc_const_mat_mul(mzd_t** result, mzd_t *matrix, mzd_t **vector, unsigned sc) {
  if(result == 0)
    result = mpc_init_empty_share_vector(vector[0]->ncols, sc);
  for(unsigned i = 0; i < sc ; i++)
    mzd_mul(result[i], vector[i], matrix, 0);
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

void mpc_free(mzd_t **vec, unsigned sc) {
  for(unsigned i = 0 ; i < sc ; i++)
    mzd_free(vec[i]);
  free(vec);
}

mzd_t **mpc_init_empty_share_vector(rci_t n, unsigned sc) {
  mzd_t **s = (mzd_t**)malloc(3 * sizeof(mzd_t*));
  for(unsigned i = 0 ; i < sc ; i++)
    s[i] = mzd_init(1, n);
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
  s[0] = mzd_init_random_vector(v->ncols);
  s[1] = mzd_init_random_vector(v->ncols);
  s[2] = mzd_init(1, v->ncols);

  mzd_copy(s[0], v);
  mzd_copy(s[1], v);
  mzd_copy(s[2], v);

  return s;
}

mzd_t **mpc_init_share_vector(mzd_t *v) {
  mzd_t **s = (mzd_t**)malloc(3 * sizeof(mzd_t*));
  s[0] = mzd_init_random_vector(v->ncols);
  s[1] = mzd_init_random_vector(v->ncols);
  s[2] = mzd_init(1, v->ncols);
  mzd_add(s[2], s[0], s[1]);
  mzd_add(s[2], s[2], v);

  return s;
}
