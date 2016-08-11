#include "mzd_additional.h"
#include "randomness.h"

mzd_t *mzd_init_random_vector(rci_t n) {
  mzd_t *A = mzd_init(1,n);
  for(rci_t i=0; i<n; i++)
    mzd_write_bit(A, 0, n-i-1, getrandbit());
  return A;
}

mzd_t **mzd_init_random_vectors_from_seed(unsigned char key[16], rci_t n, unsigned count) {
  if(n % (8 * sizeof(word)) != 0)
    return 0;
  
  unsigned char *randomness = (unsigned char*)malloc(n / 8 * count * sizeof(unsigned char));
  getRandomness(key, randomness, n / 8 * count * sizeof(unsigned char));

  mzd_t **vectors = (mzd_t**)malloc(count * sizeof(mzd_t*));
  unsigned j = 0;
  for(int v = 0 ; v < count ; v++) {
    vectors[v] = mzd_init(1, n);
    for(int i = 0 ; i < n / (8 * sizeof(word)) ; i++) {
      memcpy(vectors[v]->rows[0] + i, randomness, sizeof(word));
    }
  }
  
  return vectors;
}

word mzd_shift_right(mzd_t* res, mzd_t *val, unsigned count, word carry) {
  word prev = 0;

  for(int i = 0 ; i < val->ncols / (8 * sizeof(word)); i++) {
    if(i < val->ncols / (8 * sizeof(word)) - 1)
      prev = val->rows[0][i + 1] << (8 * sizeof(word) - count);
    else 
      prev = 0;
    res->rows[0][i] = (val->rows[0][i] >> count) | prev;
  }

  
  if(carry == 0)
    return (val->rows[0][0] << (8 * sizeof(word) - count)) >> (8 * sizeof(word) - count);
  else {
    res->rows[0][(res->ncols / (8 * sizeof(word))) - 1] |= (carry << (8 * sizeof(word) - count));
    return 0;
  }
}

word mzd_shift_left(mzd_t* res, mzd_t *val, unsigned count, word carry) {
  word prev = 0;

  for(int i = 0 ; i < val->ncols / (8 * sizeof(word)); i++) {
    res->rows[0][i] = (val->rows[0][i] << count) | prev;
    prev = val->rows[0][i] >> (8 * sizeof(word) - count);
  }

  if(carry == 0)
    return prev; 
  else {
    res->rows[0][0] |= carry;
    return 0;
  } 
}

mzd_t *mzd_and(mzd_t *res, mzd_t *first, mzd_t *second) {
  if(res == 0) {
    res = mzd_init(1, first->ncols);
  }
  for(int i = 0 ; i < first->ncols / (8 * sizeof(word)); i++) {
    res->rows[0][i] = first->rows[0][i] & second->rows[0][i];
  }
  return res;
}

mzd_t *mzd_xor(mzd_t *res, mzd_t *first, mzd_t *second) {
  if(res == 0) {
    res = mzd_init(1, first->ncols);
  }
  for(int i = 0 ; i < first->ncols / (8 * sizeof(word)); i++) {
    res->rows[0][i] = first->rows[0][i] ^ second->rows[0][i];
  }
  return res;
}
