#include "mzd_additional.h"
#include "randomness.h"

#include <openssl/rand.h>

void mzd_randomize_ssl(mzd_t *val) {
  // similar to mzd_randomize but using RAND_Bytes instead
  const word mask_end = val->high_bitmask;
  for (rci_t i = 0; i < val->nrows; ++i) {
    RAND_bytes((unsigned char *)val->rows[i], val->width * sizeof(word));
    val->rows[i][val->width - 1] &= mask_end;
  }
}

mzd_t *mzd_init_random_vector(rci_t n) {
  mzd_t *A = mzd_init(1, n);
  mzd_randomize_ssl(A);

  return A;
}

mzd_t **mzd_init_random_vectors_from_seed(unsigned char key[16], rci_t n, unsigned int count) {
  if (n % (8 * sizeof(word)) != 0)
    return NULL;

  aes_prng_t* aes_prng = aes_prng_init(key);

  mzd_t **vectors = calloc(count, sizeof(mzd_t *));
  for (unsigned int v = 0; v < count; ++v) {
    vectors[v] = mzd_init(1, n);
    aes_prng_get_randomness(aes_prng, (unsigned char*) vectors[v]->rows[0], n / 8);
    vectors[v]->rows[0][vectors[v]->width - 1] &= vectors[v]->high_bitmask;
  }

  aes_prng_free(aes_prng);
  return vectors;
}

void mzd_shift_right_inplace(mzd_t *val, unsigned int count) {
  if (!count) {
    return;
  }

  const unsigned int nwords = val->ncols / (8 * sizeof(word));
  const unsigned int left_count = 8 * sizeof(word) - count;

  for (unsigned int i = 0; i < nwords - 1; ++i) {
    val->rows[0][i] = (val->rows[0][i] >> count) | (val->rows[0][i + 1] << left_count);
  }
  val->rows[0][nwords - 1] >>= count;
}

void mzd_shift_left_inplace(mzd_t *val, unsigned count) {
  if (!count) {
    return;
  }

  const unsigned int nwords      = val->ncols / (8 * sizeof(word));
  const unsigned int right_count = 8 * sizeof(word) - count;

  for (unsigned int i = nwords - 1; i > 0; --i) {
    val->rows[0][i] = (val->rows[0][i] << count) | (val->rows[0][i - 1] >> right_count);
  }
  val->rows[0][0] = val->rows[0][0] << count;
}

word mzd_shift_right(mzd_t *res, mzd_t *val, unsigned count, word carry) {
  if (!count) {
    mzd_copy(res, val);
    return 0;
  }
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
  if(!count) {
    mzd_copy(res, val);
    return 0;
  }
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


void mzd_shared_init(mzd_shared_t *shared_value, mzd_t *value) {
  shared_value->share_count = 1;

  shared_value->shared = calloc(1, sizeof(mzd_t *));
  shared_value->shared[0] = mzd_init(1, value->ncols);
  mzd_copy(shared_value->shared[0], value);
}

void mzd_shared_copy(mzd_shared_t *dst, mzd_shared_t *src) {
  mzd_shared_clear(dst);

  dst->shared = calloc(src->share_count, sizeof(mzd_t*));
  for (unsigned int i = 0; i < src->share_count; ++i) {
    dst->shared[i] = mzd_init(1, src->shared[i]->ncols);
    mzd_copy(dst->shared[i], src->shared[i]);
  }
  dst->share_count = src->share_count;
}

void mzd_shared_from_shares(mzd_shared_t *shared_value, mzd_t **shares, unsigned int share_count) {
  shared_value->share_count = share_count;
  shared_value->shared = calloc(share_count, sizeof(mzd_t *));
  for (unsigned int i = 0; i < share_count; ++i) {
    shared_value->shared[i] = mzd_init(1, shares[i]->ncols);
    mzd_copy(shared_value->shared[i], shares[i]);
  }
}

void mzd_shared_share(mzd_shared_t *shared_value) {
  mzd_t **tmp = realloc(shared_value->shared, 3 * sizeof(mzd_t *));
  if (!tmp) {
    return;
  }

  shared_value->shared = tmp;
  shared_value->share_count = 3;

  shared_value->shared[1] = mzd_init_random_vector(shared_value->shared[0]->ncols);
  shared_value->shared[2] = mzd_init_random_vector(shared_value->shared[0]->ncols);

  mzd_add(shared_value->shared[0], shared_value->shared[0], shared_value->shared[1]);
  mzd_add(shared_value->shared[0], shared_value->shared[0], shared_value->shared[2]);
}

void mzd_shared_clear(mzd_shared_t *shared_value) {
  for (unsigned int i = 0; i < shared_value->share_count; ++i) {
    mzd_free(shared_value->shared[i]);
  }
  free(shared_value->shared);
  shared_value->share_count = 0;
  shared_value->shared = NULL;
}
