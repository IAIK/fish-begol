#include "mzd_shared.h"

void mzd_shared_init(mzd_shared_t* shared_value, mzd_t const* value) {
  shared_value->share_count = 1;

  shared_value->shared[0] = mzd_local_copy(NULL, value);
}

void mzd_shared_copy(mzd_shared_t* dst, mzd_shared_t const* src) {
  mzd_shared_clear(dst);
  mzd_shared_from_shares(dst, src->shared, src->share_count);
}

void mzd_shared_from_shares(mzd_shared_t* shared_value, mzd_t* const* shares,
                            unsigned int share_count) {
  shared_value->share_count = share_count;
  for (unsigned int i = 0; i < share_count; ++i) {
    shared_value->shared[i] = mzd_local_copy(NULL, shares[i]);
  }
}

void mzd_shared_share(mzd_shared_t* shared_value) {
  shared_value->share_count = 3;

  shared_value->shared[1] = mzd_init_random_vector(shared_value->shared[0]->ncols);
  shared_value->shared[2] = mzd_init_random_vector(shared_value->shared[0]->ncols);

  mzd_xor(shared_value->shared[0], shared_value->shared[0], shared_value->shared[1]);
  mzd_xor(shared_value->shared[0], shared_value->shared[0], shared_value->shared[2]);
}

void mzd_shared_share_prng(mzd_shared_t* shared_value, aes_prng_t* aes_prng) {
  shared_value->share_count = 3;

  shared_value->shared[1] = mzd_init_random_vector_prng(shared_value->shared[0]->ncols, aes_prng);
  shared_value->shared[2] = mzd_init_random_vector_prng(shared_value->shared[0]->ncols, aes_prng);

  mzd_xor(shared_value->shared[0], shared_value->shared[0], shared_value->shared[1]);
  mzd_xor(shared_value->shared[0], shared_value->shared[0], shared_value->shared[2]);
}

void mzd_shared_clear(mzd_shared_t* shared_value) {
  for (unsigned int i = 0; i < shared_value->share_count; ++i) {
    mzd_local_free(shared_value->shared[i]);
    shared_value->shared[i] = NULL;
  }
  shared_value->share_count = 0;
}
