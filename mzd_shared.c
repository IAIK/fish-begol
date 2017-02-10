/*
 * fish-begol - Implementation of the Fish and Begol signature schemes
 * Copyright (C) 2016 Graz University of Technology
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

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

void mzd_shared_share_from_keys(mzd_shared_t* shared_value, 
                                const unsigned char keys[2][16]) {
  shared_value->share_count = 3;

  shared_value->shared[1] = mzd_init_random_vector_from_seed(keys[0], shared_value->shared[0]->ncols);
  shared_value->shared[2] = mzd_init_random_vector_from_seed(keys[1], shared_value->shared[0]->ncols);
  
  mzd_xor(shared_value->shared[0], shared_value->shared[0], shared_value->shared[1]);
  mzd_xor(shared_value->shared[0], shared_value->shared[0], shared_value->shared[2]);
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
