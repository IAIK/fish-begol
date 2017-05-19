#ifndef MZD_SHARED_H
#define MZD_SHARED_H

#include "mzd_additional.h"
#include "randomness.h"

typedef struct {
  unsigned int share_count;
  mzd_t* shared[3];
} mzd_shared_t;

#define MZD_SHARED_EMPTY                                                                           \
  {                                                                                                \
    0, {                                                                                           \
      NULL                                                                                         \
    }                                                                                              \
  }

void mzd_shared_init(mzd_shared_t* shared_value, mzd_t const* value);
void mzd_shared_copy(mzd_shared_t* dst, mzd_shared_t const* src);
void mzd_shared_share_from_keys(mzd_shared_t* shared_value, const unsigned char keys[2][16]);
void mzd_shared_from_shares(mzd_shared_t* shared_value, mzd_t* const* shares,
                            unsigned int share_count);
void mzd_shared_share(mzd_shared_t* shared_value);
void mzd_shared_share_prng(mzd_shared_t* shared_value, aes_prng_t* aes_prng);
void mzd_shared_clear(mzd_shared_t* shared_value);

#endif
