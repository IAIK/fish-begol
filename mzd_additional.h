#ifndef MZD_ADDITIONAL_H
#define MZD_ADDITIONAL_H

#include <m4ri/m4ri.h>

/**
 * Initializes a random vector
 * 
 * \param n the length of the vector
 */
mzd_t *mzd_init_random_vector(rci_t n);

void mzd_randomize_ssl(mzd_t* val);

mzd_t **mzd_init_random_vectors_from_seed(unsigned char key[16], rci_t n, unsigned count);

word mzd_shift_right(mzd_t* res, mzd_t *val, unsigned count, word carry);

word mzd_shift_left(mzd_t* res, mzd_t *val, unsigned count, word carry);

mzd_t *mzd_and(mzd_t *res, mzd_t *first, mzd_t *second);

mzd_t *mzd_xor(mzd_t *res, mzd_t *first, mzd_t *second);

void mzd_shift_right_inplace(mzd_t *val, unsigned int count);

void mzd_shift_left_inplace(mzd_t *val, unsigned int count);

typedef struct {
  unsigned int share_count;
  mzd_t** shared;
} mzd_shared_t;

void mzd_shared_init(mzd_shared_t* shared_value, mzd_t* value);
void mzd_shared_copy(mzd_shared_t* dst, mzd_shared_t* src);
void mzd_shared_from_shares(mzd_shared_t* shared_value, mzd_t** shares, unsigned int share_count);
void mzd_shared_share(mzd_shared_t* shared_value);
void mzd_shared_clear(mzd_shared_t* shared_value);

#endif
