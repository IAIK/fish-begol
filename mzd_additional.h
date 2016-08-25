#ifndef MZD_ADDITIONAL_H
#define MZD_ADDITIONAL_H 

#include "m4ri/m4ri.h"

/**
 * Initializes a random vector
 * 
 * \param n the length of the vector
 */
mzd_t *mzd_init_random_vector(rci_t n);

mzd_t **mzd_init_random_vectors_from_seed(unsigned char key[16], rci_t n, unsigned count);

word mzd_shift_right(mzd_t* res, mzd_t *val, unsigned count, word carry);

word mzd_shift_left(mzd_t* res, mzd_t *val, unsigned count, word carry);

mzd_t *mzd_and(mzd_t *res, mzd_t *first, mzd_t *second);

mzd_t *mzd_xor(mzd_t *res, mzd_t *first, mzd_t *second);

void mzd_shift_right_inplace(mzd_t *val, unsigned int count);

void mzd_shift_left_inplace(mzd_t *val, unsigned int count);

#endif
