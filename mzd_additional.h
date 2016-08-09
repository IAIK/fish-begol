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

#endif
