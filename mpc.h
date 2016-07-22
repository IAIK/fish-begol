#ifndef MPC_H
#define MPC_H

#include "m4ri/m4ri.h"

mzd_t **mpc_init_share_vector(mzd_t *v);
mzd_t **mpc_init_plain_share_vector(mzd_t *v);
mzd_t **mpc_init_random_vector(rci_t n);
mzd_t **mpc_init_empty_share_vector(rci_t n);
mzd_t **mpc_init_random_vector(rci_t n);
mzd_t *mpc_reconstruct_from_share(mzd_t** shared_vec);

BIT* mpc_and_bit(BIT* a, BIT* b, BIT* r);
BIT* mpc_xor_bit(BIT* a, BIT* b);
BIT *mpc_read_bit(mzd_t **vec, rci_t n);
void mpc_write_bit(mzd_t **vec, rci_t n, BIT *bit);

mzd_t *mpc_add(mzd_t **result, mzd_t **first, mzd_t **second);
mzd_t *mpc_const_add(mzd_t **result, mzd_t **first, mzd_t *second);
mzd_t *mpc_const_mat_addmul(mzd_t** result, mzd_t *matrix, mzd_t **vector);
mzd_t *mpc_const_mat_mul(mzd_t** result, mzd_t *matrix, mzd_t **vector);

void mpc_copy(mzd_t** out, mzd_t **in);
void mpc_print(mzd_t **shared_vec);
void mpc_free(mzd_t **vec);

#endif
