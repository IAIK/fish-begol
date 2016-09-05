#ifndef SIGNATURE_BG_H
#define SIGNATURE_BG_H

#include "signature_common.h"

typedef struct {
  lowmc_key_t* k;
  lowmc_key_t* s;
} bg_private_key_t;

typedef struct {
  // pk = E_k(s)
  mzd_t* pk;
} bg_public_key_t;

typedef struct {
  proof_t proof_s;
  proof_t proof_p;
  mzd_t *c;
} bg_signature_t;

unsigned bg_compute_sig_size(unsigned m, unsigned n, unsigned r, unsigned k);

unsigned char *bg_sig_to_char_array(public_parameters_t *pp, bg_signature_t *sig, unsigned *len);

bg_signature_t *bg_sig_from_char_array(public_parameters_t *pp, unsigned char *data);

void bg_create_key(public_parameters_t* pp, bg_private_key_t* private_key,
                          bg_public_key_t* public_key, clock_t* timings);

void bg_destroy_key(bg_private_key_t* private_key, bg_public_key_t* public_key);

void bg_free_signature(public_parameters_t* pp, bg_signature_t* signature);

bg_signature_t *bg_sign(public_parameters_t* pp, bg_private_key_t* private_key, mzd_t *m, clock_t *timings);

int bg_verify(public_parameters_t* pp, bg_public_key_t *public_key, mzd_t *m, bg_signature_t *sig, clock_t *timings);

#endif
