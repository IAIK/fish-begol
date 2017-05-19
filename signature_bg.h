#ifndef SIGNATURE_BG_H
#define SIGNATURE_BG_H

#include "signature_common.h"

typedef struct {
  lowmc_key_t* s;
  mzd_t* beta;
} bg_private_key_t;

typedef struct {
  mzd_t* beta;
  // c = F_s(\beta)
  mzd_t* c;
} bg_public_key_t;

typedef struct {
  // proof for c = F_s(\beta)
  proof_t proof_c;
  // proof for y = F_s(m)
  proof_t proof_y;
  // y = F_s(m)
  mzd_t* y;
} bg_signature_t;

unsigned bg_compute_sig_size(unsigned m, unsigned n, unsigned r, unsigned k);

unsigned char* bg_sig_to_char_array(public_parameters_t* pp, bg_signature_t* sig, unsigned* len);

bg_signature_t* bg_sig_from_char_array(public_parameters_t* pp, unsigned char* data);

bool bg_create_key(public_parameters_t* pp, bg_private_key_t* private_key,
                   bg_public_key_t* public_key);

void bg_destroy_key(bg_private_key_t* private_key, bg_public_key_t* public_key);

void bg_free_signature(public_parameters_t* pp, bg_signature_t* signature);

bg_signature_t* bg_sign(public_parameters_t* pp, bg_private_key_t* private_key, mzd_t* m);

int bg_verify(public_parameters_t* pp, bg_public_key_t* public_key, mzd_t* m, bg_signature_t* sig);

#endif
