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

#ifndef SIGNATURE_FIS_H
#define SIGNATURE_FIS_H

#include "signature_common.h"

typedef struct {
  // pk = E_k(0)
  mzd_t* pk;
} fis_public_key_t;

typedef struct { lowmc_key_t* k; } fis_private_key_t;

typedef struct { proof_t* proof; } fis_signature_t;

unsigned fis_compute_sig_size(unsigned m, unsigned n, unsigned r, unsigned k);

unsigned char* fis_sig_to_char_array(public_parameters_t* pp, fis_signature_t* sig, unsigned* len);

fis_signature_t* fis_sig_from_char_array(public_parameters_t* pp, unsigned char* data);

void fis_create_key(public_parameters_t* pp, fis_private_key_t* private_key,
                    fis_public_key_t* public_key);

void fis_destroy_key(fis_private_key_t* private_key, fis_public_key_t* public_key);

fis_signature_t* fis_sign(public_parameters_t* pp, fis_private_key_t* private_key, char* m);

int fis_verify(public_parameters_t* pp, fis_public_key_t* public_key, char* m,
               fis_signature_t* sig);

void fis_free_signature(public_parameters_t* pp, fis_signature_t* signature);

#endif
