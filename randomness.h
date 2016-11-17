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

#ifndef RANDOMNESS_H
#define RANDOMNESS_H

#include <m4ri/m4ri.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdint.h>

void init_EVP();
void cleanup_EVP();

typedef struct { EVP_CIPHER_CTX* ctx; } aes_prng_t;

void aes_prng_init(aes_prng_t* aes_prng, const unsigned char* key);
void aes_prng_clear(aes_prng_t* aes_prng);
void aes_prng_get_randomness(aes_prng_t* aes_prng, unsigned char* dst, size_t count);

void init_rand_bytes(void);
void deinit_rand_bytes(void);
int rand_bytes(unsigned char* dst, size_t len);

#endif
