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

#include "randomness.h"
#include "parameters.h"

#include <openssl/rand.h>

void init_EVP() {
#if OPENSSL_VERSION_NUMBER >= 0x10100000
  OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_ADD_ALL_CIPHERS |
                          OPENSSL_INIT_ADD_ALL_DIGESTS,
                      NULL);
#else
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_config(NULL);
#endif
}

void cleanup_EVP() {
#if OPENSSL_VERSION_NUMBER >= 0x10100000
  OPENSSL_cleanup();
#else
  EVP_cleanup();
  ERR_free_strings();
#endif
}

void aes_prng_init(aes_prng_t* aes_prng, const unsigned char* key) {
  aes_prng->ctx = EVP_CIPHER_CTX_new();

  /* A 128 bit IV */
  static const unsigned char iv[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                       '8', '9', '0', '1', '2', '3', '4', '5'};
  EVP_EncryptInit_ex(aes_prng->ctx, EVP_aes_128_ctr(), NULL, key, iv);
}

void aes_prng_clear(aes_prng_t* aes_prng) {
  EVP_CIPHER_CTX_free(aes_prng->ctx);
}

void aes_prng_get_randomness(aes_prng_t* aes_prng, unsigned char* dst, size_t count) {
  static const unsigned char plaintext[16] = {'0'};

  EVP_CIPHER_CTX* ctx = aes_prng->ctx;

  int len = 0;
  for (; count >= 16; count -= 16, dst += 16) {
    EVP_EncryptUpdate(ctx, dst, &len, plaintext, sizeof(plaintext));
  }

  if (count) {
    EVP_EncryptUpdate(ctx, dst, &len, plaintext, count);
  }
}

// maybe seed with data from /dev/urandom

static aes_prng_t aes_prng;

void init_rand_bytes(void) {
  unsigned char key[PRNG_KEYSIZE];
  RAND_bytes(key, sizeof(key));

  aes_prng_init(&aes_prng, key);
}

int rand_bytes(unsigned char* dst, size_t len) {
  aes_prng_get_randomness(&aes_prng, dst, len);
  return 1;
}

void deinit_rand_bytes(void) {
  aes_prng_clear(&aes_prng);
}
