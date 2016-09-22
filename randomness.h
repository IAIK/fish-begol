#ifndef RANDOMNESS_H
#define RANDOMNESS_H

#include <m4ri/m4ri.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdint.h>

void init_EVP();

void cleanup_EVP();

/**
 * Returns a random bit
 */
BIT getrandbit();

typedef struct  {
  EVP_CIPHER_CTX* ctx;
} aes_prng_t;

void aes_prng_init(aes_prng_t* aes_prng, const unsigned char* key);
void aes_prng_clear(aes_prng_t* aes_prng);
void aes_prng_get_randomness(aes_prng_t* aes_prng, unsigned char* dst, unsigned int count);

void init_rand_bytes(void);
void deinit_rand_bytes(void);
int rand_bytes(unsigned char* dst, size_t len);

#endif
