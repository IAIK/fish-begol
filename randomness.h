#ifndef RANDOMNESS_H
#define RANDOMNESS_H
 
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <m4ri/m4ri.h>

void init_EVP();

void cleanup_EVP();

/**
 * Returns a random bit
 */
BIT getrandbit();

typedef struct aes_prng_s aes_prng_t;

aes_prng_t* aes_prng_init(unsigned char* key);
void aes_prng_free(aes_prng_t* aes_prng);
void aes_prng_get_randomness(aes_prng_t* aes_prng, unsigned char* dst, unsigned int count);

/**
 * Writes count pseudorandom bytes to the pre-initialized randomness array
 *
 * \param key        the key
 * \param randomness the preinitialized randomness array
 * \param count      the number of random bytes to be written to randomness
 *
 */
void getRandomness(unsigned char key[16], unsigned char *randomness, unsigned count);

#endif
