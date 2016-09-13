#include "randomness.h"

#include <openssl/rand.h>

void init_EVP() {
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_config(NULL);
}

void cleanup_EVP() {
  EVP_cleanup();
  ERR_free_strings();
}

BIT getrandbit() {
  static int initialized = 0;
  static word w[1];
  static int count = 8 * sizeof(word);

  if (!initialized) {
    RAND_bytes((unsigned char*)w, sizeof(word));
    initialized = 1;
  }

  if (count == 0) {
    RAND_bytes((unsigned char*)w, sizeof(word));
    count = 8 * sizeof(word);
  }

  BIT b = *w & 0x01;
  *w >>= 1;
  count--;
  return b;
}

static void __attribute__((noreturn)) handleErrors(void) {
  ERR_print_errors_fp(stderr);
  abort();
}

struct aes_prng_s {
  EVP_CIPHER_CTX* ctx;
};

aes_prng_t* aes_prng_init(const unsigned char* key) {
  aes_prng_t* aes_prng = malloc(sizeof(aes_prng_t));
  aes_prng->ctx        = EVP_CIPHER_CTX_new();

  /* A 128 bit IV */
  static const unsigned char iv[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                       '8', '9', '0', '1', '2', '3', '4', '5'};
  if (1 != EVP_EncryptInit_ex(aes_prng->ctx, EVP_aes_128_ctr(), NULL, key, iv))
    handleErrors();

  return aes_prng;
}

void aes_prng_free(aes_prng_t* aes_prng) {
  if (!aes_prng) {
    return;
  }

  EVP_CIPHER_CTX_free(aes_prng->ctx);
  free(aes_prng);
}

#define unlikely(p) __builtin_expect(!!(p), 0)

void aes_prng_get_randomness(aes_prng_t* aes_prng, unsigned char* dst, unsigned int count) {
  static const unsigned char plaintext[16] = {'0'};

  EVP_CIPHER_CTX* ctx = aes_prng->ctx;

  int len = 0;
  for (; count >= 16; count -= 16, dst += 16) {
    if (unlikely(1 != EVP_EncryptUpdate(ctx, dst, &len, plaintext, sizeof(plaintext)))) {
      handleErrors();
    }
  }

  if (count) {
    if (unlikely(1 != (EVP_EncryptUpdate(ctx, dst, &len, plaintext, count), 1))) {
      handleErrors();
    }
  }
}

// maybe seed with data from /dev/urandom

void init_rand_bytes(void) {}

int rand_bytes(unsigned char* dst, size_t len) {
  return RAND_bytes(dst, len);
}

void deinit_rand_bytes(void) {}

