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
  
  if(!initialized) {
    RAND_bytes((unsigned char*) w, sizeof(word));
    initialized = 1;
  }

  if(count == 0) {
    RAND_bytes((unsigned char*) w, sizeof(word));
    count = 8 * sizeof(word);
  }
  
  BIT b = *w & 0x01;
  *w >>= 1;
  count--;
  return b;
} 

static void handleErrors(void) {
  ERR_print_errors_fp(stderr);
  abort();
}


static void _setupAES(EVP_CIPHER_CTX* ctx, unsigned char key[16]) {
  EVP_CIPHER_CTX_init(ctx);

  /* A 128 bit IV */
  unsigned char *iv = (unsigned char *)"01234567890123456";
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv))
    handleErrors();
}

void getRandomness(unsigned char key[16], unsigned char *randomness, unsigned count) {
  if(count % 16 != 0)
    exit(-1);

  EVP_CIPHER_CTX ctx;
  _setupAES(&ctx, key);
  unsigned char plaintext[16] = { '0' };
  int len;
  for(int j = 0 ; j < count / 16 ; j++) {
    if(1 != EVP_EncryptUpdate(&ctx, &randomness[j*16], &len, plaintext, sizeof(plaintext)))
      handleErrors();
  }
  EVP_CIPHER_CTX_cleanup(&ctx);
}

