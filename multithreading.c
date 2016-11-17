#include "multithreading.h"

/**
 * OpenMP integration of OpenSSL is based on
 * https://github.com/Sobuno/ZKBoo/blob/master/MPC_SHA256/shared.h.
 */

#ifdef WITH_OPENMP
#include <omp.h>
#include <openssl/crypto.h>

static omp_lock_t* locks = NULL;

static void openmp_locking_callback(int mode, int type, const char* file, int line) {
  (void)file;
  (void)line;
  if (mode & CRYPTO_LOCK) {
    omp_set_lock(&locks[type]);
  } else {
    omp_unset_lock(&locks[type]);
  }
}

static unsigned long openmp_thread_id(void) {
  return (unsigned long)omp_get_thread_num();
}

void openmp_thread_setup(void) {
  locks = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(omp_lock_t));
  for (int i = 0; i < CRYPTO_num_locks(); i++) {
    omp_init_lock(&locks[i]);
  }

  CRYPTO_set_id_callback(openmp_thread_id);
  CRYPTO_set_locking_callback(openmp_locking_callback);
}

void openmp_thread_cleanup(void) {
  CRYPTO_set_id_callback(NULL);
  CRYPTO_set_locking_callback(NULL);
  for (int i = 0; i < CRYPTO_num_locks(); i++)
    omp_destroy_lock(&locks[i]);
  OPENSSL_free(locks);
}

#else
void openmp_thread_setup(void) {}

void openmp_thread_cleanup(void) {}
#endif
