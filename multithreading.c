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

#include "multithreading.h"

#include <openssl/crypto.h>

/**
 * OpenMP integration of OpenSSL is based on
 * https://github.com/Sobuno/ZKBoo/blob/master/MPC_SHA256/shared.h.
 */

#if defined(WITH_OPENMP) && OPENSSL_VERSION_NUMBER < 0x10100000
#include <omp.h>

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

#if OPENSSL_VERSION_NUMBER < 0x10000000
static unsigned long openmp_thread_id(void) {
  return (unsigned long)omp_get_thread_num();
}
#endif

void openmp_thread_setup(void) {
  locks = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(omp_lock_t));
  for (int i = 0; i < CRYPTO_num_locks(); i++) {
    omp_init_lock(&locks[i]);
  }

#if OPENSSL_VERSION_NUMBER < 0x10000000
  CRYPTO_set_id_callback(openmp_thread_id);
#endif
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
