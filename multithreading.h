#ifndef MULTITHREADING_H
#define MULTITHREADING_H

#include "omp.h"
#include "openssl/crypto.h"

omp_lock_t *locks;

void openmp_locking_callback(int mode, int type, char *file, int line);

unsigned long openmp_thread_id(void);

void openmp_thread_setup(void);

void openmp_thread_cleanup(void);

#endif 
