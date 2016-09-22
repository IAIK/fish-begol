#ifndef PARAMETERS_H
#define PARAMETERS_H

#include <openssl/sha.h>

// Output of size of the random oracle (\gamma')
#define COMMITMENT_LENGTH SHA256_DIGEST_LENGTH
#define COMMITMENT_RAND_LENGTH 4

// Repetition count (\gamma)
#define NUM_ROUNDS 219
#define FIS_NUM_ROUNDS NUM_ROUNDS
#define BG_NUM_ROUNDS NUM_ROUNDS

#endif
