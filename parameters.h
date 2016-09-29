#ifndef PARAMETERS_H
#define PARAMETERS_H

#include <openssl/sha.h>

// Output of size of the random oracle (\rho)
#define COMMITMENT_LENGTH SHA256_DIGEST_LENGTH
// Size of the randomness for the commitment (\nu)
#define COMMITMENT_RAND_LENGTH 17

// Repetition count (\gamma)
#define NUM_ROUNDS 219
#define FIS_NUM_ROUNDS NUM_ROUNDS
#define BG_NUM_ROUNDS NUM_ROUNDS

#endif
