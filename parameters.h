#ifndef PARAMETERS_H
#define PARAMETERS_H

#include <openssl/sha.h>

// Output of size of the random oracle (\rho)
#define COMMITMENT_LENGTH SHA256_DIGEST_LENGTH
// Size of the randomness for the commitment (\nu)
#define COMMITMENT_RAND_LENGTH 0

// Repetition count (\gamma)
#ifdef WITH_PQ_PARAMETERS
#define NUM_ROUNDS 438
#else
#define NUM_ROUNDS 219
#endif

#define FIS_NUM_ROUNDS NUM_ROUNDS
#define BG_NUM_ROUNDS NUM_ROUNDS

// Share count for proofs
#define SC_PROOF 3
// Share count for verification
#define SC_VERIFY 2

// Key size for PRNG
#define PRNG_KEYSIZE 16

#endif
