#ifndef PARAMETERS_H
#define PARAMETERS_H

#include <openssl/sha.h>

#define COMMITMENT_LENGTH SHA256_DIGEST_LENGTH
#define NUM_ROUNDS 219
#define FIS_NUM_ROUNDS NUM_ROUNDS
#define BG_NUM_ROUNDS NUM_ROUNDS

#endif