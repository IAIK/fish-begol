#ifndef HASHING_UTIL_H
#define HASHING_UTIL_H

#include "mpc_lowmc.h"
#include <openssl/sha.h>

#define GETBIT(x, i) (((x) >> (i)) & 0x01)

void H(unsigned char k[16], mzd_t *y[3], view_t* v, unsigned vidx, unsigned vcnt, unsigned char r[4], unsigned char hash[SHA256_DIGEST_LENGTH]);

void H3(unsigned char c[NUM_ROUNDS][3][SHA256_DIGEST_LENGTH], int* ch);

void H4(unsigned char c1[NUM_ROUNDS][3][SHA256_DIGEST_LENGTH], unsigned char c2[NUM_ROUNDS][3][SHA256_DIGEST_LENGTH], int* ch);

#endif
