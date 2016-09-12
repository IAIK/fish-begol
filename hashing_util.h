#ifndef HASHING_UTIL_H
#define HASHING_UTIL_H

#include "mpc_lowmc.h"
#include <openssl/sha.h>

#define GETBIT(x, i) (((x) >> (i)) & 0x01)

void H(const unsigned char k[16], mzd_t *y[3], view_t const* v, unsigned vidx, 
    unsigned vcnt, const unsigned char r[4],
    unsigned char hash[SHA256_DIGEST_LENGTH]);

void fis_H3(unsigned char h[NUM_ROUNDS][3][SHA256_DIGEST_LENGTH], char *m, 
         unsigned m_len, int* ch);

void fis_H3_verify(unsigned char h[NUM_ROUNDS][2][SHA256_DIGEST_LENGTH], 
                unsigned char hp[NUM_ROUNDS][SHA256_DIGEST_LENGTH], 
                unsigned char ch_in[(NUM_ROUNDS + 3) / 4], char *m, 
                unsigned m_len, int* ch);

void bg_H3(const unsigned char c1[NUM_ROUNDS][3][SHA256_DIGEST_LENGTH], 
        const unsigned char c2[NUM_ROUNDS][3][SHA256_DIGEST_LENGTH], int* ch);

void bg_H3_verify(unsigned char const h1[NUM_ROUNDS][2][SHA256_DIGEST_LENGTH], 
               unsigned char const hp1[NUM_ROUNDS][SHA256_DIGEST_LENGTH], 
               unsigned char const h2[NUM_ROUNDS][2][SHA256_DIGEST_LENGTH], 
               unsigned char const hp2[NUM_ROUNDS][SHA256_DIGEST_LENGTH],
               unsigned char const ch_in[(NUM_ROUNDS + 3) / 4], int* ch);

#endif
