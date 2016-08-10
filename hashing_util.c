#include "hashing_util.h"
#include "mpc_lowmc.h"
#include "m4ri/m4ri.h"

/*
 * Computes the SHA256 hash of a view using openssl (similar as in 
 * https://github.com/Sobuno/ZKBoo/blob/master/MPC_SHA256/shared.h)
 */ 
void H(unsigned char k[16], mzd_t *y[3], view_t* v, unsigned vidx, unsigned vcnt, unsigned char r[4], unsigned char hash[SHA256_DIGEST_LENGTH]) {
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, k, 16);
  for(unsigned i = 0 ; i < 3 ; i++) 
    for (rci_t m = 0; m < y[i]->nrows; m++) 
      for(wi_t n = 0; n < y[i]->width ; n++)  
        SHA256_Update(&ctx, y[i]->rows[m] + n, sizeof(word));   
  for(unsigned i = 0 ; i < vcnt ; i++) 
    for (rci_t m = 0; m < v[i].s[vidx]->nrows; m++) 
      for(wi_t n = 0; n < v[i].s[vidx]->width ; n++)  
        SHA256_Update(&ctx, v[i].s[vidx]->rows[m] + n, sizeof(word));   
  SHA256_Update(&ctx, r, 4);
  SHA256_Final(hash, &ctx);
}

/**
 * Computes the challenge (as in https://github.com/Sobuno/ZKBoo/blob/master/MPC_SHA256/shared.h)
 */
void H3(unsigned char c[NUM_ROUNDS][3][SHA256_DIGEST_LENGTH], int* ch) {

  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_CTX ctx;
  SHA256_Init(&ctx);   
  SHA256_Update(&ctx, c, 3 * SHA256_DIGEST_LENGTH * NUM_ROUNDS);   
  SHA256_Final(hash, &ctx);

  //Pick bits from hash
  int i = 0;
  int bitTracker = 0;
  while(i < NUM_ROUNDS) {
    if(bitTracker >= SHA256_DIGEST_LENGTH*8) { //Generate new hash
      SHA256_Init(&ctx);
      SHA256_Update(&ctx, hash, sizeof(hash));
      SHA256_Final(hash, &ctx);
      bitTracker = 0;
      //printf("Generated new hash\n");
    }

    int b1 = GETBIT(hash[bitTracker/8], bitTracker % 8);
    int b2 = GETBIT(hash[(bitTracker+1)/8], (bitTracker+1) % 8);
    if(b1 == 0) {
      if(b2 == 0) {
        ch[i] = 0;
	bitTracker += 2;
	i++;
      } else {
        ch[i] = 1;
	bitTracker += 2;
	i++;
      }
    } else {
      if(b2 == 0) {
        ch[i] = 2;
	bitTracker += 2;
	i++;
      } else {
        bitTracker += 2;
      }
    }
  }
}
