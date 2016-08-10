#include "mzd_additional.h"
#include "randomness.h"

mzd_t *mzd_init_random_vector(rci_t n) {
  mzd_t *A = mzd_init(1,n);
  for(rci_t i=0; i<n; i++)
    mzd_write_bit(A, 0, n-i-1, getrandbit());
  return A;
}

mzd_t **mzd_init_random_vectors_from_seed(unsigned char key[16], rci_t n, unsigned count) {
  if(n % 8 != 0)
    exit(-1);
  
  unsigned char *randomness = (unsigned char*)malloc(n / 8 * count * sizeof(unsigned char));
  getRandomness(key, randomness, n / 8 * count * sizeof(unsigned char));

  mzd_t **vectors = (mzd_t**)malloc(count * sizeof(mzd_t*));
  unsigned j = 0;
  for(int v = 0 ; v < count ; v++) {
    vectors[v] = mzd_init(1, n);
    for(int i = 0 ; i < n ; i++) {
      mzd_write_bit(vectors[v], 0, i, randomness[j] & 0x01);
      randomness[j] >>= 1;
      if(((i + 1) % 8) == 0) {
        j++;
      }
    }
  }
  
  return vectors;
}
