#include "mzd_additional.h"
#include "randomness.h"

mzd_t *mzd_init_random_vector(rci_t n) {
  mzd_t *A = mzd_init(n,1);
  for(rci_t i=0; i<n; i++)
    mzd_write_bit(A, n-i-1, 0, getrandbit());
  return A;
}
