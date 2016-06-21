#include <m4ri/m4ri.h>


// I am a C programmer, deal with it
typedef struct {
  size_t m;
  size_t n;
  size_t r;
  size_t k;
  mzd_t *key;
  mzd_t **LMatrix;
  mzd_t **KMatrix;
  mzd_t **Constants;
  
} lowmc_t;

lowmc_t *lowmc_init(size_t m, size_t n, size_t r, size_t k);
mzd_t *lowmc_call(lowmc_t *lowmc, mzd_t *p);
void lowmc_free(lowmc_t *lowmc);
