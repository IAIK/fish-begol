#include <m4ri/m4ri.h>

// Modifications to reference implementation
//
// mzd_t *key => mzd_t **key to account for secret shared keys
//
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


