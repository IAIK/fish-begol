#include "lowmc.h"
#include "mzd_additional.h"
#include "lowmc_pars.h"

void sbox_layer(mzd_t *out, mzd_t *in, rci_t m) {
  mzd_copy(out, in);
  for(rci_t n=out->nrows-3*m; n<out->nrows; n+=3) {
    word x0 = mzd_read_bit(in, n+0, 0);
    word x1 = mzd_read_bit(in, n+1, 0);
    word x2 = mzd_read_bit(in, n+2, 0);

    mzd_write_bit(out, n+0, 0, x1&x2 ^ x0);
    mzd_write_bit(out, n+1, 0, x0&x2 ^ x0 ^ x1);
    mzd_write_bit(out, n+2, 0, x0&x1 ^ x0 ^ x1 ^ x2);
  }
}

mzd_t *lowmc_call(lowmc_t *lowmc, mzd_t *p) {
  mzd_t *c = mzd_init(lowmc->n,1);

  mzd_t *x = mzd_init(lowmc->n,1);
  mzd_t *y = mzd_init(lowmc->n,1);
  mzd_t *z = mzd_init(lowmc->n,1);

  mzd_copy(x, p);
  mzd_addmul(x, lowmc->KMatrix[0], lowmc->key[0], 0);

  for(int i=0; i<lowmc->r; i++) {
    sbox_layer(y, x, lowmc->m);
    mzd_mul(z, lowmc->LMatrix[i], y, 0);
    mzd_add(z, z, lowmc->Constants[i]);
    mzd_addmul(z, lowmc->KMatrix[i+1], lowmc->key[0], 0);
    mzd_copy(x, z);
  }
 
  mzd_copy(c, x);

  mzd_free(z);
  mzd_free(y);
  mzd_free(x);
  return c;
}

