#include "lowmc.h"
#include "mzd_additional.h"
#include "lowmc_pars.h"

void sbox_layer(mzd_t *out, mzd_t *in, rci_t m) {
  mzd_copy(out, in);
  for(rci_t n=out->ncols-3*m; n<out->ncols; n+=3) {
    word x0 = mzd_read_bit(in, 0, n+0);
    word x1 = mzd_read_bit(in, 0, n+1);
    word x2 = mzd_read_bit(in, 0, n+2);

    mzd_write_bit(out, 0, n+0, (x1&x2) ^ x0);
    mzd_write_bit(out, 0, n+1, (x0&x2) ^ x0 ^ x1);
    mzd_write_bit(out, 0, n+2, (x0&x1) ^ x0 ^ x1 ^ x2);
  }
}

mzd_t *lowmc_call(lowmc_t *lowmc, lowmc_key_t *lowmc_key, mzd_t *p) {
  mzd_t *c = mzd_init(1, lowmc->n);

  mzd_t *x = mzd_init(1, lowmc->n);
  mzd_t *y = mzd_init(1, lowmc->n);
  mzd_t *z = mzd_init(1, lowmc->n);

  mzd_copy(x, p);
  mzd_addmul(x, lowmc_key->key[0], lowmc->KMatrix[0], 0);

  for(unsigned i=0; i<lowmc->r; i++) {
    sbox_layer(y, x, lowmc->m);
    mzd_mul(z, y, lowmc->LMatrix[i], 0);
    mzd_add(z, z, lowmc->Constants[i]);
    mzd_addmul(z, lowmc_key->key[0], lowmc->KMatrix[i+1], 0);
    mzd_copy(x, z);
  }
 
  mzd_copy(c, x);

  mzd_free(z);
  mzd_free(y);
  mzd_free(x);
  return c;
}

