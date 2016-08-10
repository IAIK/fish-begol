#include "lowmc.h"
#include "mzd_additional.h"
#include "lowmc_pars.h"

void prepareMasks(mzd_t *first, mzd_t *second, mzd_t *third, mzd_t *mask, rci_t n, rci_t m) {
  if(0 != n % (8 * sizeof(word)))
    return;

  for(int i = 0 ; i < n - 3 * m ; i++) {
    mzd_write_bit(mask, 0, i, 1);
  }
  for(unsigned i = n - 3 * m; i < n ; i+=3) {
    mzd_write_bit(first,   0, i    , 1);
    mzd_write_bit(second,  0, i + 1, 1);
    mzd_write_bit(third,   0, i + 2, 1);
  }
}

word mzd_shift_right(mzd_t* res, mzd_t *val, unsigned count) {
  word prev = 0;
  if(res == 0) 
    res = mzd_init(1, val->ncols);
  
  for(int i = 0 ; i < val->ncols / (8 * sizeof(word)); i++) {
    res->rows[0][i] = (val->rows[0][i] >> count) | prev;
    prev = val->rows[0][i] << (8 * sizeof(word) - count);
  }

  return prev;
}

void sbox_layer_bitsliced(mzd_t *out, mzd_t *in, rci_t m) {
  mzd_copy(out, in);
   
  mzd_t *x0   = mzd_init(1, out->ncols);
  mzd_t *x1   = mzd_init(1, out->ncols);
  mzd_t *x2   = mzd_init(1, out->ncols);
  mzd_t *mask = mzd_init(1, out->ncols);
  prepareMasks(x0, x1, x2, mask, out->ncols, m);

  word prev0 = 0, prev1 = 0;
  for(unsigned i = 1 ; i < out->ncols / (8 * sizeof(word)) ; i++) {
    word x00 = in->rows[0][i] & x0->rows[0][i];
    word x10 = in->rows[0][i] & x1->rows[0][i];
    word x20 = in->rows[0][i] & x2->rows[0][i]; 
    x10 >>= 1;
    x20 >>= 2;  
 
    if(i < out->ncols / (8 * sizeof(word)) - 1) {
      if(x0->rows[0][i] & 0x8000000000000000) {
        if(in->rows[0][i + 1] & 0x01)
          x10 |= 0x8000000000000000;
        if(in->rows[0][i + 1] & 0x02)
          x20 |= 0x8000000000000000;
      } else if(x0->rows[0][i] & 0x4000000000000000) {
        if(in->rows[0][i + 1] & 0x01)
          x20 |= 0x4000000000000000;
      }
    }

    word t0 = (x10 & x20) ^ x00;
    word t1 = (x00 & x20) ^ x00 ^ x10;
    word t2 = (x00 & x10) ^ x00 ^ x10 ^ x20;
 
    out->rows[0][i] &= mask->rows[0][i];
    out->rows[0][i] ^= t0 ^ (t1 << 1) ^ (t2 << 2) ^ prev0 ^ prev1;  
   
    prev0 = (t1 & 0x8000000000000000) ? 1 : 0;
    prev1 = (t2 & 0x8000000000000000) ? 2 : (t2 & 0x4000000000000000) ? 1 : 0;
  } 
}

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
    sbox_layer_bitsliced(y, x, lowmc->m);
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

