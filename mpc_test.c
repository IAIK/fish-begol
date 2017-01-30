/*
 * fish-begol - Implementation of the Fish and Begol signature schemes
 * Copyright (C) 2016 Graz University of Technology
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "mpc_test.h"
#include "m4ri/m4ri.h"
#include "mpc.h"
#include "mzd_additional.h"

void test_mpc_share() {
  mzd_t* t1    = mzd_init_random_vector(10);
  mzd_t** s1   = mpc_init_share_vector(t1);
  mzd_t* t1cmb = mpc_reconstruct_from_share(NULL, s1);

  if (mzd_cmp(t1, t1cmb) == 0)
    printf("Share test successful.\n");

  mzd_local_free(t1);
  for (unsigned i = 0; i < 3; i++)
    mzd_local_free(s1[i]);
  mzd_local_free(t1cmb);
}

void test_mpc_add() {
  mzd_t* t1  = mzd_init_random_vector(10);
  mzd_t* t2  = mzd_init_random_vector(10);
  mzd_t* res = mzd_add(0, t1, t2);

  mzd_t** s1   = mpc_init_share_vector(t1);
  mzd_t** s2   = mpc_init_share_vector(t2);
  mzd_t** ress = mpc_init_empty_share_vector(10, 3);
  mpc_add(ress, s1, s2, 3);

  mzd_t* cmp = mpc_reconstruct_from_share(NULL, ress);

  if (mzd_cmp(res, cmp) == 0)
    printf("Shared add test successful.\n");

  mzd_local_free(t1);
  mzd_local_free(t2);
  mzd_local_free(res);
  for (unsigned i = 0; i < 3; i++) {
    mzd_local_free(s1[i]);
    mzd_local_free(s2[i]);
    mzd_local_free(ress[i]);
  }
  mzd_local_free(cmp);
}

void test_mzd_equal(void) {
  for (unsigned int i = 0; i < 10; ++i) {
    mzd_t* a = mzd_init_random_vector((i + 1) * 64);
    mzd_t* b = mzd_local_copy(NULL, a);

    if (mzd_equal(a, b) == 0) {
      printf("equal: ok [%u]\n", (i + 1) * 64);
    }

    b = mzd_xor(b, b, a);
    if (mzd_equal(a, b) != 0)
      printf("equal: ok [%u]\n", (i + 1) * 64);

    mzd_local_free(a);
    mzd_local_free(b);
  }
}

void test_mzd_mul(void) {
  for (unsigned int i = 1; i <= 10; ++i) {
    for (unsigned int j = 1; j <= 10; ++j) {
      mzd_t* A = mzd_local_init(i * 64, j * 64);
      mzd_t* v = mzd_local_init(1, i * 64);
      mzd_t* c = mzd_local_init(1, j * 64);

      mzd_randomize_ssl(A);
      mzd_randomize_ssl(v);
      mzd_randomize_ssl(c);

      mzd_t* c2 = mzd_local_copy(NULL, c);

      for (unsigned int k = 0; k < 3; ++k) {
        mzd_t* r  = mzd_mul_v(c, v, A);
        mzd_t* r2 = mzd_mul(c2, v, A, __M4RI_STRASSEN_MUL_CUTOFF);

        if (mzd_cmp(r, r2) == 0) {
          printf("mul: ok [%u x %u]\n", i * 64, j * 64);
        } else {
          printf("mul: fail [%u x %u]\n", i * 64, j * 64);
          printf("r =  ");
          mzd_print(r);
          printf("r2 = ");
          mzd_print(r2);
        }
      }

      mzd_local_free(A);
      mzd_local_free(v);
      mzd_local_free(c);

      mzd_local_free(c2);
    }
  }
}
