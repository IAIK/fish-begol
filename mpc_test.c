#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <m4ri/m4ri.h>

#include "mpc_test.h"

#include "mpc.h"
#include "mzd_additional.h"
#include "multithreading.h"

static void test_mpc_share(void) {
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

static void test_mpc_add(void) {
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

void test_mzd_local_equal(void) {
  for (unsigned int i = 0; i < 10; ++i) {
    mzd_t* a = mzd_init_random_vector((i + 1) * 64);
    mzd_t* b = mzd_local_copy(NULL, a);

    if (mzd_local_equal(a, b)) {
      printf("equal: ok [%u]\n", (i + 1) * 64);
    }

    b = mzd_xor(b, b, a);
    if (mzd_local_equal(a, b))
      printf("equal: ok [%u]\n", (i + 1) * 64);

    mzd_local_free(a);
    mzd_local_free(b);
  }
}

static void test_mzd_mul(void) {
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

        if (mzd_cmp(r, r2) != 0) {
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

#ifdef WITH_OPT
#include "simd.h"
#endif

static void test_mzd_shift(void) {
#ifdef WITH_OPT
#ifdef WITH_SSE2
  if (CPU_SUPPORTS_SSE2) {
    mzd_t* v = mzd_local_init(1, 128);
    mzd_t* w = mzd_local_copy(NULL, v);
    mzd_t* r = mzd_local_copy(NULL, v);
    __m128i* wr = __builtin_assume_aligned(FIRST_ROW(w), 16);

    for (unsigned int i = 0; i < 32; ++i) {
      mzd_randomize_ssl(v);
      mzd_local_copy(w, v);

      mzd_shift_left(r, v, i);
      *wr = mm128_shift_left(*wr, i);

      if (mzd_cmp(r, w) != 0) {
        printf("lshift fail\nv = ");
        mzd_print(v);
        printf("r = ");
        mzd_print(r);
        printf("w = ");
        mzd_print(w);
      }
    }

    for (unsigned int i = 0; i < 32; ++i) {
      mzd_randomize_ssl(v);
      mzd_local_copy(w, v);

      mzd_shift_right(r, v, i);
      *wr = mm128_shift_right(*wr, i);

      if (mzd_cmp(r, w) != 0) {
        printf("rshift fail\nv = ");
        mzd_print(v);
        printf("r = ");
        mzd_print(r);
        printf("w = ");
        mzd_print(w);
      }
    }

    mzd_local_free(w);
    mzd_local_free(v);
    mzd_local_free(r);
  }
#endif
#ifdef WITH_AVX2
  if (CPU_SUPPORTS_AVX2) {
    mzd_t* v = mzd_local_init(1, 256);
    mzd_t* w = mzd_local_copy(NULL, v);
    mzd_t* r = mzd_local_copy(NULL, v);
    __m256i* wr = __builtin_assume_aligned(FIRST_ROW(w), 32);

    for (unsigned int i = 0; i < 32; ++i) {
      mzd_randomize_ssl(v);
      mzd_local_copy(w, v);

      mzd_shift_left(r, v, i);
      *wr = mm256_shift_left(*wr, i);

      if (mzd_cmp(r, w) != 0) {
        printf("lshift fail\nv = ");
        mzd_print(v);
        printf("r = ");
        mzd_print(r);
        printf("w = ");
        mzd_print(w);
      }
    }

    for (unsigned int i = 0; i < 32; ++i) {
      mzd_randomize_ssl(v);
      mzd_local_copy(w, v);

      mzd_shift_right(r, v, i);
      *wr = mm256_shift_right(*wr, i);

      if (mzd_cmp(r, w) != 0) {
        printf("rshift fail\nv = ");
        mzd_print(v);
        printf("r = ");
        mzd_print(r);
        printf("w = ");
        mzd_print(w);
      }
    }

    mzd_local_free(w);
    mzd_local_free(v);
    mzd_local_free(r);
  }
#endif
#endif
}

void run_tests(void) {
  (void) test_mpc_share;
  (void) test_mpc_add;
  (void) test_mzd_local_equal;
  (void) test_mzd_mul;
  (void) test_mzd_shift;

  // test_mpc_share();
  // test_mpc_add();
  // test_mzd_local_equal();
  // test_mzd_mul();
  test_mzd_shift();
}

int main() {
  init_rand_bytes();
  init_EVP();
  openmp_thread_setup();

  run_tests();

  openmp_thread_cleanup();
  cleanup_EVP();
  deinit_rand_bytes();

  return 0;
}
