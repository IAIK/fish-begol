#include "lowmc_pars.h"
#include "mpc.h"
#include "mzd_additional.h"
#include "randomness.h"

#include <m4ri/m4ri.h>
#include <stdbool.h>

static mask_t* prepare_masks(mask_t* mask, rci_t n, rci_t m) {
  mask->x0   = mzd_local_init(1, n);
  mask->x1   = mzd_local_init_ex(1, n, false);
  mask->x2   = mzd_local_init_ex(1, n, false);
  mask->mask = mzd_local_init(1, n);

  const int bound = n - 3 * m;
  for (int i = 0; i < bound; ++i) {
    mzd_write_bit(mask->mask, 0, i, 1);
  }
  for (int i = bound; i < n; i += 3) {
    mzd_write_bit(mask->x0, 0, i, 1);
  }
  mzd_shift_left(mask->x1, mask->x0, 1);
  mzd_shift_left(mask->x2, mask->x0, 2);

  return mask;
}

static mzd_t* mzd_sample_matrix_word(rci_t n, rci_t k, rci_t rank, bool with_xor) {
  // use mzd_init for A since m4ri will work with it in mzd_echolonize
  // also, this function cannot be parallelized as mzd_echolonize will call
  // mzd_init and mzd_free at will causing various crashes.
  mzd_t* A = mzd_init(n, k);
  mzd_t* B = mzd_local_init_ex(n, k, false);
  do {
    mzd_randomize_ssl(A);
    if (with_xor) {
      for (rci_t i = 0; i < n; i++) {
        mzd_xor_bits(A, n - i - 1, (k + i + 1) % k, 1, 1);
      }
    }
    mzd_local_copy(B, A);
  } while (mzd_echelonize(A, 0) != rank);
  mzd_free(A);
  return B;
};

/**
 * Samples the L matrix for the LowMC instance
 *
 * \param n the blocksize
 */
static mzd_t* mzd_sample_lmatrix(rci_t n) {
  return mzd_sample_matrix_word(n, n, n, false);
}

/**
 * Samples the K matrix for the LowMC instance
 * \param n the blocksize
 */
static mzd_t* mzd_sample_kmatrix(rci_t n, rci_t k) {
  return mzd_sample_matrix_word(n, k, MIN(n, k), true);
}

lowmc_t* lowmc_init(size_t m, size_t n, size_t r, size_t k) {
  lowmc_t* ret = readFile(m, n, r, k);
  if (ret) {
    return ret;
  }

  lowmc_t* lowmc = calloc(sizeof(lowmc_t), 1);
  lowmc->m       = m;
  lowmc->n       = n;
  lowmc->r       = r;
  lowmc->k       = k;

  lowmc->k0_matrix = mzd_sample_kmatrix(k, n);
#ifdef NOSCR
  lowmc->k0_lookup = mzd_precompute_matrix_lookup(lowmc->k0_matrix);
#endif

  lowmc->rounds = calloc(sizeof(lowmc_round_t), r);
  for (unsigned int i = 0; i < r; ++i) {
    lowmc->rounds[i].l_matrix = mzd_sample_lmatrix(n);
    lowmc->rounds[i].k_matrix = mzd_sample_kmatrix(k, n);
    lowmc->rounds[i].constant = mzd_init_random_vector(n);

#ifdef NOSCR
    lowmc->rounds[i].l_lookup = mzd_precompute_matrix_lookup(lowmc->rounds[i].l_matrix);
    lowmc->rounds[i].k_lookup = mzd_precompute_matrix_lookup(lowmc->rounds[i].k_matrix);
#endif
  }

  if (!prepare_masks(&lowmc->mask, n, m)) {
    lowmc_free(lowmc);
    return NULL;
  }

  writeFile(lowmc);

  return lowmc;
}

lowmc_t* readFile(size_t m, size_t n, size_t r, size_t k) {

  lowmc_t* lowmc  = NULL;
  char* file_name = calloc(20, sizeof(char));
  sprintf(file_name, "%zu-%zu-%zu-%zu", m, n, r, k);
  FILE* file = fopen(file_name, "r+");
  free(file_name);
  if (file) {
    lowmc = calloc(1, sizeof(lowmc_t));

    int ret = 0;

    ret = fread(&lowmc->m, sizeof(lowmc->m), 1, file);
    ret += fread(&lowmc->n, sizeof(lowmc->n), 1, file);
    ret += fread(&lowmc->r, sizeof(lowmc->r), 1, file);
    ret += fread(&lowmc->k, sizeof(lowmc->k), 1, file);

    if (lowmc->m != m || lowmc->n != n || lowmc->r != r || lowmc->k != k) {
      printf("Error when reading file!\n");
      return NULL;
    }

    lowmc->mask.x0   = readMZD_TStructFromFile(file);
    lowmc->mask.x1   = readMZD_TStructFromFile(file);
    lowmc->mask.x2   = readMZD_TStructFromFile(file);
    lowmc->mask.mask = readMZD_TStructFromFile(file);

    lowmc->k0_matrix = readMZD_TStructFromFile(file);
#ifdef NOSCR
    lowmc->k0_lookup = readMZD_TStructFromFile(file);
#endif
    lowmc->rounds = calloc(r, sizeof(lowmc_round_t));
    for (size_t i = 0; i < lowmc->r; ++i) {
      lowmc->rounds[i].k_matrix = readMZD_TStructFromFile(file);
      lowmc->rounds[i].l_matrix = readMZD_TStructFromFile(file);
      lowmc->rounds[i].constant = readMZD_TStructFromFile(file);
#ifdef NOSCR
      lowmc->rounds[i].k_lookup = readMZD_TStructFromFile(file);
      lowmc->rounds[i].l_lookup = readMZD_TStructFromFile(file);
#endif
    }
    fclose(file);
  }

  return lowmc;
}

bool writeFile(lowmc_t* lowmc) {

  char* file_name = calloc(20, sizeof(char));
  sprintf(file_name, "%zu-%zu-%zu-%zu", lowmc->m, lowmc->n, lowmc->r, lowmc->k);
  FILE* file = fopen(file_name, "w");
  free(file_name);
  if (file) {
    fwrite(&lowmc->m, sizeof(lowmc->m), 1, file);
    fwrite(&lowmc->n, sizeof(lowmc->n), 1, file);
    fwrite(&lowmc->r, sizeof(lowmc->r), 1, file);
    fwrite(&lowmc->k, sizeof(lowmc->k), 1, file);

    writeMZD_TStructToFile(lowmc->mask.x0, file);
    writeMZD_TStructToFile(lowmc->mask.x1, file);
    writeMZD_TStructToFile(lowmc->mask.x2, file);
    writeMZD_TStructToFile(lowmc->mask.mask, file);

    writeMZD_TStructToFile(lowmc->k0_matrix, file);

#ifdef NOSCR
    writeMZD_TStructToFile(lowmc->k0_lookup, file);
#endif
    for (size_t i = 0; i < lowmc->r; ++i) {
      writeMZD_TStructToFile(lowmc->rounds[i].k_matrix, file);
      writeMZD_TStructToFile(lowmc->rounds[i].l_matrix, file);
      writeMZD_TStructToFile(lowmc->rounds[i].constant, file);
#ifdef NOSCR
      writeMZD_TStructToFile(lowmc->rounds[i].k_lookup, file);
      writeMZD_TStructToFile(lowmc->rounds[i].l_lookup, file);
#endif
    }
    fclose(file);
  }

  return false;
}

void writeMZD_TStructToFile(mzd_t* matrix, FILE* file) {

  fwrite(&(matrix->nrows), sizeof(rci_t), 1, file);
  fwrite(&(matrix->ncols), sizeof(rci_t), 1, file);
  fwrite(&(matrix->width), sizeof(wi_t), 1, file);
  fwrite(&(matrix->rowstride), sizeof(wi_t), 1, file);
  fwrite(&(matrix->offset_vector), sizeof(wi_t), 1, file);
  fwrite(&(matrix->row_offset), sizeof(wi_t), 1, file);
  fwrite(&(matrix->flags), sizeof(uint8_t), 1, file);
  fwrite(&(matrix->blockrows_log), sizeof(uint8_t), 1, file);
  fwrite(&(matrix->high_bitmask), sizeof(word), 1, file);

  for (int i = 0; i < matrix->nrows; i++) {
    fwrite((matrix->rows[i]), matrix->rowstride * sizeof(word), 1, file);
  }
}

mzd_t* readMZD_TStructFromFile(FILE* file) {

  int ret       = 0;
  int nrows     = 0;
  int ncols     = 0;
  int width     = 0;
  int rowstride = 0;
  ret += fread(&(nrows), sizeof(rci_t), 1, file);
  ret += fread(&(ncols), sizeof(rci_t), 1, file);
  ret += fread(&(width), sizeof(wi_t), 1, file);
  ret += fread(&(rowstride), sizeof(wi_t), 1, file);

  const rci_t width_cal = (ncols + m4ri_radix - 1) / m4ri_radix;
  rci_t rowstride_cal   = 0;

  // COPIED FROM MZD_ADDITIONAL.C
  if ((size_t)width_cal >= (256 / (8 * sizeof(word)))) {
    rowstride_cal = ((width_cal * sizeof(word) + 31) & ~31) / sizeof(word);
  } else {
    rowstride_cal = ((width_cal * sizeof(word) + 15) & ~15) / sizeof(word);
  }

  if (width != width_cal || rowstride != rowstride_cal) {
    printf("Error when reading file!\n");
  }

  const size_t buffer_size = nrows * rowstride * sizeof(word);
  const size_t rows_size   = nrows * sizeof(word*);

  static const size_t mzd_t_size = (sizeof(mzd_t) + 0x3f) & ~0x3f;
  unsigned char* buffer = aligned_alloc(32, (mzd_t_size + buffer_size + rows_size + 31) & ~31);

  mzd_t* A = (mzd_t*)buffer;
  buffer += mzd_t_size;

  memset(buffer, 0, buffer_size);

  A->nrows     = nrows;
  A->ncols     = ncols;
  A->width     = width;
  A->rowstride = rowstride;

  ret += fread(&(A->offset_vector), sizeof(wi_t), 1, file);
  ret += fread(&(A->row_offset), sizeof(wi_t), 1, file);
  ret += fread(&(A->flags), sizeof(uint8_t), 1, file);
  ret += fread(&(A->blockrows_log), sizeof(uint8_t), 1, file);
  ret += fread(&(A->high_bitmask), sizeof(word), 1, file);

  A->blocks = NULL;

  A->rows = (word**)(buffer + buffer_size);
  for (rci_t i = 0; i < nrows; ++i, buffer += rowstride * sizeof(word)) {
    A->rows[i] = (word*)(buffer);
  }

  for (int i = 0; i < A->nrows; i++) {
    ret += fread((A->rows[i]), A->rowstride * sizeof(word), 1, file);
  }

  return A;
}

lowmc_key_t* lowmc_keygen(lowmc_t* lowmc) {
  return mzd_init_random_vector(lowmc->k);
}

void lowmc_free(lowmc_t* lowmc) {
  for (unsigned i = 0; i < lowmc->r; ++i) {
#ifdef NOSCR
    mzd_local_free(lowmc->rounds[i].k_lookup);
    mzd_local_free(lowmc->rounds[i].l_lookup);
#endif
    mzd_local_free(lowmc->rounds[i].constant);
    mzd_local_free(lowmc->rounds[i].k_matrix);
    mzd_local_free(lowmc->rounds[i].l_matrix);
  }
#ifdef NOSCR
  mzd_local_free(lowmc->k0_lookup);
#endif
  mzd_local_free(lowmc->k0_matrix);
  free(lowmc->rounds);

  mzd_local_free(lowmc->mask.x0);
  mzd_local_free(lowmc->mask.x1);
  mzd_local_free(lowmc->mask.x2);
  mzd_local_free(lowmc->mask.mask);

  free(lowmc);
}

void lowmc_key_free(lowmc_key_t* lowmc_key) {
  mzd_local_free(lowmc_key);
}
