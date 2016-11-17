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

#ifndef TIMING_H
#define TIMING_H

#include <stdint.h>
#include <time.h>

typedef union {
  struct {
    struct {
      uint64_t lowmc_init, keygen, pubkey;
    } gen;
    struct {
      uint64_t rand, secret_sharing, lowmc_enc, views, challenge;
    } sign;
    struct {
      uint64_t challenge, output_shares, output_views, verify;
    } verify;
    uint64_t size;
  };
  uint64_t data[13];
} timing_and_size_t;

extern timing_and_size_t* timing_and_size;

#ifdef WITH_DETAILED_TIMING

#define gettime gettime_clock
#define TIME_FUNCTION uint64_t start_time
#define START_TIMING start_time = gettime()
#define END_TIMING(dst) dst     = gettime() - start_time

#define TIMING_SCALE (1000000 / CLOCKS_PER_SEC);

#ifdef WITH_OPENMP
#include <omp.h>

static inline uint64_t gettime_clock() {
  return omp_get_wtime() * 1000 * 1000;
}
#else
static inline uint64_t gettime_clock() {
  return clock() * TIMING_SCALE;
}
#endif

#else

#define TIME_FUNCTION                                                                              \
  do {                                                                                             \
  } while (0)
#define START_TIMING                                                                               \
  do {                                                                                             \
  } while (0)
#define END_TIMING(dst)                                                                            \
  do {                                                                                             \
  } while (0)

#endif

#endif
