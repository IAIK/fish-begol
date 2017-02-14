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

#ifndef LOWMC_PARS_H
#define LOWMC_PARS_H

#include "mzd_additional.h"
#include <m4ri/m4ri.h>

typedef mzd_t lowmc_key_t;

typedef struct {
  mzd_t* x0;
  mzd_t* x1;
  mzd_t* x2;
  mzd_t* mask;
  mzd_t* maskInv;
} mask_t;

typedef struct {
  mzd_t* k_matrix;
  mzd_t* l_matrix;
  mzd_t* constant;

#ifdef NOSCR
  mzd_t* k_lookup;
  mzd_t* l_lookup;
#endif
} lowmc_round_t;

/**
 * Represents the LowMC parameters as in https://bitbucket.org/malb/lowmc-helib/src,
 * with the difference that key in a separate struct
 */
typedef struct {
  size_t m;
  size_t n;
  size_t r;
  size_t k;

  mask_t mask;

  mzd_t* k0_matrix;
#ifdef NOSCR
  mzd_t* k0_lookup;
#endif
  lowmc_round_t* rounds;
} lowmc_t;

/**
 * Generates a new LowMC instance (also including a key)
 *
 * \param m the number of sboxes
 * \param n the blocksize
 * \param r the number of rounds
 * \param k the keysize
 *
 * \return parameters defining a LowMC instance (including a key)
 */
lowmc_t* lowmc_init(size_t m, size_t n, size_t r, size_t k);

lowmc_key_t* lowmc_keygen(lowmc_t* lowmc);

/**
 * Frees the allocated LowMC parameters
 *
 * \param lowmc the LowMC parameters to be freed
 */
void lowmc_free(lowmc_t* lowmc);

/**
 * Frees the allocated LowMC key.
 *
 * \param lowmc_key the LowMC key to be freed
 */
void lowmc_key_free(lowmc_key_t* lowmc_key);

/**
 * Updates a given LowMC parameter instance so that the key is
 * split into three components representing the additive secret
 * sharing of LowMC
 *
 * \param lowmc the LowMC parameters
 */
void lowmc_secret_share(lowmc_t* lowmc, lowmc_key_t* lowmc_key);

#endif
