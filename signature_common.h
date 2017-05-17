/*
 * fish-begol - Implementation of the Fish and Begol signature schemes
 * Copyright (C) 2016-2017 Graz University of Technology
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

#ifndef SIGNATURE_COMMON_H
#define SIGNATURE_COMMON_H

#include <stdbool.h>
#include <time.h>

#include "lowmc_pars.h"
#include "mpc_lowmc.h"

//#define VERBOSE

typedef struct {
  // The LowMC instance.
  mpc_lowmc_t* lowmc;
} public_parameters_t;

bool create_instance(public_parameters_t* pp, int m, int n, int r, int k);

void destroy_instance(public_parameters_t* pp);

void init_view(mpc_lowmc_t const* lowmc, view_t* views[NUM_ROUNDS]);
void free_view(mpc_lowmc_t const* lowmc, view_t* views[NUM_ROUNDS]);

#endif
