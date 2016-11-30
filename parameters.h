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

#ifndef PARAMETERS_H
#define PARAMETERS_H

#include <openssl/sha.h>

// Output of size of the random oracle (\rho)
#define COMMITMENT_LENGTH SHA256_DIGEST_LENGTH
// Size of the randomness for the commitment (\nu)
#define COMMITMENT_RAND_LENGTH 17

// Repetition count (\gamma)
#define NUM_ROUNDS 219
#define FIS_NUM_ROUNDS NUM_ROUNDS
#define BG_NUM_ROUNDS NUM_ROUNDS

// Share count for proofs
#define SC_PROOF 3
// Share count for verification
#define SC_VERIFY 2

#endif
