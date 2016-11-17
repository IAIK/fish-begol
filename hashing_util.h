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

#ifndef HASHING_UTIL_H
#define HASHING_UTIL_H

#include "mpc_lowmc.h"
#include "parameters.h"

#define GETBIT(x, i) (((x) >> (i)) & 0x01)

void H(const unsigned char k[16], mzd_t* y[3], view_t const* v, unsigned vidx, unsigned vcnt,
       const unsigned char r[COMMITMENT_RAND_LENGTH], unsigned char hash[COMMITMENT_LENGTH]);

void fis_H3(unsigned char const h[NUM_ROUNDS][3][COMMITMENT_LENGTH], const char* m, unsigned m_len,
            unsigned char* ch);

void fis_H3_verify(unsigned char const h[NUM_ROUNDS][2][COMMITMENT_LENGTH],
                   unsigned char const hp[NUM_ROUNDS][COMMITMENT_LENGTH],
                   unsigned char const ch_in[(NUM_ROUNDS + 3) / 4], const char* m, unsigned m_len,
                   unsigned char* ch);

void bg_H3(const unsigned char c1[NUM_ROUNDS][3][COMMITMENT_LENGTH],
           const unsigned char c2[NUM_ROUNDS][3][COMMITMENT_LENGTH], unsigned char* ch);

void bg_H3_verify(unsigned char const h1[NUM_ROUNDS][2][COMMITMENT_LENGTH],
                  unsigned char const hp1[NUM_ROUNDS][COMMITMENT_LENGTH],
                  unsigned char const h2[NUM_ROUNDS][2][COMMITMENT_LENGTH],
                  unsigned char const hp2[NUM_ROUNDS][COMMITMENT_LENGTH],
                  unsigned char const ch_in[(NUM_ROUNDS + 3) / 4], unsigned char* ch);

unsigned int getChAt(unsigned char const* ch, unsigned int i);

#endif
