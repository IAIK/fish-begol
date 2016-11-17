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

#include <m4ri/m4ri.h>

#include "io.h"
#include "mzd_additional.h"

unsigned char* mzd_to_char_array(mzd_t* data, unsigned numbytes) {
  if (!numbytes)
    return 0;

  const unsigned vec_len         = data->ncols;
  const unsigned word_count      = vec_len / (8 * sizeof(word));
  const unsigned num_full_words  = numbytes / 8;
  const unsigned bytes_last_word = numbytes - (num_full_words * 8);
  unsigned char* result          = (unsigned char*)malloc(numbytes * sizeof(unsigned char));

  word* d             = data->rows[0];
  unsigned char* temp = result;
  int i               = word_count - 1;
  int j               = i - num_full_words;
  for (; i > j; i--) {
    memcpy(temp, &d[i], sizeof(word));
    temp += sizeof(word);
  }
  if (bytes_last_word) {
    unsigned char* in = ((unsigned char*)&d[i]) + (sizeof(word) - bytes_last_word);
    memcpy(temp, in, bytes_last_word);
  }
  return result;
}

mzd_t* mzd_from_char_array(unsigned char* data, unsigned len, unsigned vec_len) {
  mzd_t* result = mzd_local_init(1, vec_len);

  const unsigned word_count      = vec_len / (8 * sizeof(word));
  const unsigned num_full_words  = len / 8;
  const unsigned bytes_last_word = len - (num_full_words * 8);

  word* d      = result->rows[0];
  word* in     = (word*)data;
  unsigned idx = word_count - 1;
  for (unsigned i = 0; i < num_full_words; i++) {
    memcpy(&d[idx], in, sizeof(word));
    in++;
    idx--;
  }
  if (bytes_last_word) {
    unsigned char* out = ((unsigned char*)&d[idx]) + (sizeof(word) - bytes_last_word);
    memcpy(out, in, bytes_last_word);
  }
  return result;
}
