#include "m4ri/m4ri.h"
#include "io.h"

unsigned char *toCharArray(mzd_t *data, short numbits, unsigned *len) {
  if(!numbits)
    return 0;

  *len = (numbits + 7) / 8;

  const unsigned vec_len         = data->ncols;
  const unsigned word_count      = vec_len / (8 * sizeof(word));
  const unsigned num_full_words  = *len / 8;
  const unsigned bytes_last_word = *len - (num_full_words * 8); 
  unsigned char *result = (unsigned char*)malloc(*len * sizeof(unsigned char));

//  printf("numbits: %d\n len: %d\n numwords: %d\n, bytes last word: %d\n", numbits, *len, num_full_words, bytes_last_word);
  mzd_print(data);
  word *d = data->rows[0];
  unsigned char *temp = result;
  int i = word_count - 1;
  for(; i > (word_count - 1) - num_full_words  ; i--) {
    memcpy(temp, &d[i], sizeof(word));
    temp += sizeof(word);
  }
  if(bytes_last_word) {
    unsigned char* in = ((unsigned char*)&d[i]) + (sizeof(word) - bytes_last_word);
    memcpy(temp, in, bytes_last_word);
  }
  return result;
}

mzd_t *fromCharArray(unsigned char *data, unsigned len, unsigned numbits, unsigned vec_len) {
  mzd_t *result = mzd_init(1, vec_len);

  const unsigned word_count      = vec_len / (8 * sizeof(word));
  const unsigned num_full_words  = len / 8;
  const unsigned bytes_last_word = len - (num_full_words * 8); 
  
  word *d  = result->rows[0];
  word *in = (word*)data;
  unsigned idx = word_count - 1;
  for(int i = 0 ; i < num_full_words ; i++) {
    memcpy(&d[idx], in, sizeof(word));
    in++;
    idx--;
  }
  if(bytes_last_word) {
    unsigned char* out = ((unsigned char*)&d[idx]) + (sizeof(word) - bytes_last_word);
    memcpy(out, in, bytes_last_word);
  }
  return result;
}
