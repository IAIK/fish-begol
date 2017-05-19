#ifndef IO_H
#define IO_H

unsigned char* mzd_to_char_array(mzd_t* data, unsigned numbytes);

mzd_t* mzd_from_char_array(unsigned char* data, unsigned len, unsigned vec_len);

#endif
