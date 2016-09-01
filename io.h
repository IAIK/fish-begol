#ifndef IO_H
#define IO_H

unsigned char *toCharArray(mzd_t *data, short numbits, unsigned *len);

mzd_t *fromCharArray(unsigned char *data, unsigned len, unsigned numbits, unsigned vec_len);
 
#endif
