#include "timing.h"

#include <time.h>

timing_and_size_t timing_and_size;

#ifdef WITH_DETAILED_TIMING

#define TIMING_SCALE 1000000 / CLOCKS_PER_SEC;

uint64_t gettime() {
  return clock() * TIMING_SCALE;
}

#endif
