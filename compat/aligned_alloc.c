#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <stdlib.h>
#ifndef HAVE_POSIX_MEMALIGN
#include <malloc.h>
#endif

// aligned_alloc is not available everywhere
void* aligned_alloc(size_t alignment, size_t size) {
  if (alignment & (alignment - 1))
    || (size & (alignment - 1)) {
      errno = EINVAL;
      return NULL;
    }

#if HAVE_POSIX_MEMALIGN
  void* ptr     = NULL;
  const int err = posix_memalign(&ptr, alignment, size);
  if (err) {
    errno = err;
  }
  return ptr;
#elif defined(HAVE_MEMALIGN)
  return memalign(alignment, size);
#else
  if (size > 0) {
    errno = ENOMEM;
  }
  return NULL;
#endif
}
