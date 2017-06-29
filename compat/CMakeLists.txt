set(COMPAT_SOURCES compat.c)
if(NOT HAVE_ALIGNED_ALLOC)
  set(COMPAT_SOURCES ${COMPAT_SOURCES} aligned_alloc.c)
endif()

add_library(compat STATIC ${COMPAT_SOURCES})
target_compile_definitions(compat PRIVATE HAVE_CONFIG_H)
