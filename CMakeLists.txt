cmake_minimum_required(VERSION 3.1 FATAL_ERROR)

# cmake setup
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(picnic C)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING
      "Choose the type of build." FORCE)
endif()

# set required C standard version
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# required fuctions
include(CheckFunctionExists)
include(CheckCCompilerFlag)
include(CheckIncludeFiles)
include(CheckSymbolExists)

# required libraries
find_package(OpenSSL REQUIRED)
find_package(m4ri REQUIRED)
set(M4RI_VERSION M4RI_VERSION_STRING)

# check headers
check_include_files(immintrin.h HAVE_IMMINTRIN_H)

# check availability of some functions
check_symbol_exists(aligned_alloc stdlib.h HAVE_ALIGNED_ALLOC)
check_symbol_exists(posix_memalign stdlib.h HAVE_POSIX_MEMALIGN)
check_symbol_exists(memalign malloc.h HAVE_MEMALIGN)

# check supported compiler flags
check_c_compiler_flag(-march=native CC_SUPPORTS_MARCH_NATIVE)
check_c_compiler_flag(-mtune=native CC_SUPPORTS_MTUNE_NATIVE)
check_c_compiler_flag(-O3 CC_SUPPORTS_03)

# user-settable options
set(WITH_SIMD_OPT ON CACHE BOOL "Enable optimizations via SIMD.")
set(WITH_AVX2 ON CACHE BOOL "Use AVX2 if available.")
set(WITH_SSE2 ON CACHE BOOL "Use SSE2 if available.")
set(WITH_SSE4_1 ON CACHE BOOL "Use SSE4.1 if available.")
set(WITH_MARCH_NATIVE ON CACHE BOOL "Build with -march=native -mtune=native (if supported).")
set(WITH_LTO ON CACHE BOOL "Enable link-time optimization (if supported).")
set(WITH_PQ_PARAMETERS ON CACHE BOOL "Use PQ parameters.")
set(WITH_OPENMP OFF CACHE BOOL "Use OpenMP.")

# enable -march=native -mtune=native if supported
if(WITH_MARCH_NATIVE)
  if (CC_SUPPORTS_MARCH_NATIVE)
    add_compile_options("-march=native")
  endif()
  if (CC_SUPPORTS_MTUNE_NATIVE)
    add_compile_options("-mtune=native")
  endif()
endif()

# enable LTO if supported
if(WITH_LTO)
  if ("${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION}" VERSION_LESS 3.9)
    if(CMAKE_COMPILER_IS_GNUCC)
      set(CMAKE_AR "gcc-ar")
      set(CMAKE_C_ARCHIVE_CREATE "<CMAKE_AR> qcs <TARGET> <LINK_FLAGS> <OBJECTS>")
      set(CMAKE_C_ARCHIVE_FINISH true)
    endif()

    check_c_compiler_flag(-flto CC_SUPPORTS_FLTO)
    if(CC_SUPPORTS_FLTO)
      set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -flto")
      set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -flto")
    endif()
  else()
    include(CheckIPOSupprt)
    check_ipo_support(RESULT LTO_SUPPORTED)
    if (LTO_SUPPORTED)
      set(CMAKE_INTINTERPROCEDURAL_OPTIMIZATION TRUE)
    endif()
  endif()
endif()

# enable OpenMP if supported
if(WITH_OPENMP)
  include(FindOpenMP)
  if(NOT OPENMP_FOUND)
    message(WARNING "OpenMP requested, but not supported.")
  else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
  endif()
endif()

# enable -O3
if(WITH_SIMD_OPT AND CC_SUPPORTS_03)
  add_compile_options(-O3)
endif()

configure_file(config.h.in config.h)
include_directories(${CMAKE_CURRENT_BINARY_DIR} compat)

add_subdirectory(compat)

set(PICNIC_SOURCES
    hashing_util.c
    io.c
    lowmc.c
    lowmc_pars.c
    mpc.c
    mpc_lowmc.c
    multithreading.c
    mzd_additional.c
    mzd_shared.c
    randomness.c
    signature_common.c
    signature_fis.c
    timing.c)
add_library(picnic STATIC ${PICNIC_SOURCES})
target_link_libraries(picnic OpenSSL::Crypto ${M4RI_LIBRARY} compat)

target_compile_definitions(picnic PRIVATE HAVE_CONFIG_H)
target_compile_definitions(picnic PRIVATE WITH_DETAILED_TIMING)
if(WITH_SIMD_OPT AND HAVE_IMMINTRIN_H)
  target_compile_definitions(picnic PRIVATE WITH_OPT)
  target_compile_definitions(picnic PRIVATE NOSCR)
  if(WITH_SSE2)
    target_compile_definitions(picnic PRIVATE WITH_SSE2)
    if(WITH_SSE4_1)
      target_compile_definitions(picnic PRIVATE WITH_SSE4_1)
    endif()
  endif()
  if(WITH_AVX2)
    target_compile_definitions(picnic PRIVATE WITH_AVX2)
  endif()
endif()
if(WITH_PQ_PARAMETERS)
  target_compile_definitions(picnic PRIVATE WITH_PQ_PARAMETERS)
endif()

add_executable(bench main.c)
target_link_libraries(bench picnic)
target_compile_definitions(bench PRIVATE HAVE_CONFIG_H)

add_executable(mpc_test mpc_test.c)
target_link_libraries(mpc_test picnic)
target_compile_definitions(mpc_test PRIVATE HAVE_CONFIG_H)
