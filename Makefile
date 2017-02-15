CC=gcc

# CPPFLAGS+=-DVERBOSE
CPPFLAGS+=-DWITH_OPT
CPPFLAGS+=-DWITH_DETAILED_TIMING
CPPFLAGS+=-DM4RI_VERSION=$(shell pkg-config --modversion m4ri)
CPPFLAGS+=-DNOSCR
CFLAGS+=-g
CFLAGS+=-O3
CFLAGS+=-std=c11
CFLAGS+=-Wall
CFLAGS+=-march=native
CFLAGS+=-mtune=native
LDFLAGS+=-flto
LDLIBS+=-lm4ri
LDLIBS+=-lcrypto

WITH_SSE2 ?= $(shell $(CC) $(CFLAGS) -dM -E - < /dev/null | grep -q "SSE2" && echo 1 || echo 0)
WITH_SSE4_1 ?= $(shell $(CC) $(CFLAGS) -dM -E - < /dev/null | grep -q "SSE4_1" && echo 1 || echo 0)
WITH_AVX2 ?= $(shell $(CC) $(CFLAGS) -dM -E - < /dev/null | grep -q "AVX2" && echo 1 || echo 0)

ifneq ($(WITH_SSE2),0)
CPPFLAGS+=-DWITH_SSE2
endif
ifneq ($(WITH_SSE4_1),0)
CPPFLAGS+=-DWITH_SSE4_1
endif
ifneq ($(WITH_AVX2),0)
CPPFLAGS+=-DWITH_AVX2
endif

SOURCES=$(sort $(wildcard *.c))
HEADERS=$(sort $(wildcard *.h))

TIMING_SOURCES=$(wildcard timing/*.py)
TIMING_INSTANCES=$(wildcard timing/lowmc-*-*-*.txt) $(wildcard timing/pq-lowmc-*-*-*.txt)

all: mpc_lowmc mpc_lowmc_pq mpc_lowmc_openmp mpc_lowmc_pq_openmp

mpc_lowmc mpc_lowmc_pq mpc_lowmc_openmp mpc_lowmc_pq_openmp: $(SOURCES) $(HEADERS) Makefile

mpc_lowmc: CFLAGS+=-Wno-unknown-pragmas
mpc_lowmc_pq: CPPFLAGS+=-DWITH_PQ_PARAMETERS
mpc_lowmc_pq: CFLAGS+=-Wno-unknown-pragmas
mpc_lowmc_openmp: CPPFLAGS+=-DWITH_OPENMP
mpc_lowmc_openmp: CFLAGS+=-fopenmp
mpc_lowmc_pq_openmp: CPPFLAGS+=-DWITH_PQ_PARAMETERS -DWITH_OPENMP
mpc_lowmc_pq_openmp: CFLAGS+=-fopenmp

mpc_lowmc mpc_lowmc_pq mpc_lowmc_openmp mpc_lowmc_pq_openmp:
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SOURCES) $(LDFLAGS) $(LDLIBS) -o $@

clean:
	rm -f *.o *.gch mpc_lowmc mpc_lowmc_pq mpc_lowmc_openmp mpc_lowmc_pq_openmp

# create anonymized source files
dist:
	mkdir -p temp-clean/timing
	cp Makefile temp-clean
	cp README.md.anon temp-clean/README.md
	cp $(TIMING_INSTANCES) timing/Makefile temp-clean/timing
	for f in $(SOURCES) $(HEADERS) ; do \
		awk 'NR >= 19' $$f > temp-clean/$$f; \
	done
	for f in $(TIMING_SOURCES) ; do \
		awk 'NR < 2 || NR >= 18' $$f > temp-clean/$$f; \
	done
	(cd temp-clean && zip $(CURDIR)/../source.zip \
		$(SOURCES) $(HEADERS) Makefile README.md \
		$(TIMING_SOURCES) timing/Makefile \
		$(TIMING_INSTANCES))
	rm -rf temp-clean
