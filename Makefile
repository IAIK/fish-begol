CC=gcc

# CPPFLAGS+=-DVERBOSE
CPPFLAGS+=-DWITH_OPT
CPPFLAGS+=-DWITH_DETAILED_TIMING
CFLAGS+=-g
CFLAGS+=-O3
CFLAGS+=-std=c11
CFLAGS+=-Wall
CFLAGS+=-march=native
CFLAGS+=-mtune=native
CFLAGS+=-msse2avx
LDFLAGS+=-flto
LDLIBS+=-lm4ri -lcrypto

SOURCES=$(wildcard *.c)
HEADERS=$(wildcard *.h)

TIMING_SOURCES=$(wildcard timing/*.py)
TIMING_INSTANCES=$(wildcard timing/lowmc-*-*-*.txt) $(wildcard timing/pq-lowmc-*-*-*.txt)

all:
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SOURCES) $(LDFLAGS) $(LDLIBS) -o mpc_lowmc -Wno-unknown-pragmas
	$(CC) $(CPPFLAGS) -DWITH_PQ_PARAMETERS $(CFLAGS) $(SOURCES) $(LDFLAGS) $(LDLIBS) -o mpc_lowmc_pq -Wno-unknown-pragmas
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SOURCES) $(LDFLAGS) $(LDLIBS) -o mpc_lowmc_openmp -fopenmp -DWITH_OPENMP

clean:
	rm -f *.o *.gch mpc_lowmc mpc_lowmc_pq mpc_lowmc_openmp

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
