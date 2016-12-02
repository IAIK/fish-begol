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

all:
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SOURCES) $(LDFLAGS) $(LDLIBS) -o mpc_lowmc -Wno-unknown-pragmas
	$(CC) $(CPPFLAGS) -DWITH_PQ_PARAMETERS $(CFLAGS) $(SOURCES) $(LDFLAGS) $(LDLIBS) -o mpc_lowmc_pq -Wno-unknown-pragmas
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SOURCES) $(LDFLAGS) $(LDLIBS) -o mpc_lowmc_openmp -fopenmp -DWITH_OPENMP

clean:
	rm -f *.o *.gch mpc_lowmc_pq mpc_lowmc_openmp

dist:
	zip ../source.zip $(SOURCES) $(HEADERS) Makefile README.md \
		$(wildcard timing/*.py) timing/Makefile \
		$(wildcard timing/lowmc-*-*-*.txt) $(wildcard timing/pq-lowmc-*-*-*.txt)
