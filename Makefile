CC=gcc

# CPPFLAGS+=-DVERBOSE
CPPFLAGS+=-DWITH_OPT
CPPFLAGS+=-DWITH_DETAILED_TIMING
CFLAGS+=-O3
CFLAGS+=-std=c11
CFLAGS+=-Wall
CFLAGS+=-march=native
CFLAGS+=-mtune=native
CFLAGS+=-msse2avx
LDFLAGS+=-flto
LDLIBS+=-lm4ri -lcrypto

all:
	$(CC) $(CPPFLAGS) $(CFLAGS) $(wildcard *.c) $(LDFLAGS) $(LDLIBS) -o mpc_lowmc -Wno-unknown-pragmas
	$(CC) $(CPPFLAGS) $(CFLAGS) $(wildcard *.c) $(LDFLAGS) $(LDLIBS) -o mpc_lowmc_openmp -fopenmp -DWITH_OPENMP

clean:
	rm -f *.o *.gch mpc_lowmc mpc_lowmc_openmp

dist:
	zip ../source.zip $(wildcard *.c) $(wildcard *.h) Makefile README.md \
		$(wildcard timing/*.py) timing/Makefile \
		$(wildcard timing/lowmc-*-*-*.txt) $(wildcard timing/pq-lowmc-*-*-*.txt)
