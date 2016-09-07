CC=gcc

CFLAGS+=-DWITH_OPT
CFLAGS+=-DWITH_DETAILED_TIMING
CFLAGS+=-std=c11
CFLAGS+=-Wall
LDLIBS+=-lm4ri -lcrypto

all:
	$(CC) $(CFLAGS) $(wildcard *.c) $(LDLIBS) -o mpc_lowmc -Wno-unknown-pragmas
	$(CC) $(CFLAGS) $(wildcard *.c) $(LDLIBS) -o mpc_lowmc_openmp -fopenmp -DWITH_OPENMP

clean:
	rm -f *.o *.gch mpc_lowmc mpc_lowmc_openmp
