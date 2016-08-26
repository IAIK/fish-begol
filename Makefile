CC=gcc

CFLAGS+=-std=c99
CFLAGS+=-Wall
LDLIBS+=-lm4ri -lcrypto

all:
	$(CC) $(CFLAGS) *.c $(LDLIBS) -o mpc_lowmc -Wno-unknown-pragmas
	$(CC) $(CFLAGS) *.c $(LDLIBS) -o mpc_lowmc_openmp -fopenmp -DWITH_OPENMP

clean:
	rm -f *.o *.gch mpc_lowmc mpc_lowmc_openmp
