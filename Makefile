CC=gcc

LDLIBS+=-lm4ri -lcrypto

all:
	$(CC) -std=c99 *.c $(LDLIBS) -o mpc_lowmc
	$(CC) -std=c99 *.c $(LDLIBS) -o mpc_lowmc_openmp -fopenmp -DWITH_OPENMP

clean:
	rm -f *.o *.gch mpc_lowmc mpc_lowmc_openmp
