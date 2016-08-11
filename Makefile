CC=gcc

LDLIBS+=-lm4ri -lcrypto -lomp

all: 
	$(CC) *.c *.h $(LDLIBS) -o mpc_lowmc

clean:
	rm -f *.o *.gch mpc_lowmc
