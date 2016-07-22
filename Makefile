CC=g++

LDLIBS+=-lm4ri

all: 
	$(CC) *.c *.cpp *.h $(LDLIBS) -o mpc_lowmc

clean:
	rm -f *.o *.gch mpc_lowmc
