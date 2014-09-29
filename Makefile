CC=gcc
CFLAGS=-g -Wall 
CLIBS=-ludis86

all: clean itrace

itrace: itrace.c
	$(CC) $(CFLAGS) itrace.c $(CLIBS) -o itrace 

test: test.o
	ld -o test test.o

test.o: test.s
	nasm -felf32 test.s

clean:
	rm -rf *.o itrace

