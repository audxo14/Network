all: test

test: test.o
	gcc -o test test.o -lnetfilter_queue

test.o: nfqnl_test.c
	gcc -c -o test.o nfqnl_test.c
