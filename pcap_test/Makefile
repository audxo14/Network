#Makefile

all: pcap_test

pcap_test: main.o pcap_test.o
	g++ -o pcap_test main.o pcap_test.o

main.o: pcap_test.h main.c
	g++ -c -o main.o main.c

pcap_test.o: pcap_test.h pcap_test.o
	g++ -c -o pcap_test.o pcap_test.c

clean:
	rm pcap_test
	rm -f *.o

