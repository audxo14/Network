#Makefile

all: pcap_test

pcap_test: main.o pcap_test.o
	g++ -o pcap_test main.o pcap_test.o -lpcap

main.o: pcap_test.h main.cpp
	g++ -c -o main.o main.cpp

pcap_test.o: pcap_test.h pcap_test.cpp
	g++ -c -o pcap_test.o pcap_test.cpp

clean:
	rm -f *.o
	rm pcap_test


