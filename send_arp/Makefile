#Make file

all: send_arp

send_arp: main.o send_arp.o
	g++ -o send_arp main.o send_arp.o -lpcap

main.o: send_arp.h main.cpp
	g++ -c -o main.o main.cpp

send_arp.o: send_arp.h send_arp.cpp
	g++ -c -o send_arp.o send_arp.cpp

clean:
	rm -f *.o
	rm send_arp
