#Make file

all: send_arp

send_arp: main.o send_arp.o
	g++ -o send_arp main.o send_arp.o -lpcap

main.o: arp_spoof.h main.cpp
	g++ -c -o main.o main.cpp

send_arp.o: arp_spoof.h send_arp.cpp
	g++ -c -o send_arp.o send_arp.cpp

clean:
	rm -f *.o
	rm send_arp
