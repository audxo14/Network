#Make file

all: send_arp

send_arp: main.o arp_main.o get_arp.o send_arp.o
	g++ -o send_arp main.o arp_main.o get_arp.o send_arp.o -lpcap

main.o: arp_spoof.h main.cpp
	g++ -c -o main.o main.cpp

arp_main.o: arp_spoof.h arp_main.cpp
	g++ -c -o arp_main.o arp_main.cpp

send_arp.o: arp_spoof.h send_arp.cpp
	g++ -c -o send_arp.o send_arp.cpp

get_arp.o: arp_spoof.h get_arp.cpp
	g++ -c -o get_arp.o get_arp.cpp

clean:
	rm -f *.o
	rm send_arp
