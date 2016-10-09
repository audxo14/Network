#Make file

all: test
	mkdir Object
	mv *.o Object/

test: main.o arp_main.o get_arp.o send_arp.o packet_spoof.o
	g++ -o test main.o arp_main.o get_arp.o send_arp.o packet_spoof.o -lpcap

main.o: arp_spoof.h main.cpp
	g++ -c -o main.o main.cpp

arp_main.o: arp_spoof.h arp_main.cpp
	g++ -c -o arp_main.o arp_main.cpp

get_arp.o: arp_spoof.h get_arp.cpp
	g++ -c -o get_arp.o get_arp.cpp

send_arp.o: arp_spoof.h send_arp.cpp
	g++ -c -o send_arp.o send_arp.cpp

packet_spoof.o: arp_spoof.h packet_spoof.cpp
	g++ -c -o packet_spoof.o packet_spoof.cpp

clean:
	rm -f *.o
	rm -f *.cpp~
	rm -f *.h~
	rm -f Makefile~
	rm -r Object
	rm test
