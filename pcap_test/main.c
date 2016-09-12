// main.c

#include <stdio.h>
#include <pcap.h>
#include <libnet.h>
#include "pcap_test.h"

int main()
{
	int index = 1;
	pcap_t *handle;			//Session handle
	char *dev;			//The device to sniff on
	char errbuf[PCAP_ERRBUF_SIZE];	//Error string
	struct bpf_program fp;		//The compiled filter
	char filter_ex[] = "port 23";	//The filter expression
	bpf_u_int32 mask;		//Our netmask
	bpf_u_int32 net;		//our IP
	struct pcap_pkthdr header;	//The header that pcap gives us
	const u_char *packet;		//The actual packet
	
	packet = pcap_next_ex(handle, &headeR);
	while(packet)
	{

		pritnf("Sniffing Packet No. %d!\n", index);
		pcap_test(packet);
	
		packet = pcap_next_ex(handle, &header);
		index++;
	}

	return 0;
}
