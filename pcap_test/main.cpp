// main.c

#include <stdio.h>
#include <pcap.h>
#include <libnet.h>
#include "pcap_test.h"

int main()
{
	int index = 1;
	int result;			
	pcap_t *handle;			//Session handle
	char dev[] = "eth0";		//The device to sniff on
	char errbuf[PCAP_ERRBUF_SIZE];	//Error string
	bpf_u_int32 mask;		//Our netmask
	bpf_u_int32 net;		//our IP
	struct pcap_pkthdr *header;	//The header that pcap gives us
	const u_char *packet;		//The actual packet

	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
	{
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (handle == NULL)
	{
		fprintf(stderr, "Couldn't oupen device %s: %s\n", dev, errbuf);
		return(2);
	}
	
	result = pcap_next_ex(handle, &header, &packet);

	while(result > 0)	// If the packet was read without problems, return 1
	{
		printf("\nSniffing Packet No. %d!\n", index);
		pcap_test(packet);
	
		// Result value is 0, it means the timeout expired.
		result = pcap_next_ex(handle, &header, &packet);
		index++;
	}

	printf("There is no more packet to sniff!\n");

	pcap_close(handle);

	return 0;
}

