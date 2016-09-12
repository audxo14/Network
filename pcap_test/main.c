// main.c

#include <stdio.h>
#include <pcap.h>
#include <libnet.h>
#include "pcap_test.h"

int main()
{
	pcap_t *handle;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_ex[] = "port 23";
	bpf_u_int32 mask;
	bpf_u_int32 net;
	struct pcap_pkthdr header;
	const u_char *packet;

	pritnf("Sniffing Packets!\n");
	

	pcap_test(packet);
	return 0;
}
