// pcap_test.cpp

#include <stdio.h>
#include <pcap.h>
#include <libnet.h>

void pcap_test(const u_char *packet)
{
	const struct libnet_ethernet_hdr *eth_hdr;
	const struct libnet_ipv4_hdr *ip_hdr;
	const struct libnet_tcp_hdr *tcp_hdr;

	eth_hdr = (struct libnet_ethernet_hdr *)packet;
	ip_hdr = (struct libnet_ipv4_hdr *)(packet + sizeof(struct libnet_ethernet_hdr));
	//tcp_hdr = (struct libnet
	
	printf("Destionation ");
	for (int i = 0; i < 6; i++)
	{
		printf("%02X",eth_hdr->ether_dhost[i]);
		if(i < 5)
			printf(".");
	}
	//printf("Destination: %x\n",ntohs(eth_hdr->ether_dhost[ETHER_ADDR_LEN]));

	if (ntohs(eth_hdr->ether_type) == 0x0800)
		printf("Success %x\n",ntohs(eth_hdr->ether_type));
	

	printf("%x, %d, %o\n",ntohs(ip_hdr->ip_p),ip_hdr->ip_p,ntohs(ip_hdr->ip_p));
	//printf("%d!", eth_hdr->ether_type);
}

