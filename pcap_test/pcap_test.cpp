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
	tcp_hdr = (struct libnet

	printf("%x\n",ntohs(eth_hdr->ether_type));
	printf("%x, %d, %o\n",ntohs(ip_hdr->ip_p),ip_hdr->ip_p,ntohs(ip_hdr->ip_p));
	//printf("%d!", eth_hdr->ether_type);
}

