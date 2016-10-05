// get_arp.cpp

#include <stdio.h>
#include <libnet.h>

int get_arp(const u_char *packet, u_char *s_mac, u_char *d_mac, struct in_addr d_ip)
{
	int flag = 1;
	const struct libnet_ethernet_hdr *eth_hdr;
	const struct libnet_arp_hdr *arp_hdr;

	eth_hdr = (struct libnet_ethernet_hdr *)packet;

	if (memcmp(s_mac, eth_hdr -> ether_dhost, ETHER_ADDR_LEN))	//ETHER_ADDR_LEN = 6
		return 0;

	if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP)	//If it is ARP,
	{
		arp_hdr = (struct libnet_arp_hdr *)(packet + LIBNET_ETH_H);

		//If it's a reply packet, get the victim's MAC address
		if(ntohs(arp_hdr -> ar_op) == ARPOP_REPLY)
		{
			memcpy(d_mac, packet + 22, ETHER_ADDR_LEN);
			return 1;
		}
		else
			return 0;
	}
}
