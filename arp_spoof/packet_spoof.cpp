// packet_spoof.cpp

#include <pcap.h>
#include <stdio.h>
#include <libnet.h>
#include <string.h>
#include <arpa/inet.h>

void packet_spoof(u_char *s_mac, u_char *d_mac, struct in_addr s_ip, struct in_addr d_ip, pcap_t *handle)
{
	u_char *packet;
	struct pcap_pkthdr *header;
	struct libnet_ethernet_hdr *eth_hdr;
	struct libnet_ipv4_hdr *ip_hdr;

	while (1)
	{		
		pcap_next_ex(handle, &header, &packet);
		eth_hdr = (struct libnet_ethernet_hdr *)packet;

		if(memcmp(d_mac, eth_hdr -> ether_shost, ETHER_ADDR_LEN))
			continue;
		else if(memcmp(s_mac, eth_hdr -> ether_dhost, ETHER_ADDR_LEN))
			continue;

	}		
}
