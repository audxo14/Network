// packet_spoof.cpp

#include <pcap.h>
#include <stdio.h>
#include <libnet.h>
#include <string.h>
#include <arpa/inet.h>

void packet_spoof(u_char *packet, pcap_t *handle, struct in_addr s_ip, u_char *s_mac, u_char *d_mac)
{
	struct libnet_ethernet_hdr *eth_hdr;
	struct libnet_ipv4_hdr *ip_hdr;

	eth_hdr = (struct libnet_ethernet_hdr *)packet;

	if(memcmp(d_mac, eth_hdr -> ether_shost, ETHER_ADDR_LEN))
		continue;
	else if(memcmp(s_mac, eth_hdr -> ether_dhost, ETHER_ADDR_LEN))
		continue;
		
		
}
