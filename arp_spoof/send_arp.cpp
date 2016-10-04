// send_arp.cpp

#include <libnet.h>
#include <pcap.h>
#include <string.h>
#include <stdio.h>

void send_arp(u_char *packet, u_char *s_mac, u_char *d_mac,
		struct in_addr s_ip, struct in_addr d_ip, pcap_t *handle, int flag)
{
	struct libnet_ethernet_hdr *eth_hdr;	//ethernet header
	struct libnet_arp_hdr *arp_hdr;		//arp hedaer
	int packet_size = 42;

	eth_hdr = (struct libnet_ethernet_hdr *)malloc(sizeof(struct libnet_ethernet_hdr));
	arp_hdr = (struct libnet_arp_hdr *)malloc(sizeof(struct libnet_arp_hdr));

	if(flag == 1)
	{	
		for (int i = 0; i < 6; i++)
		{
			eth_hdr -> ether_dhost[i] = 0xff;	//For broadcasting
			eth_hdr -> ether_shost[i] = s_mac[i];
		}
	
		eth_hdr -> ether_type = htons(ETHERTYPE_ARP);	//ARP protocol, ETHERTYPE_ARP = 0x0806
		memcpy(packet, (u_char *)eth_hdr, 14);		//ethernet header

		arp_hdr -> ar_hrd = htons(ARPHRD_ETHER);	//ARPHRD_ETHER = 1
		arp_hdr -> ar_pro = htons(0x0800);		//0x0800 (IPv4)
		arp_hdr -> ar_hln = 0x06;			//header size
		arp_hdr -> ar_pln = 0x04;			//protocol size
		arp_hdr -> ar_op = htons(ARPOP_REQUEST);	//ARPOP_REQUEST = 1

		memcpy(packet + 14, (u_char *)arp_hdr, 8);	//Copy arp header data into the packet
		memcpy(packet + 22, s_mac, 6);			//Source MAC address
		memcpy(packet + 28, &s_ip.s_addr, 4);		//Source IP address
		memset(packet + 32, 0x00, 6);			//We don't know the MAC address yet
		memcpy(packet + 38, &d_ip.s_addr, 4);		//Victim's IP address

		pcap_sendpacket(handle, packet, packet_size);	//Send ARP request packet
	}
	else if (flag == 2)
	{
		
	}
}
