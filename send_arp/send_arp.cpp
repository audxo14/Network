// send_arp.cpp

#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <libnet.h>

void send_arp(char *victim_ip, u_char *s_mac, struct in_addr s_ip, u_char *d_mac, struct in_addr d_ip)
{
	struct libnet_ethernet_hdr *eth_hdr;
	struct libnet_arp_hdr *arp_hdr;	

	const int packet_size = 42;	//arp_packet size (ether + arp)
	pcap_t *handle = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	char dev[] = "eth0";
	bpf_u_int32 mask;
	bpf_u_int32 net;
	u_char *packet;

	packet = (u_char *)malloc(packet_size);
	eth_hdr = (struct libnet_ethernet_hdr *)malloc(sizeof(struct libnet_ethernet_hdr));
	memset(packet, 0, 42);
/*
	if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
	{
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
*/	
	handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);
	if(handle == NULL)
	{
		fprintf(stderr, "%s\n", errbuf);
		exit(1);
	}
	
	for (int i = 0; i < 6; i++)
	{
		eth_hdr -> ether_dhost[i] = 0xff;
		eth_hdr -> ether_shost[i] = s_mac[i];
	}
	
	eth_hdr -> ether_type = htons(ETHERTYPE_ARP);	//ARP protocol
	memcpy(packet, (u_char *)eth_hdr, 14);		//ethernet header


//	pcap_sendpacket(handle, packet, packet_size);

	printf("hello world\n");
	printf("%02x.%02x\n",s_mac[2], s_mac[4]);	
}
