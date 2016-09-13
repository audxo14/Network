// pcap_test.cpp

#include <stdio.h>
#include <pcap.h>
#include <libnet.h>

void pcap_test(const u_char *packet)
{
	const struct libnet_ethernet_hdr *eth_hdr;
	const struct libnet_ipv4_hdr *ip_hdr;
	const struct in_addr *ip_addr;
	const struct libnet_tcp_hdr *tcp_hdr;

	eth_hdr = (struct libnet_ethernet_hdr *)packet;
	ip_hdr = (struct libnet_ipv4_hdr *)(packet + sizeof(struct libnet_ethernet_hdr));
	
	printf("Destionation MAC Address: ");
	for (int i = 0; i < 6; i++)
	{
		printf("%02x",eth_hdr->ether_dhost[i]);
		if(i < 5)
			printf(".");
	}

	printf("\nSource MAC Address: ");

        for (int i = 0; i < 6; i++)
        {
                printf("%02x",eth_hdr->ether_shost[i]);
                if(i < 5)
                        printf(".");
        }
	printf("\n");	
	if (ntohs(eth_hdr->ether_type) == 0x0800)
	{
		printf("\nThe next header  is IP header!!!\n");

		unsigned int eth_size = sizeof(struct libnet_ethernet_hdr);
	        ip_hdr = (struct libnet_ipv4_hdr *)(packet + eth_size);
		printf("IP source Address: %s\n",inet_ntoa(ip_hdr->ip_src));
		printf("IP Destination Address: %s\n", inet_ntoa(ip_hdr->ip_dst));

		if (ip_hdr->ip_p == 6)
		{
			printf("\nThe protocol is TCP!!\n");
			unsigned int iph_size = (ip_hdr->ip_hl) * 4;
			unsigned int tcph_size = (tcp_hdr->th_off) * 4;
			tcp_hdr = (struct libnet_tcp_hdr *)(packet + eth_size + iph_size);
			printf("TCP source Port: %x\n", ntohs(tcp_hdr->th_sport));
			printf("TCP Destination Port: %x\n", ntohs(tcp_hdr->th_dport));
		}
	}
	
	//printf("%d!", eth_hdr->ether_type);
}

