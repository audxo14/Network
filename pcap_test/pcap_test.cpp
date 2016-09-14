// pcap_test.cpp

#include <stdio.h>
#include <libnet.h>

void pcap_test(const u_char *packet)
{
	const struct libnet_ethernet_hdr *eth_hdr;
	const struct libnet_ipv4_hdr *ip_hdr;
	const struct in_addr *ip_addr;
	const struct libnet_tcp_hdr *tcp_hdr;	

	eth_hdr = (struct libnet_ethernet_hdr *)packet;
	
        printf("\nSource MAC Address: ");

        for (int i = 0; i < 6; i++)
        {
                printf("%02x",eth_hdr->ether_shost[i]);
                if(i < 5)
                        printf(".");
        }

	printf("\nDestionation MAC Address: ");
	for (int i = 0; i < 6; i++)
	{
		printf("%02x",eth_hdr->ether_dhost[i]);
		if(i < 5)
			printf(".");
	}
	printf("\n");	
	
	if (ntohs(eth_hdr->ether_type) == 0x0800)		//If it is Ethernet
	{
		printf("\nThe next header  is IP header!!!\n");

		unsigned int eth_size = sizeof(struct libnet_ethernet_hdr);			//ethernet header size
	        ip_hdr = (struct libnet_ipv4_hdr *)(packet + eth_size);				//pointer for ip header
		printf("IP source Address: %s\n",inet_ntoa(ip_hdr->ip_src));
		printf("IP Destination Address: %s\n", inet_ntoa(ip_hdr->ip_dst));

		if (ip_hdr->ip_p == 6)				//If its protocol is TCP
		{
			printf("\nThe protocol is TCP!!\n");
			unsigned int iph_size = (ip_hdr->ip_hl) * 4;				//ip header size
			unsigned int tcph_size = (tcp_hdr->th_off) * 4;				//tcp header size
			unsigned int packet_size = ntohs(ip_hdr->ip_len) - iph_size - tcph_size; //payload size
			
			tcp_hdr = (struct libnet_tcp_hdr *)(packet + eth_size + iph_size);	//pointer for tcp header
			printf("TCP source Port: %d\n", ntohs(tcp_hdr->th_sport));		// source port number
			printf("TCP Destination Port: %d\n", ntohs(tcp_hdr->th_dport));		//Destination port number
			
			if (packet_size > 0)				//If this packet has data(payload)
			{
				printf("Payload: \n");
				for(int i = 0; i <  packet_size; i++)
					printf("%02x ", *(u_char *)(packet + eth_size + iph_size + tcph_size+i));
				printf("\n");
			}
		}
	}
}

