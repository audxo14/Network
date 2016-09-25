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
#include "send_arp.h"

int main()
{
	int fd;
	struct ifreq ifr;
	struct in_addr addr;
	char buf[32];
	char victim_ip[32];
	char iface[] = "eth0";
	u_char *s_mac;
	struct in_addr s_ip;
	u_char *d_mac;
	struct in_addr d_ip;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;

	strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);

	puts("IP address of the target : ");
	fgets(victim_ip, sizeof(victim_ip), stdin);

	printf("My Network Status: \n");
	printf("Device: %s\n", iface);

	//Mac address	
        ioctl(fd, SIOCGIFHWADDR, &ifr);
	
	s_mac = (u_char *)malloc(6);
	memcpy(s_mac, (u_char *)ifr.ifr_hwaddr.sa_data, 6);
	
	//test = (unsigned char *)malloc(6);
	//memcpy(test, s_mac, 6);
	//strncpy(s_mac, (unsigned char*)ifr.ifr_hwaddr.sa_data, 6);
	printf("MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
		s_mac[0], s_mac[1], s_mac[2], s_mac[3], s_mac[4], s_mac[5]);
	
	//IP addrses
        ioctl(fd, SIOCGIFADDR, &ifr);
	s_ip = ((struct sockaddr_in *)&ifr.ifr_addr) -> sin_addr;
	printf("IP address: %s\n", inet_ntop(AF_INET, &s_ip, buf, sizeof(buf)));
	
	//Gateway
	ioctl(fd, SIOCGIFBRDADDR, &ifr);
	printf("Gateway: %s\n", inet_ntop(AF_INET, &(((struct sockaddr_in *)&ifr.ifr_broadaddr) -> sin_addr), buf, sizeof(buf)));
	printf("%s", victim_ip);

	close(fd);
//	printf("IP address: %s\n", inet_ntop(AF_INET, &s_ip, buf, sizeof(buf)));
//	printf("%02x\n",s_mac[5]);
	send_arp(victim_ip, s_mac, s_ip, d_mac, d_ip);
	return 0;
}
