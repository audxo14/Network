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
	struct in_addr addr;
	char buf[INET_ADDRSTRLEN];
	pcap_t *handle = NULL;
	u_char *s_mac;
	u_char *d_mac;

	struct in_addr s_ip;
	struct in_addr d_ip;
	
	s_mac = (u_char *)malloc(6);
	d_mac = (u_char *)malloc(6);

	arp_main(s_mac, d_mac, s_ip, d_ip, handle);
	//packet_spoof(s_mac, d_mac, s_ip, d_ip, handle);
	
	free(s_mac);
	free(d_mac);
	return 0;
}
