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

int main()
{
	int fd;
	struct ifreq ifr;
	struct in_addr addr;
	char buf[32];
	char victim_ip[32];
	
	char iface[] = "eth0";

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;

	strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);

	ioctl(fd, SIOCGIFADDR, &ifr);
	
	close(fd);

	puts("IP address of the target : ");
	fgets(victim_ip, sizeof(victim_ip), stdin);

	//addr.s_addr = &ifr.ifr_addr// -> sin_addr;

	printf("Your device is %s", iface);
	for (int i = 0; i< 6; i++)
		printf("%.2x.", (unsigned char)ifr.ifr_hwaddr.sa_data[i]);
	//printf("Mac Address: %s", ether_ntoa((struct ether_addr *)ifr.ifr_hwaddr.sa_data));
	//printf("Your Mac address: %s\n", &(((struct sockaddr_in *)&ifr.ifr_hwaddr) ->
	printf("Your IP address: %s\n", inet_ntop(AF_INET, &(((struct sockaddr_in *)&ifr.ifr_addr) -> sin_addr), buf, sizeof(buf)));
	printf("%s", victim_ip);

	return 0;
}
