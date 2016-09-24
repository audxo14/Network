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
	unsigned char *mac;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;

	strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);

	ioctl(fd, SIOCGIFADDR, &ifr);

	puts("IP address of the target : ");
	fgets(victim_ip, sizeof(victim_ip), stdin);

	//addr.s_addr = &ifr.ifr_addr// -> sin_addr;

	printf("Your device is %s", iface);
	

        ioctl(fd, SIOCGIFHWADDR, &ifr);
	mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
	printf("Your MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	
        ioctl(fd, SIOCGIFADDR, &ifr);

	printf("Your IP address: %s\n", inet_ntop(AF_INET, &(((struct sockaddr_in *)&ifr.ifr_addr) -> sin_addr), buf, sizeof(buf)));
	printf("%s", victim_ip);

	close(fd);
	return 0;
}
