// arp_spoof.h

#pragma once
void arp_main(u_char *s_mac, u_char *d_mac, u_char *r_mac, struct in_addr s_ip, struct in_addr d_ip, pcap_t *handle);
void send_arp(u_char *packet, u_char *s_mac, u_char *d_mac, struct in_addr s_ip, struct in_addr d_ip, pcap_t *handle, struct pcap_pkthdr *header, int flag);
int get_arp(const u_char *packet, u_char *s_mac, u_char *d_mac, struct in_addr d_ip);

void packet_spoof(u_char *s_mac, u_char *d_mac, u_char *r_mac, struct in_addr s_ip, struct in_addr d_ip);
