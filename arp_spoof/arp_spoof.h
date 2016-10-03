// send_arp.h

#pragma once
void send_arp(u_char *s_mac, u_char *d_mac, struct in_addr s_ip, struct in_addr d_ip, pcap_t *handle);
