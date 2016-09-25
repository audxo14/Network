// send_arp.h

#pragma once
void send_arp(char *victim_ip, u_char *s_mac, struct in_addr s_ip, u_char *d_mac, struct in_addr d_ip);
