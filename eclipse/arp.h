#ifndef GLOBAL_H
#define GLOBAL_H
#include "globals.h"
#endif

void parse_packet_arp(u_char *user, struct pcap_pkthdr *packethdr, u_char *packetptr);
char* get_Mac_ARP(char* target_ip_string,char *if_name);
