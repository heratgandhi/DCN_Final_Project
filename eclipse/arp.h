#ifndef GLOBAL_H
#define GLOBAL_H
#include "globals.h"
#endif

//ARP packet handler
void parse_packet_arp(u_char *user, struct pcap_pkthdr *packethdr, u_char *packetptr);
//Main function to get the MAC from the IP
char* get_Mac_ARP(char* target_ip_string,char *if_name);
//Clean up Thread
void cleanup_ARP();
