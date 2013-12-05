#ifndef GLOBAL_H
#define GLOBAL_H
#include "globals.h"
#endif
#include "uthash.h"

//ARP table
typedef struct ip_mac
{
	char mac[18];
	int timestamp;
	int valid;
}ip_mac;

typedef struct ARP_table{
    char key[16];
    ip_mac* value;
    UT_hash_handle hh;
}ARP_table;

ARP_table *arp_tbl;

//ARP packet handler
void parse_packet_arp(u_char *user, struct pcap_pkthdr *packethdr, u_char *packetptr);
//Main function to get the MAC from the IP
char* get_Mac_ARP(char* target_ip_string,char *if_name);
//Clean up Thread
void cleanup_ARP();
