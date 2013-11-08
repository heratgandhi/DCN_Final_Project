#ifndef GLOBAL_H
#define GLOBAL_H
#include "globals.h"
#endif

void capture_loop(pcap_t* pd, int packets, pcap_handler func, u_char* dump);
void parse_packet_file(u_char *user, struct pcap_pkthdr *packethdr, u_char *packetptr);
void parse_packet_p(u_char *user, struct pcap_pkthdr *packethdr, u_char *packetptr);
void parse_packet(u_char *user, struct pcap_pkthdr *packethdr, u_char *packetptr);
