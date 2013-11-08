#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <sys/types.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>

#define INT_IN "eth1"
#define INT_OUT "eth2"

#define MAC_IN "00:0c:29:91:87:9a"
#define MAC_OUT "00:0c:29:91:87:a4"

#define IP_IN "10.1.1.128"
#define IP_OUT "20.1.1.129"

#define NET_IN "10.1.1.0"
#define NET_OUT "20.1.1.0"

#define SUB_IN "255.255.255.0"
#define SUB_OUT "255.255.255.0"

#define true 1
#define false 0

#define BLOCK 1
#define PASS 2
#define REJECT 3

extern pcap_t* in_handle;
extern pcap_t* out_handle;
extern FILE* fp;
extern int mac_t[6];
extern char ip[16], mac[18];
extern int linkhdrlen;
extern pcap_dumper_t *dumper;

extern int arp_linkhdrlen;
extern pcap_t *arp_pcap;
extern char check_ip[16];
extern char arp_ans[18];
