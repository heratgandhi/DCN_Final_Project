#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

#define THRESHOLD 10

void process_packet(u_char *, const struct pcap_pkthdr *,
		const u_char *);

pcap_t *handle;
 
int main(int argc,char*argv[])
{
	//Handle of the pcap file
    pcap_t *file_handle;
    char errbuf[100] , *devname;
    int packets;

    handle = pcap_open_live("eth0",65536,1,0,errbuf);
    
    file_handle = pcap_open_offline("data.pcap",errbuf);
    pcap_loop(file_handle, -1, process_packet, NULL);
    
    return 0;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header,
		const u_char *buffer)
{
    printf("%d\n",pcap_inject(handle,buffer,header->len));
}
