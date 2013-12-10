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

pcap_t *handle,*out_f;
pcap_dumper_t *dumper;
 
int main(int argc,char*argv[])
{
    pcap_t *file_handle;
    char errbuf[100] , *devname;
    int packets;

    //handle = pcap_open_live("eth0",65536,1,0,errbuf);
    
    file_handle = pcap_open_offline("data.pcap",errbuf);
    if(file_handle == NULL)
		printf("Error\n");
	//802.3 = 1 - link type	
    out_f = pcap_open_dead(1,65536);
    dumper = pcap_dump_open(out_f, "out.pcap");
        
    //pcap_loop(file_handle, -1, process_packet, NULL);
    pcap_loop(file_handle, -1, process_packet, (u_char*)dumper);
    
    return 0;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header,
		const u_char *buffer)
{
    //printf("%d\n",pcap_inject(handle,buffer,header->len));
    pcap_dump(args,header,buffer);
}
