#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

void process_packet(u_char *, const struct pcap_pkthdr *,
		const u_char *);

pcap_t * in_handle;
pcap_t * out_handle;
FILE* fp;
 
int main(int argc,char*argv[])
{
    char errbuf[100], *devname;
    int packets;

    in_handle = pcap_open_live("eth0",65536,1,0,errbuf);
    out_handle = pcap_open_live("eth1",65536,1,0,errbuf);
    
    fp = fopen("rules","r");
    
    pcap_loop(in_handle, -1, process_packet_in, NULL);
    pcap_loop(out_handle, -1, process_packet_out, NULL);
    
    fclose(fp);
    return 0;
}

void process_packet_in(u_char *args, const struct pcap_pkthdr *header,
		const u_char *buffer)
{
	unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)(buffer +
    		sizeof(struct ethhdr) );
	struct sockaddr_in source,dest;
    iphdrlen = iph->ihl*4;
    //Get the source IP address
    memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	//Get the destination IP address
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;   
	
	char* src_ip_s = inet_ntoa(source.sin_addr);
	char* dst_ip_s = inet_ntoa(dest.sin_addr);
	
	if(strcmp(src_ip_s,"192.168.48.152") == 0) {
		printf("%d\n",pcap_inject(out_handle,buffer,header->len));
	}
}

void process_packet_out(u_char *args, const struct pcap_pkthdr *header,
		const u_char *buffer)
{
	unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)(buffer +
    		sizeof(struct ethhdr) );
	struct sockaddr_in source,dest;
    iphdrlen = iph->ihl*4;
    //Get the source IP address
    memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	//Get the destination IP address
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;   
	
	char* src_ip_s = inet_ntoa(source.sin_addr);
	char* dst_ip_s = inet_ntoa(dest.sin_addr);
	
	if(strcmp(src_ip_s,"192.168.48.152") == 0) {
		printf("%d\n",pcap_inject(out_handle,buffer,header->len));
	}
}
