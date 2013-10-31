#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

#define INT_IN "eth0"
#define INT_OUT "eth1"

#define MAC_IN "00:0c:29:91:87:9a"
#define MAC_OUT "00:0c:29:91:87:a4" 

#define IP_IN "10.1.1.128"
#define IP_OUT "20.1.1.129"

void process_packet_in(u_char *, const struct pcap_pkthdr *,const u_char *);
void process_packet_out(u_char *, const struct pcap_pkthdr *,const u_char *);

pcap_t* in_handle;
pcap_t* out_handle;
FILE* fp;
int mac_t[6];

int matchWithRules(char* src, char* dest)
{
	FILE* fp_rules = fopen("rules","r");
	char* ptr;
	char str[256];
	int i = 0;
	while(fgets(str, 255, fp_rules) != NULL)
	{
		ptr = strtok(str, "\t");
		while(ptr != NULL)
		{
			ptr = strtok(NULL, "\t");
		}
		i = 0;
	} 
}

void getArrayFromString(char* str1)
{
	char c = ' ';
	int i = 0;
	int total = 0;
	int pos = 16;
	int j = 0;
	char v;
	
	while((c = str1[i]) != '\0')
	{
		if(c == ':')
		{
			pos = 16;
			mac_t[j] = total;
			total = 0;
			j++;
		}
		else
		{
			if(c == 'a' || c == 'A')
				v = 10;
			else if(c == 'b' || c == 'B')
				v = 11;
			else if(c == 'c' || c == 'C')
				v = 12;		
			else if(c == 'd' || c == 'D')
				v = 13;
			else if(c == 'e' || c == 'E')
				v = 14;
			else if(c == 'f' || c == 'F')
				v = 15;
			else
				v = c - 48;
			total += pos * v;
			pos = 1;
		}
		i++;
	}
}
 
int main(int argc,char*argv[])
{
    char errbuf[100];

    in_handle = pcap_open_live(INT_IN,65536,1,0,errbuf);
    out_handle = pcap_open_live(INT_OUT,65536,1,0,errbuf);
    
    pcap_loop(in_handle, -1, process_packet_in, NULL);
    pcap_loop(out_handle, -1, process_packet_out, NULL);
    
    return 0;
}

void process_packet_in(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	struct ethhdr *eth = (struct ethhdr *)buffer;
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr) );
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
	
	int i;
	/*getArrayFromString(MAC2);
	for(i=0;i<6;i++)
		printf("%d\n",mac_t[i]);*/
	
	//if(strcmp(src_ip_s,"192.168.48.152") == 0) 
	//{
		printf("%d\n",pcap_inject(out_handle,buffer,header->len));
	//}
}

void process_packet_out(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
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
	
	if(strcmp(src_ip_s,"192.168.48.152") == 0) 
	{
		printf("%d\n",pcap_inject(out_handle,buffer,header->len));
	}
}
