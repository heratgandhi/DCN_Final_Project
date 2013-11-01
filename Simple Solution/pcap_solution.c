#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

#define INT_IN "eth2"
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

void process_packet_in(u_char *, const struct pcap_pkthdr *,const u_char *);
void process_packet_out(u_char *, const struct pcap_pkthdr *,const u_char *);

pcap_t* in_handle;
pcap_t* out_handle;
FILE* fp;
int mac_t[6];
char ip[16], mac[18];
struct sockaddr_in source;
struct sockaddr_in dest;

void process_packet_in(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	int i;
	unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;
	
	//struct ethhdr *eth = (struct ethhdr *)buffer;
    
    //Get the source IP address
    memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	//Get the destination IP address
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;   
	
	//char* src_ip_s = inet_ntoa(source.sin_addr);
	//char* dst_ip_s = inet_ntoa(dest.sin_addr);
	
	printf("%s %s\n",inet_ntoa(source.sin_addr),inet_ntoa(dest.sin_addr));
	if(!IsIPInRange(dst_ip_s,NET_OUT,SUB_OUT))
		return;

	getArrayFromString(MAC_OUT);
	for(i=0;i<6;i++)
	{
		eth->h_source[i] = mac_t[i];
	}
	
	getMac(dst_ip_s);
	
	getArrayFromString(mac);
	for(i=0;i<6;i++)
	{
		eth->h_dest[i] = mac_t[i];
	}		
	
	printf("%d\n",pcap_inject(out_handle,buffer,header->len));
}

int IPToUInt(char* ip) 
{
    int a, b, c, d;
    int addr = 0;
 
    if (sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d) != 4)
        return 0;
 
    addr = a << 24;
    addr |= b << 16;
    addr |= c << 8;
    addr |= d;
    return addr;
}

int IsIPInRange(char* ip, char* network, char* mask) 
{
    int ip_addr = IPToUInt(ip);
    int network_addr = IPToUInt(network);
    int mask_addr = IPToUInt(mask);
 
    int net_lower = (network_addr & mask_addr);
    int net_upper = (net_lower | (~mask_addr));
 
    if (ip_addr >= net_lower &&
        ip_addr <= net_upper)
        return true;
    return false;
}

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

void getMac(char* ip_req)
{
	//Look inside the ARP cache first
	int i=0;
	const char filename[] = "/proc/net/arp";
	
	FILE *file = fopen(filename, "r");
	if (file)
	{
		char line [BUFSIZ];
		fgets(line, sizeof line, file);
		while (fgets(line, sizeof line, file))
		{
			char a,b,c,d;
			if(sscanf(line, "%s %s %s %s %s %s", &ip,&a, &b, &mac, &c, &d) < 10)
			{
				if(strcmp(ip_req,ip) == 0)
					return;
			}
		}
	}
	else
	{
		perror(filename);
	}
	
	//Did not find in the APR cache, use arping
	FILE *fp;
	int status;
	char path[1035];
	char cmd[1024];
	char *p;	
	i=1;
	
	sprintf(cmd,"arping -c1 %s",ip_req);
	
	fp = popen(cmd, "r");
	if (fp == NULL) 
	{
		printf("Failed to run command\n" );
	}
	
	while (fgets(path, sizeof(path)-1, fp) != NULL) 
	{
		if((p = strchr(path, '[')) != NULL) 
		{
			while(p[i] != ']') 
			{
				mac[i-1] = p[i];
				i++;		
			}
			mac[i-1] = '\0';
		}
	}	
	pclose(fp);	
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
	mac_t[j] = total;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    int size = header->len;
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    switch (iph->protocol)
    {
        case 6:  //TCP Protocol
            process_packet_in(args, header, buffer);
            break;
    }
}
 
int main(int argc,char*argv[])
{
    char errbuf[100];

    in_handle = pcap_open_live(INT_IN,65536,1,0,errbuf);
    //out_handle = pcap_open_live(INT_OUT,65536,1,0,errbuf);
    
    pcap_loop(in_handle, -1, process_packet, NULL);
    //pcap_loop(out_handle, -1, process_packet, NULL);
    
    return 0;
}



void process_packet_out(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	int i;
	
	struct ethhdr *eth = (struct ethhdr *)buffer;
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr) );
	struct sockaddr_in source,dest;
    
    iphdrlen = iph->ihl*4;
    
    //Get the source IP address
    memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = (uint32_t)iph->saddr;

	//Get the destination IP address
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = (uint32_t)iph->daddr;   
	
	char* src_ip_s = inet_ntoa(source.sin_addr);
	char* dst_ip_s = inet_ntoa(dest.sin_addr);
	
	if(!IsIPInRange(dst_ip_s,NET_IN,SUB_IN))
		return;
	
	getArrayFromString(MAC_IN);
	for(i=0;i<6;i++)
	{
		eth->h_source[i] = mac_t[i];
	}
	
	getMac(dst_ip_s);
	getArrayFromString(mac);
	for(i=0;i<6;i++)
	{
		eth->h_dest[i] = mac_t[i];
	}		
	
	printf("%d\n",pcap_inject(in_handle,buffer,header->len));
}
