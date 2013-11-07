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

pcap_t* in_handle;
pcap_t* out_handle;
FILE* fp;
int mac_t[6];
char ip[16], mac[18];
int linkhdrlen;
pcap_dumper_t *dumper;

unsigned short in_cksum(unsigned short *addr, int len)
{
    register int sum = 0;
    u_short answer = 0;
    register u_short *w = addr;
    register int nleft = len;
    
    while (nleft > 1)
    {
      sum += *w++;
      nleft -= 2;
    }
    
    if (nleft == 1)
    {
      *(u_char *) (&answer) = *(u_char *) w;
      sum += answer;
    }
    
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return (answer);
}

void SendICMPError(char* src_addr, char* dst_addr)
{
    struct iphdr *ip, *ip_reply;
    struct icmphdr* icmp;
    struct sockaddr_in connection;
    char *packet, *buffer;
    int sockfd, optval, addrlen;

    packet = malloc(sizeof(struct iphdr) + sizeof(struct icmphdr));
    buffer = malloc(sizeof(struct iphdr) + sizeof(struct icmphdr));
    ip = (struct iphdr*) packet;
    icmp = (struct icmphdr*) (packet + sizeof(struct iphdr));

    ip->ihl         = 5;
    ip->version     = 4;
    ip->tot_len     = sizeof(struct iphdr) + sizeof(struct icmphdr);
    ip->protocol    = IPPROTO_ICMP;
    ip->saddr       = inet_addr(src_addr);
    ip->daddr       = inet_addr(dst_addr);
    ip->check = in_cksum((unsigned short *)ip, sizeof(struct iphdr)); 

    icmp->type      = ICMP_DEST_UNREACH;
    icmp->code      = ICMP_PKT_FILTERED;
    icmp->checksum = in_cksum((unsigned short *)icmp, sizeof(struct icmphdr));

    /* open ICMP socket */
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    
    /* IP_HDRINCL must be set on the socket so that the kernel does not attempt 
     *  to automatically add a default ip header to the packet*/
    setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(int));

    connection.sin_family       = AF_INET;
    connection.sin_addr.s_addr  = ip->daddr;
    sendto(sockfd, packet, ip->tot_len, 0, (struct sockaddr *)&connection, sizeof(struct sockaddr));
    addrlen = sizeof(connection);
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
	int default_dec = -1;
	int rule_p = 0;
	int len;
	int def_rule;
	char src_ip_l[16],dst_ip_l[16];
	int decision;
	
	while(fgets(str, 255, fp_rules) != NULL)
	{
		if(str[0] == '#')
			continue;
		ptr = strtok(str, " ");
		rule_p = 0;
		def_rule = 0;
		while(ptr != NULL)
		{
			len = strlen(ptr);
			if(ptr[len-1] == '\n')
			{
				ptr[len-1] = '\0';
				len--;
			}
			//printf("%s %d\n",ptr,strlen(ptr));
			if(rule_p == 0 && strcmp(ptr,"default") == 0)
			{
				def_rule = 1;
			}
			if(def_rule)
			{
				if(strcmp(ptr,"off") == 0)
				{
					default_dec = 0;
				}
				if(strcmp(ptr,"on") == 0)
				{
					default_dec = 1;
				}
			}
			else
			{
				switch(rule_p)
				{
					case 0:
						if(strcmp(ptr,"pass") == 0)
						{
							decision = PASS;
						}
						else if(strcmp(ptr,"reject") == 0)
						{
							decision = REJECT;
						}
						else
						{
							decision = BLOCK; 
						}
					break;
					case 1:
						strcpy(src_ip_l,ptr);
					break;
					case 2:
					break;
					case 3:
					break;
					case 4:
						strcpy(dst_ip_l,ptr);
					break;
					case 5:
					break;
					case 6:
					break;
				}				
			}
			ptr = strtok(NULL, " ");
			rule_p++;
		}
		i = 0;
		if(!def_rule)
		{
			if(strcmp(src_ip_l,src) == 0 && strcmp(dst_ip_l,dest) == 0)
			{
				if(decision == PASS)
					return 1;
				else if(decision == BLOCK)
					return 0;
				else if(decision == REJECT)
					return -1;
			}
		}		
	}
	return default_dec; 
}

void getMac(char* ip_req,char *inter_face)
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
				{
					printf("Found in the cache:%s",mac);
					return;
				}
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
	
	sprintf(cmd,"arping -c1 -I %s %s",inter_face,ip_req);
	
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

void capture_loop(pcap_t* pd, int packets, pcap_handler func, u_char* dump)
{
    int linktype;
 
    // Determine the datalink layer type.
    if ((linktype = pcap_datalink(pd)) < 0)
    {
        printf("pcap_datalink(): %s\n", pcap_geterr(pd));
        return;
    }
 
    // Set the datalink layer header size.
    switch (linktype)
    {
		case DLT_NULL:
			linkhdrlen = 4;
			break;
	 
		case DLT_EN10MB:
			linkhdrlen = 14;
			break;
	 
		case DLT_SLIP:
		case DLT_PPP:
			linkhdrlen = 24;
			break;
	 
		default:
			printf("Unsupported datalink (%d)\n", linktype);
			return;
    }
 
    // Start capturing packets.
    if (pcap_loop(pd, packets, func, dump) < 0)
	{
		printf("pcap_loop failed: %s\n", pcap_geterr(pd));
	}
}

void parse_packet(u_char *user, struct pcap_pkthdr *packethdr, u_char *packetptr)
{
    struct ip* iphdr;
    struct icmphdr* icmphdr;
    struct tcphdr* tcphdr;
    struct udphdr* udphdr;
    char iphdrInfo[256], srcip[256], dstip[256];
    unsigned short id, seq;
    int i;
    int decision_p;
    
    struct ethhdr *eth = (struct ethhdr *)packetptr;
 
    // Skip the datalink layer header and get the IP header fields.
    packetptr += linkhdrlen;
    iphdr = (struct ip*)packetptr;
    strcpy(srcip, inet_ntoa(iphdr->ip_src));
    strcpy(dstip, inet_ntoa(iphdr->ip_dst));
    sprintf(iphdrInfo, "ID:%d TOS:0x%x, TTL:%d IpLen:%d DgLen:%d",
            ntohs(iphdr->ip_id), iphdr->ip_tos, iphdr->ip_ttl,
            4*iphdr->ip_hl, ntohs(iphdr->ip_len));
 
    // Advance to the transport layer header then parse and display
    // the fields based on the type of hearder: tcp, udp or icmp.
    packetptr += 4*iphdr->ip_hl;
    
    printf("1 %s %s\n",srcip,dstip);
    
    /*switch (iphdr->ip_p)
    {
    case IPPROTO_TCP:
        tcphdr = (struct tcphdr*)packetptr;
        printf("TCP  %s:%d -> %s:%d\n", srcip, ntohs(tcphdr->source),
               dstip, ntohs(tcphdr->dest));
        printf("%s\n", iphdrInfo);
        printf("%c%c%c%c%c%c Seq: 0x%x Ack: 0x%x Win: 0x%x TcpLen: %d\n",
               (tcphdr->urg ? 'U' : '*'),
               (tcphdr->ack ? 'A' : '*'),
               (tcphdr->psh ? 'P' : '*'),
               (tcphdr->rst ? 'R' : '*'),
               (tcphdr->syn ? 'S' : '*'),
               (tcphdr->fin ? 'F' : '*'),
               ntohl(tcphdr->seq), ntohl(tcphdr->ack_seq),
               ntohs(tcphdr->window), 4*tcphdr->doff);
        break;
 
    case IPPROTO_UDP:
        udphdr = (struct udphdr*)packetptr;
        printf("UDP  %s:%d -> %s:%d\n", srcip, ntohs(udphdr->source),
               dstip, ntohs(udphdr->dest));
        printf("%s\n", iphdrInfo);
        break;
 
    case IPPROTO_ICMP:
        icmphdr = (struct icmphdr*)packetptr;
        printf("ICMP %s -> %s\n", srcip, dstip);
        printf("%s\n", iphdrInfo);
        memcpy(&id, (u_char*)icmphdr+4, 2);
        memcpy(&seq, (u_char*)icmphdr+6, 2);
        printf("Type:%d Code:%d ID:%d Seq:%d\n", icmphdr->type, icmphdr->code, 
               ntohs(id), ntohs(seq));
        break;
    }
    printf(
        "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");*/
	
	if(!IsIPInRange(dstip,NET_OUT,SUB_OUT))
	{
		return;
	}
	
	decision_p = matchWithRules(srcip,dstip);
	if(decision_p == 0)
	{
		printf("Drop!\n");
		return;
	} 
	else if(decision_p == -1) 	
	{
		printf("Reject!\n");
		SendICMPError(dstip,srcip);
		return;
	}

	getArrayFromString(MAC_OUT);
	for(i=0;i<6;i++)
	{
		eth->h_source[i] = mac_t[i];
	}
	
	getMac(dstip,INT_OUT);
	printf("%s",mac);
	getArrayFromString(mac);	
	
	for(i=0;i<6;i++)
	{
		eth->h_dest[i] = mac_t[i];
	}		
	
	printf("%d\n",pcap_inject(out_handle,eth,packethdr->len));
}

void parse_packet_p(u_char *user, struct pcap_pkthdr *packethdr, u_char *packetptr)
{
    struct ip* iphdr;
    struct icmphdr* icmphdr;
    struct tcphdr* tcphdr;
    struct udphdr* udphdr;
    char iphdrInfo[256], srcip[256], dstip[256];
    unsigned short id, seq;
    int i;
    int decision_p;
    
    struct ethhdr *eth = (struct ethhdr *)packetptr;
 
    // Skip the datalink layer header and get the IP header fields.
    packetptr += linkhdrlen;
    iphdr = (struct ip*)packetptr;
    strcpy(srcip, inet_ntoa(iphdr->ip_src));
    strcpy(dstip, inet_ntoa(iphdr->ip_dst));
    sprintf(iphdrInfo, "ID:%d TOS:0x%x, TTL:%d IpLen:%d DgLen:%d",
            ntohs(iphdr->ip_id), iphdr->ip_tos, iphdr->ip_ttl,
            4*iphdr->ip_hl, ntohs(iphdr->ip_len));
 
    // Advance to the transport layer header then parse and display
    // the fields based on the type of hearder: tcp, udp or icmp.
    packetptr += 4*iphdr->ip_hl;
    
    printf("2 %s %s\n",srcip,dstip);
    
    /*switch (iphdr->ip_p)
    {
    case IPPROTO_TCP:
        tcphdr = (struct tcphdr*)packetptr;
        printf("TCP  %s:%d -> %s:%d\n", srcip, ntohs(tcphdr->source),
               dstip, ntohs(tcphdr->dest));
        printf("%s\n", iphdrInfo);
        printf("%c%c%c%c%c%c Seq: 0x%x Ack: 0x%x Win: 0x%x TcpLen: %d\n",
               (tcphdr->urg ? 'U' : '*'),
               (tcphdr->ack ? 'A' : '*'),
               (tcphdr->psh ? 'P' : '*'),
               (tcphdr->rst ? 'R' : '*'),
               (tcphdr->syn ? 'S' : '*'),
               (tcphdr->fin ? 'F' : '*'),
               ntohl(tcphdr->seq), ntohl(tcphdr->ack_seq),
               ntohs(tcphdr->window), 4*tcphdr->doff);
        break;
 
    case IPPROTO_UDP:
        udphdr = (struct udphdr*)packetptr;
        printf("UDP  %s:%d -> %s:%d\n", srcip, ntohs(udphdr->source),
               dstip, ntohs(udphdr->dest));
        printf("%s\n", iphdrInfo);
        break;
 
    case IPPROTO_ICMP:
        icmphdr = (struct icmphdr*)packetptr;
        printf("ICMP %s -> %s\n", srcip, dstip);
        printf("%s\n", iphdrInfo);
        memcpy(&id, (u_char*)icmphdr+4, 2);
        memcpy(&seq, (u_char*)icmphdr+6, 2);
        printf("Type:%d Code:%d ID:%d Seq:%d\n", icmphdr->type, icmphdr->code, 
               ntohs(id), ntohs(seq));
        break;
    }
    printf(
        "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");*/
	
	if(!IsIPInRange(dstip,NET_IN,SUB_IN))
	{
		return;
	}
	
	decision_p = matchWithRules(srcip,dstip);
	if(decision_p == 0)
	{
		printf("Drop!\n");
		return;
	} 
	else if(decision_p == -1) 	
	{
		printf("Reject!\n");
		SendICMPError(dstip,srcip);
		return;
	}

	getArrayFromString(MAC_IN);
	for(i=0;i<6;i++)
	{
		eth->h_source[i] = mac_t[i];
	}
	
	getMac(dstip,INT_IN);
	
	getArrayFromString(mac);
	for(i=0;i<6;i++)
	{
		eth->h_dest[i] = mac_t[i];
	}		
	
	printf("%d\n",pcap_inject(in_handle,eth,packethdr->len));
}

void parse_packet_file(u_char *user, struct pcap_pkthdr *packethdr, u_char *packetptr)
{
    struct ip* iphdr;
    struct icmphdr* icmphdr;
    struct tcphdr* tcphdr;
    struct udphdr* udphdr;
    char iphdrInfo[256], srcip[256], dstip[256];
    unsigned short id, seq;
    int i;
    
    u_char *backup = packetptr;
    
    struct ethhdr *eth = (struct ethhdr *)packetptr;
 
    // Skip the datalink layer header and get the IP header fields.
    packetptr += linkhdrlen;
    iphdr = (struct ip*)packetptr;
    strcpy(srcip, inet_ntoa(iphdr->ip_src));
    strcpy(dstip, inet_ntoa(iphdr->ip_dst));
    sprintf(iphdrInfo, "ID:%d TOS:0x%x, TTL:%d IpLen:%d DgLen:%d",
            ntohs(iphdr->ip_id), iphdr->ip_tos, iphdr->ip_ttl,
            4*iphdr->ip_hl, ntohs(iphdr->ip_len));
            
    // Advance to the transport layer header then parse and display
    // the fields based on the type of hearder: tcp, udp or icmp.
    packetptr += 4*iphdr->ip_hl;
    
    /*switch (iphdr->ip_p)
    {
    case IPPROTO_TCP:
        tcphdr = (struct tcphdr*)packetptr;
        printf("TCP  %s:%d -> %s:%d\n", srcip, ntohs(tcphdr->source),
               dstip, ntohs(tcphdr->dest));
        printf("%s\n", iphdrInfo);
        printf("%c%c%c%c%c%c Seq: 0x%x Ack: 0x%x Win: 0x%x TcpLen: %d\n",
               (tcphdr->urg ? 'U' : '*'),
               (tcphdr->ack ? 'A' : '*'),
               (tcphdr->psh ? 'P' : '*'),
               (tcphdr->rst ? 'R' : '*'),
               (tcphdr->syn ? 'S' : '*'),
               (tcphdr->fin ? 'F' : '*'),
               ntohl(tcphdr->seq), ntohl(tcphdr->ack_seq),
               ntohs(tcphdr->window), 4*tcphdr->doff);
        break;
 
    case IPPROTO_UDP:
        udphdr = (struct udphdr*)packetptr;
        printf("UDP  %s:%d -> %s:%d\n", srcip, ntohs(udphdr->source),
               dstip, ntohs(udphdr->dest));
        printf("%s\n", iphdrInfo);
        break;
 
    case IPPROTO_ICMP:
        icmphdr = (struct icmphdr*)packetptr;
        printf("ICMP %s -> %s\n", srcip, dstip);
        printf("%s\n", iphdrInfo);
        memcpy(&id, (u_char*)icmphdr+4, 2);
        memcpy(&seq, (u_char*)icmphdr+6, 2);
        printf("Type:%d Code:%d ID:%d Seq:%d\n", icmphdr->type, icmphdr->code, 
               ntohs(id), ntohs(seq));
        break;
    }
    printf(
        "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");*/
	
	if(matchWithRules(srcip,dstip))
	{
		printf("%s %s\n", srcip, dstip);
		pcap_dump(user, packethdr, backup);
	}
}

int main(int argc, char **argv)
{
    char errbuf[100];
    int mode = atoi(argv[1]);
    
    if(mode == 1)
    {
		pid_t childPID;
		
		in_handle = pcap_open_live(INT_IN,65536,1,0,errbuf);
		out_handle = pcap_open_live(INT_OUT,65536,1,0,errbuf);
		
		childPID = fork();

		if(childPID >= 0)
		{
			if(childPID == 0)
			{
				capture_loop(in_handle, -1, (pcap_handler)parse_packet, NULL);
			}
			else
			{
				capture_loop(out_handle, -1, (pcap_handler)parse_packet_p, NULL);
			}
		}
		else
		{
			printf("\n Fork failed, quitting!!!!!!\n");
			return 1;
		}
	}    
	else
	{
		in_handle = pcap_open_offline("data.pcap",errbuf);
		//802.3 = 1 - link type	
		out_handle = pcap_open_dead(1,65536);
		dumper = pcap_dump_open(out_handle, "out.pcap");
		
		capture_loop(in_handle, -1, (pcap_handler)parse_packet_file, (u_char*)dumper);
	}
    return 0;
}
