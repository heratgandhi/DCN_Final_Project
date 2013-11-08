#include "util.h"

//Compute the checksum value
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

//Send ICMP error to the Sender using Raw sockets
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

    ip->ihl         = 5; //length is 5 bytes
    ip->version     = 4; //IPv4
    ip->tot_len     = sizeof(struct iphdr) + sizeof(struct icmphdr);
    ip->protocol    = IPPROTO_ICMP; //ICMP
    ip->saddr       = inet_addr(src_addr); //set source address
    ip->daddr       = inet_addr(dst_addr); //set destination address
    ip->check = in_cksum((unsigned short *)ip, sizeof(struct iphdr));

    icmp->type      = ICMP_DEST_UNREACH; //Type = 5
    icmp->code      = ICMP_PKT_FILTERED; //Code = 13
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

//Convert string ip to number
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

//Check whether IP belongs to the network
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

//Simple rule matching engine
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

//Get MAC address array from the string
void getArrayFromString(char* str1)
{
	char c = ' ';
	int i = 0;
	int total = 0;
	int pos = 16;
	int j = 0;
	char v;

	//Read the string
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
