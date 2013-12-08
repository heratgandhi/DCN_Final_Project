#include "util.h"
#include "rules.h"

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

//Send TCP reset to the Sender using Raw sockets
void SendTCPRst(char* src_addr, char* dst_addr,int sport,int dport,int seq_syn)
{
    struct iphdr *ip, *ip_reply;
    struct tcphdr* tcp;
    struct sockaddr_in connection;
    char *packet, *buffer;
    int sockfd, optval, addrlen;

    packet = malloc(sizeof(struct iphdr) + sizeof(struct tcphdr));
    buffer = malloc(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip = (struct iphdr*) packet;
    tcp = (struct tcphdr*) (packet + sizeof(struct iphdr));

    ip->ihl         = 5; //length is 5 bytes
    ip->version     = 4; //IPv4
    ip->tot_len     = sizeof(struct iphdr) + sizeof(struct tcphdr);
    ip->protocol    = IPPROTO_TCP; //TCP
    ip->saddr       = inet_addr(src_addr); //set source address
    ip->daddr       = inet_addr(dst_addr); //set destination address
    ip->check = in_cksum((unsigned short *)ip, sizeof(struct iphdr));

    tcp->ack = htons(seq_syn+1);
    tcp->seq = htons(0);
    tcp->rst = 1;
    tcp->source = htons(sport);
    tcp->dest = htons(dport);
    tcp->window = htonl(128);
	tcp->doff = (sizeof(struct tcphdr))/4;
    tcp->check = in_cksum((unsigned short *)tcp, sizeof(struct tcphdr));

    /* open ICMP socket */
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1) {
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
int isIPInSubnet(char* ip, char* network, int mask)
{
    unsigned int ip_addr = IPToUInt(ip);
    unsigned int network_addr = IPToUInt(network);
    unsigned int mask_addr = 0;
    int i = 0;
    for(i=0;i<mask;i++)
        mask_addr |= 1<<(31-i);

    unsigned int net_lower = (network_addr & mask_addr);
    unsigned int net_upper = (net_lower | (~mask_addr));

    if (ip_addr >= net_lower &&
        ip_addr <= net_upper)
        return 1;
    return 0;
}

//Check whether IP belongs to the range of addresses
int isIPInRange(char *ip,char *start_ip,char *end_ip)
{
   unsigned int sa = IPToUInt(start_ip);
   unsigned int ea = IPToUInt(end_ip);
   unsigned int check = IPToUInt(ip);
   if (check >= sa && check <= ea)
        return 1;
    return 0;
}

//Rule matching engine
int matchWithRules(char* src, char* dest, int sport, int dport, int proto)
{
	rulenode* temp = head;
	int default_dec = -3;
	int def_tcp = -3;
	int def_udp = -3;
	int def_icmp = -3;
	int sip,dip,spcon,dpcon,prtcon;

	while(temp != NULL)
	{
		//Default rule for all protocols
		if(temp->default_rule == 1 && strcmp(temp->protocol,"all") == 0)
		{
			default_dec = temp->result;
		}
		//Default rule for  TCP
		else if(temp->default_rule == 1 && strcmp(temp->protocol,"tcp") == 0)
		{
			def_tcp = temp->result;
		}
		//Default rule for UDP
		else if(temp->default_rule == 1 && strcmp(temp->protocol,"udp") == 0)
		{
			def_udp = temp->result;
		}
		//Default rule for ICMP
		else if(temp->default_rule == 1 && strcmp(temp->protocol,"icmp") == 0)
		{
			def_icmp = temp->result;
		}
		else
		{
			sip = 0;
			dip = 0;
			spcon = 0;
			dpcon = 0;
			prtcon = 0;

			//Match protocol
			if(proto == IPPROTO_TCP && strcmp(temp->protocol,"tcp") == 0)
			{
				prtcon = 1;
			}
			else if(proto == IPPROTO_UDP && strcmp(temp->protocol,"udp") == 0)
			{
				prtcon = 1;
			}
			else if(proto == IPPROTO_ICMP && strcmp(temp->protocol,"icmp") == 0)
			{
				prtcon = 1;
			}
			else if(strcmp(temp->protocol,"all") == 0)
			{
				prtcon = 1;
			}

			//Check for IP addresses and ports
			if(prtcon == 1)
			{
				//Check for the source IP
				if(strcmp(temp->src_ip1,"any") == 0)
				{
					sip = 1;
				}
				else if(temp->src_subnet2 == -1)
				{
					sip = isIPInSubnet(src,temp->src_ip1,temp->src_subnet1);
				}
				else
				{
					sip = isIPInRange(src,temp->src_ip1,temp->src_ip2);
				}

				if(sip == 1)
				{
					//Check for the destination IP
					if(strcmp(temp->dst_ip1,"any") == 0)
					{
						dip = 1;
					}
					else if(temp->dst_subnet2 == -1)
					{
						dip = isIPInSubnet(dest,temp->dst_ip1,temp->dst_subnet1);
					}
					else
					{
						dip = isIPInRange(dest,temp->dst_ip1,temp->dst_ip2);
					}
				}

				if(sip == 1 && dip == 1 && proto != IPPROTO_ICMP)
				{
					//Check for the source port
					if(temp->src_port2 != -1)
					{
						if(sport >= temp->src_port1 && sport <= temp->src_port2)
						{
							spcon = 1;
						}
					}
					else
					{
						if(strcmp(temp->src_port_op,"=") == 0
								&& temp->src_port1 == sport)
						{
							spcon = 1;
						}
						else if(strcmp(temp->src_port_op,">") == 0
								&& sport > temp->src_port1)
						{
							spcon = 1;
						}
						else if(strcmp(temp->src_port_op,"<") == 0
								&& sport < temp->src_port1)
						{
							spcon = 1;
						}
					}
					if(spcon == 1)
					{
						//Check for the destination port
						if(temp->dst_port2 != -1)
						{
							if(dport >= temp->dst_port1 && dport <= temp->dst_port2)
							{
								dpcon = 1;
							}
						}
						else
						{
							if(strcmp(temp->dst_port_op,"=") == 0
									&& temp->dst_port1 == dport)
							{
								dpcon = 1;
							}
							else if(strcmp(temp->dst_port_op,">") == 0
									&& dport > temp->dst_port1)
							{
								dpcon = 1;
							}
							else if(strcmp(temp->dst_port_op,"<") == 0
									&& dport < temp->dst_port1)
							{
								dpcon = 1;
							}
						}
					}
				}
				else if(proto == IPPROTO_ICMP)
				{
					spcon = 1;
					dpcon = 1;
				}
			}
			//printf("Result: %d %d %d %d %d\n",prtcon,sip,dip,spcon,dpcon);
			//If everything matched, return the result stored inside the node
			if(prtcon == 1 && sip == 1 && dip == 1 && spcon == 1 && dpcon == 1)
			{
				return temp->result;
			}
		}
		//Consider the next rule in the list
		temp = temp->next;
	}
	//If no matching rule found then apply the default rule
	if(proto == IPPROTO_TCP && def_tcp != -3)
		return def_tcp;
	else if(proto == IPPROTO_UDP && def_udp != -3)
		return def_udp;
	else if(proto == IPPROTO_ICMP && def_icmp != -3)
		return def_icmp;
	else
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
