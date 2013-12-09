#include "pcap.h"
#include "arp.h"
#include "util.h"
#include "state.h"

//Insert in the state table
void insert_in_table(struct ip* iphdr, void * other_p, int protocol, int timestf)
{
	//Get write lock
	if (pthread_rwlock_wrlock(&state_lock) != 0)
	{
		printf("Can't acquire write lock on state lock.\n");
	}
	struct icmphdr* icmphdr;
	struct tcphdr* tcphdr;
	struct udphdr* udphdr;
	State_table* entry = (State_table*)malloc(sizeof(State_table));

	keyStruct* key = (keyStruct*) malloc(sizeof(keyStruct));
	valStruct* val = (valStruct*) malloc(sizeof(valStruct));;

	int ticmp;
	char* tmp = (char*) malloc(sizeof(char)*50);

	//Create the key
	strcpy(key->src_ip, inet_ntoa(iphdr->ip_src));
	strcpy(key->dst_ip, inet_ntoa(iphdr->ip_dst));

	//Fill the value fields
	if(protocol == IPPROTO_TCP)
	{
		tcphdr = (struct tcphdr*) other_p;
		key->sport = ntohs(tcphdr->source);
		key->dport = ntohs(tcphdr->dest);

		val->protocol = IPPROTO_TCP;
		val->state = 1;
		val->valid = 1;
		val->identifier = -1;
		val->sequence = -1;
	}
	else if(protocol == IPPROTO_UDP)
	{
		udphdr = (struct udphdr*) other_p;
		key->sport = ntohs(udphdr->source);
		key->dport = ntohs(udphdr->dest);

		val->protocol = IPPROTO_UDP;
		val->state = -1;
		val->valid = 1;
		val->identifier = -1;
		val->sequence = -1;
	}
	else if(protocol == IPPROTO_ICMP)
	{
		icmphdr = (struct icmphdr*) other_p;
		memcpy(&ticmp, (u_char*)icmphdr+4, 2);//identifier
		key->sport = ntohs(ticmp);
		memcpy(&ticmp, (u_char*)icmphdr+6, 2);//sequence
		key->dport = ntohs(ticmp);
		//printf("Ins: %s %s %d %d\n",key->src_ip,key->dst_ip,key->sport,key->dport);

		val->protocol = IPPROTO_ICMP;
		val->state = -1;
		val->valid = 1;
		val->identifier = key->sport;
		val->sequence = key->dport;
	}
	//PCAP replay requires special handling
	if(timestf != -1)
		val->timestamp = timestf;
	else
		val->timestamp = time(0);

	strcpy(entry->key,struct_to_char(key));
	entry->value = val;

	//Insert in the table
	HASH_ADD_STR(state_tbl, key, entry);
	//Release the write lock
	pthread_rwlock_unlock(&state_lock);
}

//General pcap function which assigns the callbacks
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
		//printf("pcap_loop failed: %s\n", pcap_geterr(pd));
	}
}

//Parse packet function for one interface
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
    int decision_t;
    int proto;
    void *other_p;
    int sport, dport;

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

    //printf("1 %s %s\n",srcip,dstip);

    if(!isIPInSubnet(dstip,NET_OUT,SUB_OUT))
	{
		return;
	}

    switch (iphdr->ip_p)
    {
		case IPPROTO_TCP:
			tcphdr = (struct tcphdr*)packetptr;
			decision_t = updateState(iphdr,tcphdr,IPPROTO_TCP,1,-1);
			other_p = tcphdr;
			proto = IPPROTO_TCP;
			sport = ntohs(tcphdr->source);
			dport = ntohs(tcphdr->dest);
			break;

		case IPPROTO_UDP:
			udphdr = (struct udphdr*)packetptr;
			decision_t = updateState(iphdr,udphdr,IPPROTO_UDP,1,-1);
			other_p = udphdr;
			proto = IPPROTO_UDP;
			sport = ntohs(udphdr->source);
			dport = ntohs(udphdr->dest);
			break;

		case IPPROTO_ICMP:
			icmphdr = (struct icmphdr*)packetptr;
			memcpy(&id, (u_char*)icmphdr+4, 2);
			memcpy(&seq, (u_char*)icmphdr+6, 2);
			//printf("~~~ %s %s %d %d\n",srcip,dstip,ntohs(id),ntohs(seq));
			decision_t = updateState(iphdr,icmphdr,IPPROTO_ICMP,1,-1);
			other_p = icmphdr;
			sport = -1;
			dport = -1;
			proto = IPPROTO_ICMP;
			break;
    }
    if(decision_t == -1)
    {
    	printf("Drop!\n");
    	return;
    }
    if(decision_t == 0)
    {
    	decision_p = matchWithRules(srcip,dstip,sport,dport,proto);
		if(decision_p == 0)
		{
			printf("Drop!\n");
			return;
		}
		else if(decision_p == -1)
		{
			printf("Reject!\n");
			if(iphdr->ip_p == IPPROTO_TCP)
			{
				SendTCPRst(dstip,srcip,dport,sport,ntohl(tcphdr->seq));
			}
			else
			{
				SendICMPError(dstip,srcip);
			}
			return;
		}
		insert_in_table(iphdr,other_p,proto,-1);
    }
    getArrayFromString(MAC_OUT);
	for(i=0;i<6;i++)
	{
		eth->h_source[i] = mac_t[i];
	}

	get_Mac_ARP(dstip,INT_OUT);
	printf("1 %s\n",arp_ans);
	getArrayFromString(arp_ans);

	for(i=0;i<6;i++)
	{
		eth->h_dest[i] = mac_t[i];
	}

	printf("1 %d\n",pcap_inject(out_handle,eth,packethdr->len));
}

//Parse packet function for another interface
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
    int decision_t;
	int proto;
	void *other_p;
	int sport,dport;

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

    //printf("2 %s %s\n",srcip,dstip);

    if(!isIPInSubnet(dstip,NET_IN,SUB_IN))
	{
		return;
	}

    switch (iphdr->ip_p)
    {
		case IPPROTO_TCP:
			tcphdr = (struct tcphdr*)packetptr;
			decision_t = updateState(iphdr,tcphdr,IPPROTO_TCP,2,-1);
			other_p = tcphdr;
			proto = IPPROTO_TCP;
			sport = ntohs(tcphdr->source);
			dport = ntohs(tcphdr->dest);
			break;

		case IPPROTO_UDP:
			udphdr = (struct udphdr*)packetptr;
			decision_t = updateState(iphdr,udphdr,IPPROTO_UDP,2,-1);
			other_p = udphdr;
			proto = IPPROTO_UDP;
			sport = ntohs(udphdr->source);
			dport = ntohs(udphdr->dest);
			break;

		case IPPROTO_ICMP:
			icmphdr = (struct icmphdr*)packetptr;
			memcpy(&id, (u_char*)icmphdr+4, 2);
			memcpy(&seq, (u_char*)icmphdr+6, 2);
			decision_t = updateState(iphdr,icmphdr,IPPROTO_ICMP,2,-1);
			other_p = icmphdr;
			proto = IPPROTO_ICMP;
			sport = -1;
			dport = -1;
			break;
    }

	if(decision_t == -1)
	{
		printf("Drop!\n");
		return;
	}

	if(decision_t == 0)
	{
		decision_p = matchWithRules(srcip,dstip,sport,dport,proto);
		if(decision_p == 0)
		{
			printf("Drop!\n");
			return;
		}
		else if(decision_p == -1)
		{
			printf("Reject!\n");
			if(iphdr->ip_p == IPPROTO_TCP)
			{
				SendTCPRst(dstip,srcip,dport,sport,ntohl(tcphdr->seq));
			}
			else
			{
				SendICMPError(dstip,srcip);
			}
			return;
		}
		insert_in_table(iphdr,other_p,proto,-1);
	}

	getArrayFromString(MAC_IN);
	for(i=0;i<6;i++)
	{
		eth->h_source[i] = mac_t[i];
	}

	get_Mac_ARP(dstip,INT_IN);
	printf("2 %s\n",arp_ans);
	getArrayFromString(arp_ans);
	for(i=0;i<6;i++)
	{
		eth->h_dest[i] = mac_t[i];
	}

	printf("2 %d\n",pcap_inject(in_handle,eth,packethdr->len));
}

//Parse packet function for files
void parse_packet_file(u_char *user, struct pcap_pkthdr *packethdr, u_char *packetptr)
{
	struct ip* iphdr;
    struct icmphdr* icmphdr;
    struct tcphdr* tcphdr;
    struct udphdr* udphdr;
    char iphdrInfo[256], srcip[256], dstip[256];
    unsigned short id, seq;
    int i;
    int decision_p;
    int decision_t;
    int proto;
    void *other_p;
    int sport, dport;
    static int prev_time = 0;
    int tStamp = packethdr->ts.tv_sec;

    u_char *backup = packetptr;
    struct pcap_pkthdr* backup2 = packethdr;

    struct ethhdr *eth = (struct ethhdr *)packetptr;
    //printf("Timestamp: %ld\n",packethdr->ts.tv_sec);
    if(tStamp - prev_time > TIMEOUT)
    {
    	cleanup_State(tStamp);
    	prev_time = tStamp;
    }

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

    switch (iphdr->ip_p)
    {
		case IPPROTO_TCP:
			tcphdr = (struct tcphdr*)packetptr;
			decision_t = updateState(iphdr,tcphdr,IPPROTO_TCP,1,tStamp);
			other_p = tcphdr;
			proto = IPPROTO_TCP;
			sport = ntohs(tcphdr->source);
			dport = ntohs(tcphdr->dest);
			break;

		case IPPROTO_UDP:
			udphdr = (struct udphdr*)packetptr;
			decision_t = updateState(iphdr,udphdr,IPPROTO_UDP,1,tStamp);
			other_p = udphdr;
			proto = IPPROTO_UDP;
			sport = ntohs(udphdr->source);
			dport = ntohs(udphdr->dest);
			break;

		case IPPROTO_ICMP:
			icmphdr = (struct icmphdr*)packetptr;
			memcpy(&id, (u_char*)icmphdr+4, 2);
			memcpy(&seq, (u_char*)icmphdr+6, 2);
			decision_t = updateState(iphdr,icmphdr,IPPROTO_ICMP,1,tStamp);
			other_p = icmphdr;
			sport = -1;
			dport = -1;
			proto = IPPROTO_ICMP;
			break;
    }
    if(decision_t == -1)
    {
    	printf("Drop!\n");
    	return;
    }
    if(decision_t == 0)
    {
    	decision_p = matchWithRules(srcip,dstip,sport,dport,proto);
		if(decision_p == 0)
		{
			printf("Drop!\n");
			return;
		}
		else if(decision_p == -1)
		{
			printf("Reject!\n");
			return;
		}
		insert_in_table(iphdr,other_p,proto,tStamp);
    }
    pcap_dump(user, backup2, backup);
}
