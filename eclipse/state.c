#include "state.h"

int updateState(struct ip* iphdr, void * other_p, int protocol)
{
	struct icmphdr* icmphdr;
	struct tcphdr* tcphdr;
	struct udphdr* udphdr;

	ENTRY e1,e2,*ep1,*ep2;

	keyStruct key1,key2;
	valStruct* val;

	strcpy(key1.src_ip, inet_ntoa(iphdr->ip_src));
	strcpy(key1.dst_ip, inet_ntoa(iphdr->ip_dst));
	strcpy(key2.dst_ip, inet_ntoa(iphdr->ip_src));
	strcpy(key2.src_ip, inet_ntoa(iphdr->ip_dst));

	if(protocol == IPPROTO_TCP)
	{
		tcphdr = (struct tcphdr*) other_p;
		key1.sport = ntohs(tcphdr->source);
		key2.sport = ntohs(tcphdr->dest);
		key2.dport = ntohs(tcphdr->source);
		key1.dport = ntohs(tcphdr->dest);
	}
	else if(protocol == IPPROTO_UDP)
	{
		udphdr = (struct udphdr*) other_p;
		key1.sport = ntohs(udphdr->source);
		key2.sport = ntohs(udphdr->dest);
		key2.dport = ntohs(udphdr->source);
		key1.dport = ntohs(udphdr->dest);
	}
	else if(protocol == IPPROTO_ICMP)
	{
		icmphdr = (struct icmphdr*) other_p;
		memcpy(&key1.sport, (u_char*)icmphdr+4, 2);//identifier
        memcpy(&key1.dport, (u_char*)icmphdr+6, 2);//sequence
        memcpy(&key2.sport, (u_char*)icmphdr+4, 2);//identifier
		memcpy(&key2.dport, (u_char*)icmphdr+6, 2);//sequence
	}

	e1.key = (keyStruct*) &key1;
	e2.key = (keyStruct*) &key2;
	if((ep1 = hsearch(e1,FIND))!= NULL || (ep2 = hsearch(e2,FIND))!= NULL)
	{
		printf("Found in the session table.\n");
		if(ep1 != NULL)
		{
			val = ep1->data;
		}
		else if(ep2 != NULL)
		{
			val = ep1->data;
		}
		//Update the entry inside the table
		return 1;
	}
	else
	{
		printf("Not found in the session table.\n");
		return 0;
	}
	return 0;
}
