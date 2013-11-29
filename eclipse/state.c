#include "state.h"

char* itoa(int val, int base)
{
	static char buf[32] = {0};
	int i = 30;
	for(; val && i ; --i, val /= base)
		buf[i] = "0123456789abcdef"[val % base];
	return &buf[i+1];
}

char* struct_to_char(keyStruct* key)
{
	char *ptr = (char*) malloc(50*sizeof(char));
	char *tbuf;

	strcpy(ptr,key->src_ip);
	strcat(ptr,",");
	strcat(ptr,key->dst_ip);
	strcat(ptr,",");
	tbuf = itoa(key->sport, 10);
	strcat(ptr,tbuf);
	strcat(ptr,",");
	tbuf = itoa(key->dport, 10);
	strcat(ptr,tbuf);

	return ptr;
}

void travel_list()
{
	keyList *t = keyListHead;
	while(t != NULL)
	{
		printf("# %s %s %d %d\n",t->key->src_ip,t->key->dst_ip,t->key->sport,t->key->dport);
		t = t->next;
	}
}

int updateState(struct ip* iphdr, void * other_p, int protocol, int proc)
{
	//travel_list();
	struct icmphdr* icmphdr;
	struct tcphdr* tcphdr;
	struct udphdr* udphdr;

	ENTRY e1,e2,*ep1,*ep2;
	ep1 = NULL;
	ep2 = NULL;

	keyStruct *key1,*key2;
	valStruct* val;
	int ticmp;

	key1 = (keyStruct*) malloc(sizeof(keyStruct));
	key2 = (keyStruct*) malloc(sizeof(keyStruct));

	strcpy(key1->src_ip, inet_ntoa(iphdr->ip_src));
	strcpy(key1->dst_ip, inet_ntoa(iphdr->ip_dst));
	strcpy(key2->dst_ip, inet_ntoa(iphdr->ip_src));
	strcpy(key2->src_ip, inet_ntoa(iphdr->ip_dst));

	if(protocol == IPPROTO_TCP)
	{
		tcphdr = (struct tcphdr*) other_p;
		key1->sport = ntohs(tcphdr->source);
		key2->sport = ntohs(tcphdr->dest);
		key2->dport = ntohs(tcphdr->source);
		key1->dport = ntohs(tcphdr->dest);
	}
	else if(protocol == IPPROTO_UDP)
	{
		udphdr = (struct udphdr*) other_p;
		key1->sport = ntohs(udphdr->source);
		key2->sport = ntohs(udphdr->dest);
		key2->dport = ntohs(udphdr->source);
		key1->dport = ntohs(udphdr->dest);
	}
	else if(protocol == IPPROTO_ICMP)
	{
		icmphdr = (struct icmphdr*) other_p;
		memcpy(&ticmp, (u_char*)icmphdr+4, 2);//identifier
		key1->sport = ntohs(ticmp);
		key2->sport = ntohs(ticmp);
		memcpy(&ticmp, (u_char*)icmphdr+6, 2);//sequence
		key1->dport = ntohs(ticmp);
		key2->dport = ntohs(ticmp);

		//printf("%d ^^^ %s %s %d %d\n",proc,key1->src_ip,key1->dst_ip,key1->sport,key1->dport);
		//printf("%d ^^^ %s %s %d %d\n",proc,key2->src_ip,key2->dst_ip,key2->sport,key2->dport);
	}

	e1.key = struct_to_char(key1);
	e2.key = struct_to_char(key2);
	//printf("%s %s\n",e1.key,e2.key);

	if((ep1 = hsearch(e1,FIND)) == NULL && (ep2 = hsearch(e2,FIND))== NULL)
	{
		printf("%d-->Not found in the session table.\n",proc);
		return 0;
	}
	else
	{
		printf("%d-->Found in the session table.\n",proc);
		if(ep1 != NULL)
		{
			val = ep1->data;
		}
		else if(ep2 != NULL)
		{
			val = ep2->data;
		}
		//Update the entry inside the table
		return 1;
	}
	return 0;
}
