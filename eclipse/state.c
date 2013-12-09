#include "state.h"

//Cleanup the state table
void cleanup_State(int timeval)
{
	valStruct* val;
	State_table *entry,*tmp;

	HASH_ITER(hh, state_tbl, entry, tmp)
	{
		val = entry->value;
		if(timeval == -1)
		{
			if(val->valid && ((time(0) - val->timestamp) > TIMEOUT))
			{
				val->valid = 0;
				printf("@@@ Deleting: %s\n",entry->key);
				HASH_DEL(state_tbl, entry);
				free(entry);
			}
		}
		else
		{
			if(val->valid && ((timeval - val->timestamp) > TIMEOUT))
			{
				val->valid = 0;
				printf("@@@ Deleting: %s\n",entry->key);
				HASH_DEL(state_tbl, entry);
				free(entry);
			}
		}
	}
}

//Convert int to string
char* itoa(int val, int base)
{
	static char buf[32] = {0};
	int i = 30;
	for(; val && i ; --i, val /= base)
		buf[i] = "0123456789abcdef"[val % base];
	return &buf[i+1];
}

//Convert key from structure to string
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

//Convert string to key structure
keyStruct* char_to_struct(char* key)
{
	char* token = strtok(key, ",");
	keyStruct *key_s = (keyStruct*) malloc(sizeof(keyStruct));
	int i = 0;
	while (token)
	{
		switch(i)
		{
			case 0:
				strcpy(key_s->src_ip,token);
			break;
			case 1:
				strcpy(key_s->dst_ip,token);
			break;
			case 2:
				key_s->sport = atoi(token);
			break;
			case 3:
				key_s->dport = atoi(token);
			break;
		}
		i++;
		token = strtok(0, ",");
	}
	return key_s;
}

//Iterate the list and print it for the debugging
void travel_list()
{
	valStruct* val;
	State_table *i;
	if (pthread_rwlock_rdlock(&state_lock) != 0)
	{
		printf("Can't acquire read lock on state lock.\n");
	}
	for(i=state_tbl;i != NULL; i=i->hh.next)
	{
		printf("%s: ",i->key);
		val = i->value;
		printf("State:%d Proto:%d Sequence:%d valid:%d timestamp:%d\n",
				val->state,val->protocol,val->sequence,val->valid,val->timestamp);
	}
	pthread_rwlock_unlock(&state_lock);
}

//Handle the ICMP error
int handle_icmp_error(keyStruct* k1,keyStruct *k2)
{
	keyStruct* temp;
	valStruct* val;
	State_table *i;
	for(i=state_tbl;i != NULL; i=i->hh.next)
	{
		val = i->value;
		temp = char_to_struct(i->key);
		if(((strcmp(temp->src_ip,k1->src_ip) == 0) && (strcmp(temp->dst_ip,k1->dst_ip) == 0)) ||
						((strcmp(temp->src_ip,k2->src_ip) == 0) && (strcmp(temp->dst_ip,k2->dst_ip) == 0)))
		{
			if(val->valid && (val->protocol == IPPROTO_TCP || val->protocol == IPPROTO_UDP))
				return 1;
		}
	}
	return 0;
}

//Update the state table
int updateState(struct ip* iphdr, void * other_p, int protocol, int proc, int time_val)
{
	//Testing
	travel_list();

	struct icmphdr* icmphdr;
	struct tcphdr* tcphdr;
	struct udphdr* udphdr;
	State_table *entry1, *entry2, *entry;
	State_table *new_entry = (State_table*)malloc(sizeof(State_table));

	char *tkey1 = (char*)malloc(sizeof(char)*50);
	char *tkey2 = (char*)malloc(sizeof(char)*50);

	keyStruct *key1,*key2;
	valStruct* val1, *val2, *val;
	int ticmp;

	key1 = (keyStruct*) malloc(sizeof(keyStruct));
	key2 = (keyStruct*) malloc(sizeof(keyStruct));

	strcpy(key1->src_ip, inet_ntoa(iphdr->ip_src));
	strcpy(key1->dst_ip, inet_ntoa(iphdr->ip_dst));
	strcpy(key2->dst_ip, inet_ntoa(iphdr->ip_src));
	strcpy(key2->src_ip, inet_ntoa(iphdr->ip_dst));

	//printf("Time: %d\n",time(0));

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

	strcpy(tkey1,struct_to_char(key1));
	strcpy(tkey2,struct_to_char(key2));
	printf("Searching: 1. %s \n 2. %s\n",tkey1,tkey2);

	if (pthread_rwlock_rdlock(&state_lock) != 0)
	{
		printf("Can't acquire read lock on state lock.\n");
	}
	HASH_FIND_STR(state_tbl,tkey1,entry1);
	HASH_FIND_STR(state_tbl,tkey2,entry2);
	pthread_rwlock_unlock(&state_lock);

	if((entry1 == NULL) && (entry2== NULL))
	{
		printf("%d-->Not found in the session table.\n",proc);

		//Return 0 only if new  session is allowed otherwise return -1
		if(protocol == IPPROTO_UDP)
		{
			//If UDP then we can't do more checking
			return 0;
		}
		if(protocol == IPPROTO_ICMP)
		{
			//If ICMP then allow session to establish only for request packets
			if(icmphdr->type == 8 || icmphdr->type == 13 ||	icmphdr->type == 15 ||
				icmphdr->type == 17 || icmphdr->type == 35 ||	icmphdr->type == 37 ||
				icmphdr->type == 33)
			{
				return 0;
			}
			else
			{
				//Check for special ICMP message here that is for TCP or UDP session
				//else return -1/0
				return handle_icmp_error(key1,key2);
			}
		}
		if(protocol == IPPROTO_TCP)
		{
			//If TCP then allow session to establish only for SYN packet
			if(tcphdr->syn == 1)
			{
				return 0;
			}
			else
			{
				return -1;
			}
		}
	}
	else
	{
		printf("%d-->Found in the session table.\n",proc);
		//Update the entry inside the table
		if(entry1 != NULL)
		{
			val = entry1->value;
			entry = entry1;
		}
		else if(entry2 != NULL)
		{
			val = entry2->value;
			entry = entry2;
		}

		if(val->valid == 0)
		{
			return -1;
		}

		if(time_val == -1)
			val->timestamp = time(0);
		else
			val->timestamp = time_val;

		if(protocol == IPPROTO_TCP)
		{
			if(val->state == 1)
			{
				//SYN seen, now SYN+ACK
				if(tcphdr->syn && tcphdr->ack)
					val->state = 2;
				else
					return -1;
			}
			else if(val->state == 2)
			{
				//SYN+ACK seen, now ACK
				if(tcphdr->ack)
					val->state = 3;
				else
					return -1;
			}
			else if(val->state == 3)
			{
				//ACK seen, now data,FIN
				if(tcphdr->fin)
					val->state = 4;
			}
			else if(val->state == 4)
			{
				//FIN seen, second FIN
				if(tcphdr->fin)
					val->state = 5;
				else
					return -1;
			}
			else if(val->state == 5)
			{
				//Two FINs seen, ACK
				if(tcphdr->ack)
					val->state = 6;
				else
					return -1;
			}
		}
		if (pthread_rwlock_wrlock(&state_lock) != 0)
		{
			printf("Can't acquire write lock on state lock.\n");
		}
		strcpy(new_entry->key, entry->key);
		new_entry->value = val;

		if(val->state != 6)
		{
			HASH_REPLACE_STR(state_tbl, key, entry, new_entry);
			printf("Replaced!\n");
		}
		else
		{
			HASH_DEL(state_tbl, entry);
			printf("DELETED!\n");
		}

		pthread_rwlock_unlock(&state_lock);
		return 1;
	}
	return 0;
}
