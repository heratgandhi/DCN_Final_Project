#ifndef GLOBAL_H
#define GLOBAL_H
#include "globals.h"
#endif

typedef struct keyStruct
{
	char src_ip[16];
	char dst_ip[16];
	int sport;
	int dport;
}keyStruct;

typedef struct valStruct
{
	int state;
	int protocol;
	int sequence;
	int identifier;
	int valid;
	int timestamp;
}valStruct;

typedef struct keyList
{
	keyStruct* key;
	struct keyList* next;
}keyList;

int updateState(struct ip* iphdr, void * other_p, int protocol,int proc);
char* struct_to_char(keyStruct* key);

keyList* keyListHead;
