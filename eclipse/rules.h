#ifndef GLOBAL_H
#define GLOBAL_H
#include "globals.h"
#endif

typedef struct rulenode
{
	char src_ip1[16];
	char src_ip2[16];
	int src_subnet1;
	int src_subnet2;
	char dst_ip1[16];
	char dst_ip2[16];
	int dst_subnet1;
	int dst_subnet2;
	int src_port1;
	int src_port2;
	char src_port_op[2];
	int dst_port1;
	int dst_port2;
	char dst_port_op[2];
	char protocol[5];
	int default_rule;
	int result;
	rulenode* next;
}rulenode;
