#include "rules.h"

rulenode* head;

void initialize(rulenode *ptr)
{
	strcpy(ptr->src_ip1,"");
	strcpy(ptr->src_ip2,"");
	ptr->src_subnet1 = -1;
	ptr->src_subnet2 = -1;
	strcpy(ptr->dst_ip1,"");
	strcpy(ptr->dst_ip2,"");
	ptr->dst_subnet1 = -1;
	ptr->dst_subnet2 = -1;
	ptr->src_port1 = -1;
	ptr->src_port2 = -1;
	strcpy(ptr->src_port_op,"");
	ptr->dst_port1 = -1;
	ptr->dst_port2 = -1;
	strcpy(ptr->dst_port_op,"");
	strcpy(ptr->protocol,"");
	ptr->default_rule = 0;
	ptr->result = -1;
	ptr->next = NULL;
}

void createList(char *file)
{
	FILE* fp_rules = fopen(file,"r");
	char* ptr;
	char str[256];
	int i = 0;
	int rule_p = 0;
	int len;
	int def_rule;
	rulenode *node;
	rulenode *pnode = NULL;
	int mode;

	while(fgets(str, 255, fp_rules) != NULL)
	{
		if(str[0] == '#')
			continue;

		ptr = strtok(str, " ");
		rule_p = 0;
		def_rule = 0;
		mode = 0;

		node = (rulenode*) malloc(sizeof(rulenode));
		initialize(node);

		while(ptr != NULL)
		{
			len = strlen(ptr);
			if(ptr[len-1] == '\n')
			{
				ptr[len-1] = '\0';
				len--;
			}
			switch(rule_p)
			{
				case 0:
					if(strcmp(ptr,"pass") == 0)
						node->result = PASS;
					else if(strcmp(ptr,"reject") == 0)
						node->result = REJECT;
					else
						node->result = BLOCK;
				break;
				case 1:
					strcpy(node->protocol,ptr);
				break;
				case 2:
					if(strcmp(ptr,"default") == 0)
					{
						node->default_rule = 1;
					}
					else
					{
						strcpy(node->src_ip1,ptr);
					}
				break;
				case 3:
					node->src_subnet1 = atoi(ptr);
				break;
				case 4:
					if(strlen(ptr) > 7)
					{
						strcpy(node->src_ip2,ptr);
						mode = 1;
					}
					else
					{
						strcpy(node->src_port_op,ptr);
						mode = 2;
					}
				break;
				case 5:
					if(mode == 1)
					{
						node->src_subnet2 = atoi(ptr);
						mode = 1;
					}
					else if(mode == 2)
					{
						node->src_port1 = atoi(ptr);
						mode = 2;
					}
				break;
				case 6:
					if(mode == 1)
					{
						strcpy(node->src_port_op,ptr);
						mode = 1;
					}
					else if(strlen(ptr) < 7)
					{
						node->src_port2 = atoi(ptr);
						mode = 2;
					}
					else
					{
						strcpy(node->dst_ip1,ptr);
						mode = 3;
					}
				break;
				case 7:
					if(mode == 1)
					{
						node->src_port1 = atoi(ptr);
						mode = 1;
					}
					else if(mode == 2)
					{
						strcpy(node->dst_ip1,ptr);
						mode = 2;
					}
					else
					{
						node->dst_subnet1 = atoi(ptr);
						mode = 3;
					}
				break;
				case 8:
					if(mode == 1)
					{
						if(strlen(ptr) < 7)
						{
							node->src_port2 = atoi(ptr);
							mode = 1;
						}
						else
						{
							strcpy(node->dst_ip1,ptr);
							mode = 2;
						}
					}
					else if(mode == 2)
					{
						node->dst_subnet1 = atoi(ptr);
						mode = 3;
					}
					else if(mode == 3)
					{
						if(strlen(ptr) < 7)
						{
							strcpy(node->dst_port_op,ptr);
							mode = 4;
						}
						else
						{
							strcpy(node->dst_ip2,ptr);
							mode = 5;
						}
					}
				break;
				case 9:
					if(mode == 1)
					{
						strcpy(node->dst_ip1,ptr);
						mode = 1;
					}
					else if(mode == 2)
					{
						node->dst_subnet1 = atoi(ptr);
						mode = 2;
					}
					else if(mode == 3)
					{
						if(strlen(ptr) < 7)
						{
							strcpy(node->dst_port_op,ptr);
							mode = 3;
						}
						else
						{
							strcpy(node->dst_ip2,ptr);
							mode = 4;
						}
					}
					else if(mode == 4)
					{
						node->dst_port1 = atoi(ptr);
						mode = 5;
					}
					else
					{
						node->dst_subnet2 = atoi(ptr);
						mode = 6;
					}
				break;
				case 10:
					if(mode == 1)
					{
						node->dst_subnet1 = atoi(ptr);
						mode = 1;
					}
					else if(mode == 2)
					{
						if(strlen(ptr) < 7)
						{
							strcpy(node->dst_port_op,ptr);
							mode = 2;
						}
						else
						{
							strcpy(node->dst_ip2,ptr);
							mode = 3;
						}
					}
					else if(mode == 3)
					{
						node->dst_port1 = atoi(ptr);
						mode = 4;
					}
					else if(mode == 4)
					{
						node->dst_subnet2 = atoi(ptr);
						mode = 5;
					}
					else if(mode == 5)
					{
						node->dst_port2 = atoi(ptr);
						mode = 6;
					}
					else
					{
						strcpy(node->dst_port_op,ptr);
						mode = 7;
					}
				break;
				case 11:
					if(mode == 1)
					{
						if(strlen(ptr) < 7)
						{
							strcpy(node->dst_port_op,ptr);
							mode = 1;
						}
						else
						{
							strcpy(node->dst_ip2,ptr);
							mode = 2;
						}
					}
					else if(mode == 2)
					{
						node->dst_port1 = atoi(ptr);
						mode = 3;
					}
					else if(mode == 3)
					{
						node->dst_subnet2 = atoi(ptr);
						mode = 4;
					}
					else if(mode == 4)
					{
						node->dst_port2 = atoi(ptr);
						mode = 5;
					}
					else
					{
						strcpy(node->dst_port_op,ptr);
						mode = 6;
					}
				break;
				case 12:
					if(mode == 1)
					{
						node->dst_port1 = atoi(ptr);
						mode = 1;
					}
					else if(mode == 2)
					{
						node->dst_subnet2 = atoi(ptr);
						mode = 2;
					}
					else if(mode == 3)
					{
						node->dst_port2 = atoi(ptr);
						mode = 3;
					}
					else if(mode == 4)
					{
						strcpy(node->dst_port_op,ptr);
						mode = 4;
					}
					else
					{
						node->dst_port1 = atoi(ptr);
						mode = 5;
					}
				break;
				case 13:
					if(mode == 1)
					{
						node->dst_port2 = atoi(ptr);
						mode = 1;
					}
					else if(mode == 2)
					{
						strcpy(node->dst_port_op,ptr);
						mode = 2;
					}
					else if(mode == 4)
					{
						node->dst_port1 = atoi(ptr);
						mode = 3;
					}
					else
					{
						node->dst_port2 = atoi(ptr);
						mode = 4;
					}
				break;
				case 14:
					if(mode == 2)
					{
						node->dst_port1 = atoi(ptr);
						mode = 1;
					}
					else
					{
						node->dst_port2 = atoi(ptr);
						mode = 2;
					}
				break;
				case 15:
					node->dst_port2 = atoi(ptr);
				break;
			}
			ptr = strtok(NULL, " ");
			rule_p++;
		}
		if(pnode == NULL)
		{
			head = node;
		}
		else
		{
			pnode->next = node;
		}
		pnode = node;
	}
	fclose(fp_rules);
}
