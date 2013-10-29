#include <stdio.h>

struct ARP_entry 
{
	char IPaddr[16];
	char MACaddr[18];
};

struct ARP_entry *ARP_table;
int count = 0;
char ip[16], mac[18];

char* getMac(char* ip_req)
{
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
			if (sscanf(line, "%s %s %s %s %s %s", &ip, 
			&a, &b, &mac, &c, &d) < 10)
			{
				if(strcmp(ip_req,ip) == 0)
					return &mac;
			}
		}
	}
	else
	{
		perror(filename);
	}
}

void getARP()
{
	int i=0;
	const char filename[] = "/proc/net/arp";
	char output[128];
	FILE *file = fopen(filename, "r");
	if (file)
	{
		char line [BUFSIZ];
		fgets(line, sizeof line, file);
		while (fgets(line, sizeof line, file))
		{
			count++;
		}
		ARP_table = (struct ARP_entry*) calloc(sizeof(struct ARP_entry),count);
		rewind(file);
		fgets(line, sizeof line, file);
		while (fgets(line, sizeof line, file))
		{
			char  a,b,c,d;
			if ( sscanf(line, "%s %s %s %s %s %s", &ip, &a, &b, &mac, &c, &d) < 10 )
			{
				if (i < count)
				{
					snprintf(ARP_table[i].IPaddr, 16, "%s", ip);
					snprintf(ARP_table[i].MACaddr, 18, "%s", mac);
					i++;
				}
			}
		}
	}
	else
	{
		perror(filename);
	}
}

void main()
{
	printf("%s\n",getMac("192.168.48.2"));
	//getARP();
	//int i;
	/*for(i=0;i<count;i++)
	{
		printf("%s %s\n",ARP_table[i].IPaddr, ARP_table[i].MACaddr);
	}*/
}
