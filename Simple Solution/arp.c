#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>

char ip[16], mac[18];

char* getMac(char* ip_req)
{
	//Look inside the ARP cache first
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
	
	//Did not find in the APR cache, use arping
	FILE *fp;
	int status;
	char path[1035];
	char cmd[1024];
	char *p;	
	i=1;
	
	sprintf(cmd,"arping -c1 %s",ip_req);
	
	fp = popen(cmd, "r");
	if (fp == NULL) {
		printf("Failed to run command\n" );
	}
	
	while (fgets(path, sizeof(path)-1, fp) != NULL) {
		if((p = strchr(path, '[')) != NULL) {
			while(p[i] != ']') {
				mac[i-1] = p[i];
				i++;		
			}
			mac[i-1] = '\0';
		}
	}
	
	pclose(fp);

	return mac;	
}

void main()
{
	printf("%s\n",getMac("192.168.48.1"));
}
