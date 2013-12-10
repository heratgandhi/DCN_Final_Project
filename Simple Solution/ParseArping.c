#include <stdio.h>
#include <stdlib.h>
char mac1[18];

char* mac(char *ip)
{
	FILE *fp;
	int status;
	char path[1035];
	char cmd[1024];
	char *p;	
	int i=1;
	
	sprintf(cmd,"arping -c1 %s",ip);
	
	/* Open the command for reading. */
	fp = popen(cmd, "r");
	if (fp == NULL) {
		printf("Failed to run command\n" );
		exit;
	}

	/* Read the output a line at a time - output it. */
	while (fgets(path, sizeof(path)-1, fp) != NULL) {
		if((p = strchr(path, '[')) != NULL) {
			while(p[i] != ']') {
				mac1[i-1] = p[i];
				i++;		
			}
			mac1[i-1] = '\0';
		}
	}

	/* close */
	pclose(fp);

	return mac1;
}

int main( int argc, char *argv[] )
{
	printf("%s\n",mac("192.168.48.2"));  
}
