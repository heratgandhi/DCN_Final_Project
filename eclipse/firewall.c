#include "arp.h"
#include "pcap.h"
#include "rules.h"
#include "state.h"
#include <pthread.h>

pcap_t* in_handle;
pcap_t* out_handle;
FILE* fp;
int mac_t[6];
char ip[16], mac[18];
int linkhdrlen;
pcap_dumper_t *dumper;

int arp_linkhdrlen;
pcap_t *arp_pcap;
char check_ip[16];
char arp_ans[18];

void func1()
{
	printf("Thread-1 Started.\n");
	capture_loop(in_handle, -1, (pcap_handler)parse_packet, NULL);
	pthread_exit(NULL);
}

void func2()
{
	printf("Thread-2 Started.\n");
	capture_loop(out_handle, -1, (pcap_handler)parse_packet_p, NULL);
	pthread_exit(NULL);
}

void func3()
{
	printf("Thread-3 Started : Cleanup Thread.\n");
	while(1)
	{
		cleanup_State();
		sleep(TIMEOUT);
	}
	pthread_exit(NULL);
}

void func4()
{
	printf("Thread-4 Started.- ARP cleanup.\n");
	while(1)
	{
		cleanup_ARP();
		sleep(TIMEOUT_ARP);
	}
	pthread_exit(NULL);
}

/*void iterList()
{
	rulenode* t = head;
	while(t != NULL)
	{
		printf("@ %s %s\n",t->src_ip1,t->dst_ip1);
		printf("@ %d %d\n",t->src_subnet1,t->dst_subnet1);
		printf("@ %s %d\n",t->protocol,t->result);
		t = t->next;
	}
}*/

int main(int argc, char **argv)
{
	//Check whether user has entered enough arguments
	if(argc < 2)
	{
		printf("Usage: ./firewall mode [input pcap file] [output pcap file]\n",
				"           Mode: 1/2\n");
	}
    char errbuf[100];
    int mode = atoi(argv[1]);
    createList("rules");
    //iterList();

	state_tbl = NULL;
	arp_tbl = NULL;

	//If mode = 1 then use the interfaces to capture packets
    if(mode == 1)
    {
    	pthread_t threads[4];
		//Open the interface handlers
		in_handle = pcap_open_live(INT_IN,65536,1,0,errbuf);
		out_handle = pcap_open_live(INT_OUT,65536,1,0,errbuf);

		//Create two threads for two interfaces
		pthread_create(threads + 0, NULL, func1, (void *) 0);
		pthread_create(threads + 1, NULL, func2, (void *) 1);
		pthread_create(threads + 2, NULL, func3, (void *) 2);
		pthread_create(threads + 3, NULL, func4, (void *) 3);

		pthread_join(threads[0], NULL);
		pthread_join(threads[1], NULL);
		pthread_join(threads[2], NULL);
		pthread_join(threads[3], NULL);

		pthread_exit(NULL);
	}
    //Else open the input pcap file for the processing and write to output pcap file
	else
	{
		//Check for the valid arguments
		if(argc < 4)
		{
			printf("Usage: ./firewall mode [input pcap file] [output pcap file]\n",
				"           Mode: 1/2\n");
		}
		in_handle = pcap_open_offline(argv[2],errbuf);
		//802.3 = 1 - link type
		//open new pcap handler
		out_handle = pcap_open_dead(1,65536);
		//open the file with the handler
		dumper = pcap_dump_open(out_handle, argv[3]);
		//Process all the packets from the file
		capture_loop(in_handle, -1, (pcap_handler)parse_packet_file, (u_char*)dumper);
	}

    hdestroy();
    return 0;
}
