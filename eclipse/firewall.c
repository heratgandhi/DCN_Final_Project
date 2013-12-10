#include "arp.h"
#include "pcap.h"
#include "rules.h"
#include "state.h"

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
int debugging;

//Thread 1 - which processes packets from one interface
void func1()
{
	printf("Thread-1 Started.\n");
	capture_loop(in_handle, -1, (pcap_handler)parse_packet, NULL);
	pthread_exit(NULL);
}

//Thread 2 - which processes packets from another interface
void func2()
{
	printf("Thread-2 Started.\n");
	capture_loop(out_handle, -1, (pcap_handler)parse_packet_p, NULL);
	pthread_exit(NULL);
}

//Thread 3 - cleans up State table
void func3()
{
	printf("Thread-3 Started : Cleanup Thread.\n");
	while(1)
	{
		//Get write lock on the state table
		if (pthread_rwlock_wrlock(&state_lock) != 0)
		{
			printf("Can't acquire write lock on state lock.\n");
		}

		cleanup_State(-1);

		//Release the write lock on the state table
		pthread_rwlock_unlock(&state_lock);

		//Sleep for the timeout period
		sleep(TIMEOUT);
	}
	pthread_exit(NULL);
}

//Thread 4 - cleans up ARP table
void func4()
{
	printf("Thread-4 Started.- ARP cleanup.\n");
	while(1)
	{
		//Get write lock on the ARP table
		if (pthread_rwlock_wrlock(&arp_lock) != 0)
		{
			printf("Can't acquire write lock on arp lock.\n");
		}

		cleanup_ARP();

		//Release the write lock on the ARP table
		pthread_rwlock_unlock(&arp_lock);

		//Sleep for the timeout period of the ARP cache
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
		printf("Usage: ./firewall mode rules_file [input pcap file] [output pcap file] 1/0\n",
				"           Mode: 1/2\n"
				"           Debugging: On/Off\n");
	}
    char errbuf[100];
    int mode = atoi(argv[1]);

    //Convert rules from File to linkedlist
    createList(argv[2]);
    //Print the rules for Debugging
    //iterList();

    //Initialize the hashtables
	state_tbl = NULL;
	arp_tbl = NULL;

	//Intitialze the locks
	if (pthread_rwlock_init(&arp_lock,NULL) != 0)
	{
		printf("ARP lock init failed.\n");
	}
	if (pthread_rwlock_init(&state_lock,NULL) != 0)
	{
		printf("State lock init failed.\n");
	}

	//If mode = 1 then use the interfaces to capture packets
    if(mode == 1)
    {
    	debugging = atoi(argv[3]);

    	pthread_t threads[4];
		//Open the interface handlers
		in_handle = pcap_open_live(INT_IN,65536,1,0,errbuf);
		out_handle = pcap_open_live(INT_OUT,65536,1,0,errbuf);

		//Create four threads
		pthread_create(threads + 0, NULL, func1, (void *) 0);
		pthread_create(threads + 1, NULL, func2, (void *) 1);
		pthread_create(threads + 2, NULL, func3, (void *) 2);
		pthread_create(threads + 3, NULL, func4, (void *) 3);

		//Wait for the four threads
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
		if(argc < 5)
		{
			printf("Usage: ./firewall mode rule_file [input pcap file] [output pcap file] 0/1\n",
				"           Mode: 1/2\n"
				"           Debug:On/Off\n");
		}
		debugging = atoi(argv[5]);
		in_handle = pcap_open_offline(argv[3],errbuf);
		//802.3 = 1 - link type
		//open new pcap handler
		out_handle = pcap_open_dead(1,65536);
		//open the file with the handler
		dumper = pcap_dump_open(out_handle, argv[4]);
		capture_loop(in_handle, -1, (pcap_handler)parse_packet_file, (u_char*)dumper);
	}
    //Memory cleanup
    cleanList();
    return 0;
}
