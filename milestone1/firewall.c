#include "arp.h"
#include "pcap.h"

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

    //If mode = 1 then use the interfaces to capture packets
    if(mode == 1)
    {
		pid_t childPID;
		//Open the interface handlers
		in_handle = pcap_open_live(INT_IN,65536,1,0,errbuf);
		out_handle = pcap_open_live(INT_OUT,65536,1,0,errbuf);
		//Create two processes for two interfaces
		childPID = fork();

		if(childPID >= 0)
		{
			//Associate the handlers with the interfaces
			if(childPID == 0)
			{
				capture_loop(in_handle, -1, (pcap_handler)parse_packet, NULL);
			}
			else
			{
				capture_loop(out_handle, -1, (pcap_handler)parse_packet_p, NULL);
			}
		}
		else
		{
			printf("\n Fork failed, quitting!!!!!!\n");
			return 1;
		}
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
    return 0;
}
