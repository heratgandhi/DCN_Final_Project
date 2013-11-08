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
	if(argc < 2)
	{
		printf("Usage: ./firewall mode [input pcap file] [output pcap file]\n",
				"           Mode: 1/2\n");
	}
    char errbuf[100];
    int mode = atoi(argv[1]);

    if(mode == 1)
    {
		pid_t childPID;

		in_handle = pcap_open_live(INT_IN,65536,1,0,errbuf);
		out_handle = pcap_open_live(INT_OUT,65536,1,0,errbuf);

		childPID = fork();

		if(childPID >= 0)
		{
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
	else
	{
		if(argc < 4)
		{
			printf("Usage: ./firewall mode [input pcap file] [output pcap file]\n",
				"           Mode: 1/2\n");
		}
		in_handle = pcap_open_offline(argv[2],errbuf);
		//802.3 = 1 - link type
		out_handle = pcap_open_dead(1,65536);
		dumper = pcap_dump_open(out_handle, argv[3]);

		capture_loop(in_handle, -1, (pcap_handler)parse_packet_file, (u_char*)dumper);
	}
    return 0;
}
