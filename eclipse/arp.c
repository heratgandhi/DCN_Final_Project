#include "arp.h"
#include "pcap.h"
#include <stdlib.h>
#include <search.h>

int arp_cnt = 0;

typedef struct ip_mac
{
	char *mac;
	int timestamp;
	int valid;
}ip_mac;

typedef struct arp_list
{
	char *ip;
	struct arp_list* next;
}arp_list;

arp_list *arpKeyListHead = NULL;

//Insert ARP binding in the list
void insertInARPList(char *ip)
{
	arp_list* new_node = (arp_list*)malloc(sizeof(arp_list));
	new_node->ip = ip;
	new_node->next = NULL;
	if(arpKeyListHead == NULL)
	{
		arpKeyListHead = new_node;
	}
	else
	{
		arp_list* t = arpKeyListHead;
		while(t->next != NULL)
		{
			t = t->next;
		}
		t->next = new_node;
	}
}

//Check whether IP address exists in the ARP table
char* checkInARPTable(char *ip)
{
	ENTRY e1,*ep;
	ip_mac *val;
	e1.key = ip;
	ep = hsearch(e1,FIND);
	if(ep == NULL)
	{
		return NULL;
	}
	else
	{
		val = ep->data;
		//printf("Cached: %s\n",val->mac);
		return val->mac;
	}
}

//Insert ARP bining in the table
void insertInARPTable(char *ip, char *mac)
{
	ENTRY e;
	ip_mac* new_bin = (ip_mac*)malloc(sizeof(ip_mac));
	char* ip_key = (char*)malloc(sizeof(char)*16);

	new_bin->mac = mac;
	new_bin->valid = 1;
	new_bin->timestamp = time(0);
	strcpy(ip_key,ip);
	e.key = ip_key;

	insertInARPList(ip_key);

	hsearch(e,ENTER);
}

//Cleanup old ARP entries
void cleanup_ARP()
{
	arp_list *t = arpKeyListHead,*prevN = NULL,*delN;
	char* temp;
	ip_mac* val;
	ENTRY e1,*ep;

	while(t != NULL)
	{
		temp = t->ip;
		e1.key = temp;
		ep = hsearch(e1,FIND);
		val = ep->data;
		if(val->valid && ((time(0) - val->timestamp) > TIMEOUT_ARP))
		{
			val->valid = 0;
			if(prevN == NULL)
				arpKeyListHead = t->next;
			else
				prevN->next = t->next;
			delN = t;
			t = t->next;
			free(delN);
			free(temp);
			free(val);
		}
		else
		{
			prevN = t;
			t = t->next;
		}
	}
}

//Pcap handler for ARP packets
void parse_packet_arp(u_char *user, struct pcap_pkthdr *packethdr, u_char *packetptr)
{
	arp_cnt++;
	/*
	 * Check for the error- If there are more than 3 packets
	 * after ARP request then timeout.
	 */
	if(arp_cnt > 3)
	{
		strcpy(arp_ans,"");
		pcap_breakloop(arp_pcap);
	}
    struct ethhdr *eth = (struct ethhdr *)packetptr;
    //Check if the packet is of ARP protocol
    if(htons(eth->h_proto) != 0x0806)
		return;
    struct ether_arp* arph = (struct ether_arp*)(packetptr+sizeof(struct ethhdr));
    char ip_hdr[16];
    //Check if the packet is ARP response
    if(ntohs(arph->arp_op) != 2)
		return;
    sprintf(ip_hdr,"%d.%d.%d.%d", arph->arp_spa[0],arph->arp_spa[1],arph->arp_spa[2],arph->arp_spa[3]);
    //Compare the ip address of the sender with the target ip address
    if(strcmp(ip_hdr,check_ip) != 0)
		return;
    //Get mac address
    sprintf(arp_ans,"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    pcap_breakloop(arp_pcap);
}

//Main function to get the MAC from IP
char* get_Mac_ARP(char* target_ip_string,char *if_name)
{

	//First check inside the cache of the OS
	const char filename[] = "/proc/net/arp";
	char ip_l[16];
	char* mac_ans;

	mac_ans = checkInARPTable(target_ip_string);
	if(mac_ans != NULL)
	{
		strcpy(arp_ans,mac_ans);
		return arp_ans;
	}

	FILE *file = fopen(filename, "r");
	if (file)
	{
		char line [BUFSIZ];
		fgets(line, sizeof line, file);
		while (fgets(line, sizeof line, file))
		{
			char a,b,c,d;
			if(sscanf(line, "%s %s %s %s %s %s", &ip_l,&a, &b, &arp_ans, &c, &d) < 10)
			{
				if(strcmp(target_ip_string,ip_l) == 0)
				{
					//printf("Found in the cache: %s\n",arp_ans);
					insertInARPTable(target_ip_string,arp_ans);
					return arp_ans;
				}
			}
		}
	}
	else
	{
		perror(filename);
	}

	//Did not find in the APR cache, use arping
    strcpy(check_ip,target_ip_string);

    // Construct Ethernet header (except for source MAC address).
    // (Destination set to broadcast address, FF:FF:FF:FF:FF:FF.)
    struct ether_header header;
    header.ether_type=htons(ETH_P_ARP);
    memset(header.ether_dhost,0xff,sizeof(header.ether_dhost));

    // Construct ARP request (except for MAC and IP addresses).
    struct ether_arp req;
    req.arp_hrd=htons(ARPHRD_ETHER);
    req.arp_pro=htons(ETH_P_IP);
    req.arp_hln=ETHER_ADDR_LEN;
    req.arp_pln=sizeof(in_addr_t);
    req.arp_op=htons(ARPOP_REQUEST);
    memset(&req.arp_tha,0,sizeof(req.arp_tha));

    // Convert target IP address from string, copy into ARP request.
    struct in_addr target_ip_addr={0};
    if (!inet_aton(target_ip_string,&target_ip_addr))
    {
       fprintf(stderr,"%s is not a valid IP address",target_ip_string);
       exit(1);
    }
    memcpy(&req.arp_tpa,&target_ip_addr.s_addr,sizeof(req.arp_tpa));

    // Write the interface name to an ifreq structure,
    // for obtaining the source MAC and IP addresses.
    struct ifreq ifr;
    size_t if_name_len=strlen(if_name);
    if (if_name_len<sizeof(ifr.ifr_name))
    {
        memcpy(ifr.ifr_name,if_name,if_name_len);
        ifr.ifr_name[if_name_len]=0;
    }
    else
    {
        fprintf(stderr,"interface name is too long");
        exit(1);
    }

    // Open an IPv4-family socket for use when calling ioctl.
    int fd=socket(AF_INET,SOCK_DGRAM,0);
    if (fd==-1)
    {
        perror(0);
        exit(1);
    }

    // Obtain the source IP address, copy into ARP request
    if (ioctl(fd,SIOCGIFADDR,&ifr)==-1)
    {
        perror(0);
        close(fd);
        exit(1);
    }
    struct sockaddr_in* source_ip_addr = (struct sockaddr_in*)&ifr.ifr_addr;
    memcpy(&req.arp_spa,&source_ip_addr->sin_addr.s_addr,sizeof(req.arp_spa));

    // Obtain the source MAC address, copy into Ethernet header and ARP request.
    if (ioctl(fd,SIOCGIFHWADDR,&ifr)==-1)
    {
        perror(0);
        close(fd);
        exit(1);
    }
    if (ifr.ifr_hwaddr.sa_family!=ARPHRD_ETHER)
    {
        fprintf(stderr,"not an Ethernet interface");
        close(fd);
        exit(1);
    }
    const unsigned char* source_mac_addr=(unsigned char*)ifr.ifr_hwaddr.sa_data;
    memcpy(header.ether_shost,source_mac_addr,sizeof(header.ether_shost));
    memcpy(&req.arp_sha,source_mac_addr,sizeof(req.arp_sha));
    close(fd);

    // Combine the Ethernet header and ARP request into a contiguous block.
    unsigned char frame[sizeof(struct ether_header)+sizeof(struct ether_arp)];
    memcpy(frame,&header,sizeof(struct ether_header));
    memcpy(frame+sizeof(struct ether_header),&req,sizeof(struct ether_arp));

    // Open a PCAP packet capture descriptor for the specified interface.
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    pcap_errbuf[0]='\0';
    arp_pcap=pcap_open_live(if_name,96,0,0,pcap_errbuf);
    if (pcap_errbuf[0]!='\0')
    {
        fprintf(stderr,"%s\n",pcap_errbuf);
    }
    if (!arp_pcap)
    {
        exit(1);
    }

    // Write the Ethernet frame to the interface.
    if (pcap_inject(arp_pcap,frame,sizeof(frame))==-1)
    {
        pcap_perror(arp_pcap,0);
        pcap_close(arp_pcap);
        exit(1);
    }

    capture_loop(arp_pcap, -1, (pcap_handler)parse_packet_arp, NULL);

    // Close the PCAP descriptor.
    pcap_close(arp_pcap);
    //printf("MAC: %s\n",arp_ans);
    insertInARPTable(target_ip_string,arp_ans);
    return arp_ans;
}
