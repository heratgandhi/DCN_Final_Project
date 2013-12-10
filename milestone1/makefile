all:
	gcc -c -w util.c
	gcc -c -w pcap.c
	gcc -c -w arp.c
	gcc -c -w firewall.c
	gcc -o firewall -w firewall.o util.o pcap.o arp.o -lpcap

clean:
	rm *.o
	rm firewall
    
