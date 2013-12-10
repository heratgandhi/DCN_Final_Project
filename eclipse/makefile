all:
	gcc -c -w rules.c
	gcc -c -w util.c
	gcc -c -w pcap.c
	gcc -c -w arp.c
	gcc -c -w firewall.c
	gcc -c -w state.c
	gcc -o firewall -w firewall.o rules.o util.o pcap.o arp.o state.o -lpcap -lpthread

clean:
	rm *.o
	rm firewall
