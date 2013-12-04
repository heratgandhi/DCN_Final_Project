all:
	gcc -c rules.c
	gcc -c util.c
	gcc -c pcap.c
	gcc -c arp.c
	gcc -c firewall.c
	gcc -c state.c
	gcc -c hashtable.c
	gcc -o firewall firewall.o rules.o util.o pcap.o arp.o state.o hashtable.o -lpcap -lpthread

clean:
	rm *.o
	rm firewall