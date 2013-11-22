all:
	gcc -c util.c
	gcc -c pcap.c
	gcc -c arp.c
	gcc -c firewall.c
	gcc -o firewall firewall.o util.o pcap.o arp.o -lpcap -lpthread

clean:
	rm *.o
	rm firewall
    
