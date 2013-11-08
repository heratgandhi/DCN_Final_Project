firewall: firewall.o arp.o pcap.o util.o
    gcc -o firewall firewall.o arp.o pcap.o util.o

firewall.o: firewall.c arp.h arp.c pcap.h pcap.o globals.h util.c util.h
    gcc -c main.c
    
arp.o: arp.c arp.h pcap.c pcap.h globals.h
	gcc -c arp.c    

pcap.o: pcap.c pcap.h arp.c arp.h globals.h util.h util.c
	gcc -c pcap.c

util.o: util.c util.h globals.h
    gcc -c util.c