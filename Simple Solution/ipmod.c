#include <stdio.h>
#include <stdlib.h>

#define true 1
#define false 0

int IPToUInt(char* ip) {
    int a, b, c, d;
    int addr = 0;
 
    if (sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d) != 4)
        return 0;
 
    addr = a << 24;
    addr |= b << 16;
    addr |= c << 8;
    addr |= d;
    return addr;
}
int IsIPInRange(char* ip, char* network, char* mask) {
    int ip_addr = IPToUInt(ip);
    int network_addr = IPToUInt(network);
    int mask_addr = IPToUInt(mask);
 
    int net_lower = (network_addr & mask_addr);
    int net_upper = (net_lower | (~mask_addr));
 
    if (ip_addr >= net_lower &&
        ip_addr <= net_upper)
        return true;
    return false;
}
void test(char* ip, char* network, char* mask, int expected) {
    if (IsIPInRange(ip, network, mask) != expected) {
        printf("Failed! %s %s %s %s\n", ip, network, mask, expected ? "True" : "False");
    } else {
        printf("Success! %s %s %s %s\n", ip, network, mask, expected ? "True" : "False");
    }
}
 
 
int main(int argc, char **argv) {
    //std::string ip(argv[1]);
 
    test("20.1.1.129", "20.1.1.0", "255.255.255.0", true);
    test("192.168.1.1", "192.168.1.2", "255.255.255.255", false);
    test("192.168.1.3", "192.168.1.2", "255.255.255.255", false);
 
    test("10.1.1.128", "10.1.1.0", "255.255.255.0", true);
    test("220.1.1.22", "220.1.1.22", "255.255.255.255", true);
    test("220.1.1.22", "220.1.1.23", "255.255.255.255", false);
    test("220.1.1.22", "220.1.1.21", "255.255.255.255", false);
 
    test("0.0.0.1", "0.0.0.0", "0.0.0.0", true);
    test("192.168.1.2", "10.0.0.1", "255.255.255.255", false);
 
    return 0;
}
