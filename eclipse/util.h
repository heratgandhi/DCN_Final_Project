#ifndef GLOBAL_H
#define GLOBAL_H
#include "globals.h"
#endif

//Get the checksum value
unsigned short in_cksum(unsigned short *addr, int len);
//Send the ICMP error
void SendICMPError(char* src_addr, char* dst_addr);
//Convert IP to the number
int IPToUInt(char* ip);
//Check whether IP is in the range
int IsIPInRange(char* ip, char* network, char* mask);
//Match with the rules
int matchWithRules(char* src, char* dest);
//Get array of MAC address from the string
void getArrayFromString(char* str1);
