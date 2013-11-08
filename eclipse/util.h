#ifndef GLOBAL_H
#define GLOBAL_H
#include "globals.h"
#endif

unsigned short in_cksum(unsigned short *addr, int len);
void SendICMPError(char* src_addr, char* dst_addr);
int IPToUInt(char* ip);
int IsIPInRange(char* ip, char* network, char* mask);
int matchWithRules(char* src, char* dest);
void getArrayFromString(char* str1);
