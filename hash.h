#ifndef HASH_H
#define HASH_H

#include"type.h"

void getRandom();
void initHash();
u_int32 tupleHash(u_int32 src_ip, u_int32 dst_ip, u_int16 sport, u_int16 dport);

#endif