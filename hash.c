#include<sys/time.h>
#include<stdio.h>
#include<fcntl.h>
#include "type.h"

static u_char perm[12];
static u_char xor[12];

//perm产生0 - 11的随机数; xor产生 0 - 255的随机数
static void getRandom() {
    struct timeval s;
    u_int32 *ptr;
    int fd = open("/dev/urandom", O_RDONLY);
    if(fd > 0) {
        read(fd, perm, 12);
        read(fd, xor, 12);
        close(fd);
        return;
    }
    gettimeofday(&s, 0);    //不用time(),time返回秒精度,在1s内多次调用,数据会一样
    srand(s.tv_usec);       //以微妙作为精度
    ptr = (unsigned int *) perm;
    *ptr = rand();
    *(ptr + 1) = rand();
    *(ptr + 2) = rand();
    ptr = (unsigned int *) xor;
    *ptr = rand();
    *(ptr + 1) = rand();
    *(ptr + 2) = rand();

    return;
}

//在perm[12]中产生0 - 11的随机数
void initHash() {
    int tmp[12];
    getRandom();
    for(int i = 0; i < 12; i++)
        tmp[i] = i;
    for(int i = 0; i < 12; i++) {
        int n = perm[i] % (12 - i);
        perm[i]  = tmp[n];
        for(int j = 0; j < 11 - n; j++)
            tmp[n + j] = tmp[n + j + 1];
    }

}

u_int32 tupleHash(u_int32 src_ip, u_int32 dst_ip, u_int16 sport, u_int16 dport) {
    u_int32 res = 0;
    int i;
    u_char data[12];
    u_int32 *stupid_strict_aliasing_warnings = (u_int32 *)data;
    *stupid_strict_aliasing_warnings = src_ip;
    *(u_int32 *) (data + 4) = dst_ip;
    *(u_int16 *) (data + 8) = sport;
    *(u_int16 *) (data + 10) = dport; 
    for(int i = 0; i < 12; i++) {
        res = ( (res << 8) + (data[perm[i]] ^ xor[i])) % 0xff100f;
    }

    return res;
}
