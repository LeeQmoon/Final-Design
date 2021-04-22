#include<stdio.h>
#include<string.h>

int main() {
    __u_char buff[100];
    __u_char pkt[50];
    for(int i = 0; i < 50 ;i++)
        pkt[i] = 'A';
    memmove(buff, pkt + 3, 50);
    printf("%s\n", pkt);
    printf("%s\n", buff);
    return 0;
}