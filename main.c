#include<pcap.h>
#include <netinet/in.h>
#include<arpa/inet.h>
#include <net/ethernet.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<stdbool.h>

typedef struct pcap_pkthdr pcap_pkthdr;
typedef struct ether_header frame_header;
typedef struct ip ip_header;
typedef struct tcphdr tcp_header;
typedef u_int8_t u_int8;
typedef u_int16_t u_int16;
typedef u_int32_t u_int32;

static unsigned long pkt_cnt = 0;


typedef struct packet_info {
    u_int8 dst_mac[6];      /* 目的mac */
    u_int8 src_mac[6];      /* 源mac */
    
    u_int32 dst_ip;         /* 目的ip */
    u_int32 src_ip;         /* 源ip */
    u_int8 iphdr_len;       /* ip首部长度 */

    u_int16 dst_port;       /* 目的端口 */ 
    u_int16 src_port;       /* 源端口 */
    u_int8 tcphdr_len;      /* tcp首部长度 */

    u_char* application_data;   /* 应用层数据 */
}pkt_info;

typedef struct packet {
    pcap_pkthdr *pkt_header;
    pkt_info *pkt_info;
}packet;

typedef struct packet_list {
    packet *head;
    packet *tail;
}packet_list;


//static packet_list *pkt_list;
static unsigned long tls_cnt = 0;
void insert(packet_list *pkt_list, packet *packet);     /* 链表插入 */
void packetHandler(const u_char *pkt, pcap_pkthdr *pkt_header);

int main(int argc, char *argv[]) {
    
    if(argc < 2) {
        fprintf(stderr, "Usage: %s <pcap>\n", argv[0]);
        exit(1);
    }
    pcap_t *pcap_handle = NULL;    //pcap文件句柄
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_pkthdr pkt_header;
    char *pcap_file_path = "/home/leemoon/Desktop/baidu.pcap";
    //packet_list *pkt_list = {NULL, NULL};

    // if(!strcmp(argv[1], pcap_file_path)) {
    //     printf("Copy pcap file path sucessfully!\n");
    // }
    // else {
    //     printf("Copy pcap file path error!\n");
    //     return(2);
    // }

    if(!(pcap_handle = pcap_open_offline(pcap_file_path, errbuf))) {
        fprintf(stderr, "Couldn't open the pcap file %s: %s\n", pcap_file_path, errbuf);
        return(2);
    }

    const u_char *pkt = NULL;
    while(pkt = pcap_next(pcap_handle, &pkt_header)) {
        packetHandler(pkt, &pkt_header);
        pkt_cnt++;
    }
    printf("tls_cnt = %lu\n", tls_cnt);
    printf("packet count = %lu\n", pkt_cnt);
    return 0;

}

void packetHandler(const u_char *pkt, pcap_pkthdr *pkt_header) {
    tls_cnt++;
    //printf("-----hello----\n");
    frame_header *framehdr = NULL;
    ip_header *iphdr = NULL;
    tcp_header *header_tcp = NULL;
    bool flag = false;          /* TCP/IPV4协议体系标志 */
    char sourceIp[INET_ADDRSTRLEN];
    char destIp[INET_ADDRSTRLEN];
    
    framehdr = (frame_header *)pkt;
    if(ntohs(framehdr->ether_type) == ETHERTYPE_IP) {//判断帧 上一层协议是否为ipv4 0x08
        iphdr = (ip_header *)(pkt + sizeof(frame_header));
        if(iphdr->ip_p == IPPROTO_TCP) {  //判断上一层是否为TCP协议, 此处不能使用ntohs转换
            flag = true;
            header_tcp = (tcp_header *)(pkt + sizeof(frame_header) + sizeof(ip_header));
        }
    }

    if(flag) {  //是TCP/ip协议体系
        packet *p = (packet*)malloc(sizeof(packet)); //这里必须强制类型转换,否则coredump
        p->pkt_header = malloc(sizeof(pcap_pkthdr));
        p->pkt_info = malloc(sizeof(pkt_info));

        p->pkt_header->caplen = pkt_header->caplen;
        p->pkt_header->len = pkt_header->len;
        p->pkt_header->ts = pkt_header->ts;
        for(int i = 0; i < 6; i++) {
            p->pkt_info->src_mac[i] = framehdr->ether_shost[i];
            p->pkt_info->dst_mac[i] = framehdr->ether_dhost[i];
        }
    
        p->pkt_info->src_ip = (iphdr->ip_src.s_addr);//调用ntohl,而不是调用ntohs
        p->pkt_info->dst_ip = (iphdr->ip_dst.s_addr);
        p->pkt_info->iphdr_len = (iphdr->ip_hl) * 4;       /* ip header长度 */
        inet_ntop(AF_INET, &(p->pkt_info->src_ip), sourceIp, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(p->pkt_info->dst_ip), destIp, INET_ADDRSTRLEN);

        p->pkt_info->src_port = ntohs(header_tcp->th_sport);//不是调用ntohl,调用的是ntohs
        p->pkt_info->dst_port = ntohs(header_tcp->th_dport);
        p->pkt_info->tcphdr_len = (header_tcp->th_off) * 4; /* 长度的获取都不许调用ntohl,n
tohs函数 */

        u_char *tmp = (u_char *)(pkt + 14 + iphdr->ip_hl * 4 + header_tcp->th_off * 4);
        u_int8 content_type = 0;
        u_int16 version = 0;
        u_int16 length = 0;
        bool tls_flag = false;

        if(tmp != pkt + pkt_header->caplen && *tmp != 0) {
            printf("num = %lu\tc = %0x\n",tls_cnt, *(tmp));
            //tls_cnt++;
        }
        //p->pkt_info->application_data = (u_char *)malloc(p->pkt_header->caplen - (sizeof(frame_header) + sizeof(ip_header) + sizeof(tcp_header)));
       // p->pkt_info->application_data = pkt + sizeof(frame_header) + sizeof(ip_header) + sizeof(tcp_header);     
        //printf("%0x\n", *pkt);
        //printf("pkt_cnt = %lu\tc = %0x\n", pkt_cnt, *(tmp));
        //printf("cap_len = %u\tc = %0x\n", pkt_header->caplen, (pkt + (sizeof(frame_header) + sizeof(ip_header) + sizeof(tcp_header))));
        if(tmp < pkt + pkt_header->caplen) {
            if(*(tmp) == 0x14 || *(tmp) == 0x15 || *(tmp) == 0x16 || *(tmp) == 0x17)
                content_type = *(tmp);
                tls_flag = true;
        }
        if(tmp + 1 < pkt + pkt_header->caplen) {
            if(*(tmp + 1) == 0x0300 || *(tmp + 1) == 0x0301 || *(tmp + 1) == 0x0302 || *(tmp + 1) == 0x0303)
                version == *(tmp + 1);
        }
        if(tmp + 3 < pkt + pkt_header->caplen) {
            length = *(tmp + 3);
            
        }
        // printf("%02x:%02x:%02x:%02x:%02x:%02x\t", 
        //         p->pkt_info->src_mac[0], p->pkt_info->src_mac[1], p->pkt_info->src_mac[2], p->pkt_info->src_mac[3], p->pkt_info->src_mac[4], p->pkt_info->src_mac[5]);
        // printf("%02x:%02x:%02x:%02x:%02x:%02x\t", 
        //         p->pkt_info->dst_mac[0], p->pkt_info->dst_mac[1], p->pkt_info->dst_mac[2], p->pkt_info->dst_mac[3], p->pkt_info->dst_mac[4], p->pkt_info->dst_mac[5]);
        // printf("sip = %s\tdip = %s\ts_port = %u\td_port = %u\n", 
        //         sourceIp, destIp, p->pkt_info->src_port, p->pkt_info->dst_port);
        // printf("etherhdr_len = %u\tiphdr_len = %u\ttcphdr_len = %u\n",
        //     pkt_header->caplen, p->pkt_info->iphdr_len, p->pkt_info->tcphdr_len);
        //free(p->pkt_info->application_data);
        if(tls_flag) {

            //printf("content_type = %u\tversion = %u\tlength = %u\n", content_type, version, length);
        }
        free(p->pkt_header);
        free(p->pkt_info);
        free(p);
        //insert(pkt_list, p);
    }
    else return;
}