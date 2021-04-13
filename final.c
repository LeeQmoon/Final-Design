#include<pcap.h>
#include"type.h"
#include"hash.h"
#include<netinet/in.h>
#include<arpa/inet.h>
#include<net/ethernet.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<stdbool.h>
#define TCP_STREAM_HASHTABLE_SIZE 1040
#define MAX_TCP_STREAM (3 * TCP_STREAM_HASHTABLE_SIZE / 4)
#define MAX_FILE_PATH 100

typedef struct pcap_pkthdr pkt_hdr;     /* pcap文件数据包头 */
typedef struct ether_header frame_hdr;  /* 帧头部 */
typedef struct ip ip_hdr;               /* ip头部 */
typedef struct tcphdr tcp_hdr;          /* tcp头部 */
typedef struct single_direction_stream single_direction_stream; /* 单向流 */
typedef struct tcp_stream tcp_stream;   /* 双向流 */
typedef struct tcp_buff tcp_buff;       /* 缓冲区 */
typedef struct packet packet;           /* 数据包 */
typedef struct tuple tuple;             /* 四元组 */

struct tuple {
    u_int32 sip;            /* 源ip */
    u_int32 dip;            /* 目的ip */
    u_int16 sport;          /* 源端口 */
    u_int16 dport;          /* 目的端口 */
};

struct packet {
    u_int32 caplen;         /* 数据包实际长度 */
    struct timeval ts;      /* 数据包到达时间 */

    u_int8 dst_mac[6];      /* 目的mac */
    u_int8 src_mac[6];      /* 源mac */
    
    u_int32 dst_ip;         /* 目的ip */
    u_int32 src_ip;         /* 源ip */
    u_int8 iphdr_len;       /* ip首部长度 */

    u_int16 dst_port;       /* 目的端口 */ 
    u_int16 src_port;       /* 源端口 */
    u_int8 tcphdr_len;      /* tcp首部长度 */
    u_int32 seq;            /* 数据包绝对序列号 */
    u_int32 relative_seq;   /* 数据包相对序列号 */
    u_int32 ack;            /* 数据包确认号 */
    u_int32 relative_ack;   /* 数据包相对确认号 */
    u_int8 flag;               /* 标志位 */ 
    
    u_char* application_data;   /* 应用层数据 */
    u_int data_len;         /* 应用层数据长度 */
};

struct tcp_buff {
    u_char *data;             /* 应用层数据包 */
    u_int32 datalen;          /* 数据包长度 */
    u_int32 seq;              /* seq */
    u_int8 flag;              /* 标志 */
    tcp_buff *next;         /* 双向链表维护包 */
    tcp_buff *prev;             
};

struct single_direction_stream {
    u_char *data;             /* 应用层数据 */
    int buffsize;             /* 有序数据buffsize */
    //FILE* fd;                 /* 关联的文件描述符 */
    u_int32 datalen;          /* 有序的应用层数据总大小 */
    u_int32 data_cnt;         /* 总的字节数 */
    u_int32 absolute_seq;     /* 绝对序列号 */
    u_int32 absolute_ack;     /* 绝对确认号 */
    tcp_buff *head;      /* 缓冲区中第一个数据包 */
    tcp_buff *tail;      /* 缓冲区中最后一个数据包 */
    char state;               /* 流状态 */
}; 

struct tcp_stream {
    tuple tuple_msg;                    /* 四元组 */
    single_direction_stream *client;    /* tcp流中的客户端 */
    single_direction_stream *server;    /* tcp流中的服务端 */
    u_int32 index;                      /* 在流表中的索引 */
    tcp_stream *next;                   /* 槽中第一个流 */
    tcp_stream *prev;                   /* 槽中的最后一个流 */
    
};

static tcp_stream **tcp_stream_hashtable;   /* tcp流哈希表 */
static tcp_stream *tcp_stream_pool;         /* tcp流池 */
static tcp_stream *free_stream;             /* 当前空闲流 */
static unsigned free_tcp_stream_cnt = 0;    /* 记录当前tcp流池的空闲块起始 */
static u_int32 tcp_cnt = 0;                 /* tcp数据的数目 */

u_int32 mkHash(tuple tuple_val);
void error(const char *msg);
void initTcp();
void packetHandler(const u_char *data, const pkt_hdr *pkt_header);
void processTcp(ip_hdr* ip_header, u_char *data);
tcp_stream *isTcpStreanExist(ip_hdr *ip_header, tcp_hdr *tcp_header, bool *isClient);
void addNewTcpStream(ip_hdr *ip_header, tcp_hdr *tcp_header, u_char *data);

int main(int agrc, char *agrv[]) {
    if(agrc < 2) 
        error("Please enter pcap file path as the second argument!\n");
    
    pcap_t *handle = NULL;  //pcap文件句柄
    char errbuf[PCAP_ERRBUF_SIZE];  //pcap错误信息
    pkt_hdr pkt_header;     //此处不能用指针,要是用指针要分配内存
    char pcap_file_path[MAX_FILE_PATH];
    strncpy(pcap_file_path, agrv[1], MAX_FILE_PATH - 1);
    pcap_file_path[MAX_FILE_PATH] = '\0';
    
    if(!(handle = pcap_open_offline(pcap_file_path, errbuf))) {
        fprintf(stderr, "Couldn't open the pcap file %s: %s\n", pcap_file_path, errbuf);
        return(2);
    }

    // printf("sizeof(frame_hdr) = %u\tsizeof(ip_hdr) = %u\tsizeof(tcp_hdr) = %u\n",
    //         sizeof(frame_hdr), sizeof(ip_hdr), sizeof(tcp_hdr)); //为啥没有内存对齐的问题,奇怪
    const u_char *pkt = NULL;
    u_int pkt_cnt = 0;
    while(pkt = pcap_next(handle, &pkt_header)) {   //一个个数据包进行获取,处理
        //printf("--- hello ---\n");
        packetHandler(pkt, &pkt_header);
        pkt_cnt++;
    }
    printf("pkt_cnt = %u\ttcp_cnt = %u\n", pkt_cnt, tcp_cnt);
    return 0;

}

u_int32 mkHash(tuple tuple_val) {
    u_int32 key = tupleHash(tuple_val.sip, tuple_val.dip, tuple_val.sport, tuple_val.dport);
    return key % TCP_STREAM_HASHTABLE_SIZE; //取模运算还可以优化,使用移位来实现
}

void error(const char *msg) {
    fprintf(stderr, msg);
    exit(1);
}

void initTcp() {
    printf("--- tcp init ---\n");
    *tcp_stream_hashtable = (tcp_stream *)calloc(TCP_STREAM_HASHTABLE_SIZE, sizeof(tcp_stream *));
    if(!tcp_stream_hashtable) {
        error("Couldn't malloc enough memory for tcp stream hashtable\n");
    }
    tcp_stream_pool = (tcp_stream*)malloc((MAX_TCP_STREAM + 1) * sizeof(tcp_stream));  //搞个流池,避免每次都向OS申请内存,时间开销大
    if(!tcp_stream_pool) {
        error("Couldn't malloc enough memory for tcp stream pool\n");
    }
    return;
}

static int k = 1;

void packetHandler(const u_char *pkt, const pkt_hdr *pkt_header) {
    //for test
    char sourceIp[INET_ADDRSTRLEN];
    char destIp[INET_ADDRSTRLEN];

    frame_hdr *frame_header = NULL;
    ip_hdr *ip_header = NULL;
    tcp_hdr *tcp_header = NULL;
    frame_header = (frame_hdr *) (pkt);
    if(ntohs(frame_header->ether_type) == ETHERTYPE_IP) {//处理ipv4的
        ip_header = (ip_hdr *) (pkt + sizeof(frame_hdr));
        if(ip_header->ip_p == IPPROTO_TCP) {//为什么此处不需要字节序的转换
            //修改
            //processTcp(ip_header, pkt + sizeof(frame_hdr) + ip_header->ip_hl * 4);


            tcp_header = (tcp_hdr *) (pkt + sizeof(frame_hdr) + ip_header->ip_hl * 4);
            packet *pkt_info = (packet *)malloc(sizeof(packet));
            pkt_info->caplen = pkt_header->caplen;
            pkt_info->ts = pkt_header->ts;
            pkt_info->src_ip = ip_header->ip_src.s_addr;    //此时还是网络字节序
            pkt_info->dst_ip = ip_header->ip_dst.s_addr;
            pkt_info->iphdr_len = ip_header->ip_hl * 4;
            inet_ntop(AF_INET, &(pkt_info->src_ip), sourceIp, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(pkt_info->dst_ip), destIp, INET_ADDRSTRLEN);
            
            pkt_info->src_port = ntohs(tcp_header->th_sport);
            pkt_info->dst_port = ntohs(tcp_header->th_dport);
            pkt_info->tcphdr_len = tcp_header->th_off * 4;
            pkt_info->flag = tcp_header->th_flags;
            pkt_info->seq = ntohl(tcp_header->th_seq);
            pkt_info->ack = ntohl(tcp_header->th_ack);

            for(int i = 0; i < 6; i++) {
                pkt_info->src_mac[i] = frame_header->ether_shost[i];
                pkt_info->dst_mac[i] = frame_header->ether_dhost[i];
            }
            pkt_info->data_len = pkt_info->caplen - sizeof(frame_hdr) - pkt_info->iphdr_len - pkt_info->tcphdr_len;
            pkt_info->application_data = (u_char *)malloc(sizeof(u_char) * (pkt_info->data_len + 1));
            printf("k = %d\tsrcIP = %s\tdstIP = %s\tseq = %u\tack = %u\tipHeaderLen = %hhu\ttcpLen = %hhu\tcaplen = %u\tdatalen = %u\n", k, sourceIp, destIp, pkt_info->seq, pkt_info->ack, pkt_info->iphdr_len,pkt_info->tcphdr_len, pkt_info->caplen, pkt_info->data_len);
            memmove(pkt_info->application_data, pkt + sizeof(frame_hdr) + pkt_info->iphdr_len + pkt_info->tcphdr_len, pkt_info->data_len);
            tcp_cnt++;
            // printf("forward index = %u\treversed inde = %d\n",
            // mkHash(pkt_info->src_ip, pkt_info->dst_ip, pkt_info->src_port, pkt_info->dst_port),
            // mkHash(pkt_info->dst_ip, pkt_info->src_ip, pkt_info->dst_port, pkt_info->src_port));
            
            //processTcp(pkt_info);
            //for test
            free(pkt_info->application_data);
            free(pkt_info);

        
        }
    }
    k++;
    return;
}

//判断流表是否含有该四元组的哈希
tcp_stream *findTcpStream(tuple tuple_val) {
    int hash_index = mkHash(tuple_val);
    tcp_stream *tmp = NULL;
    for(tmp = tcp_stream_hashtable[hash_index];
        tmp && memcmp(&tmp->tuple_msg, &tuple_val, sizeof(tuple)); 
        tmp = tmp->next);

    return tmp; 
}

//正逆皆判断,为server?为client?
tcp_stream *isTcpStreanExist(ip_hdr *ip_header, tcp_hdr *tcp_header, bool *isClient) {
    tuple forward, reverse;
    tcp_stream *tmp = NULL;
    forward.sip = ip_header->ip_src.s_addr;
    forward.dip = ip_header->ip_dst.s_addr;
    forward.sport = ntohs(tcp_header->th_sport);
    forward.dport = ntohs(tcp_header->th_dport);
    tmp = findTcpStream(forward);
    if(tmp) {
        *isClient = true;
        return tmp;
    }

    reverse.sip = forward.dip;
    reverse.dip = forward.sip;
    reverse.sport = forward.dport;
    reverse.dport = forward.sport;
    tmp = findTcpStream(reverse);
    if(tmp) {
        *isClient = false;
        return tmp;
    }

    return NULL;
}

//新增流会话
void addNewTcpStream(ip_hdr *ip_header, tcp_hdr *tcp_header, u_char *data) {
    if(tcp_cnt > MAX_TCP_STREAM) {
        error("TCP stream pool is full");
        return;
    }
    tcp_cnt++;
    tuple tuple_val;
    tcp_stream *tmp = free_stream, *link = NULL;
    free_stream = free_stream + sizeof(tcp_stream);
    tuple_val.sip = ip_header->ip_src.s_addr;
    tuple_val.dip = ip_header->ip_dst.s_addr;
    tuple_val.sport = ntohs(tcp_header->th_sport);
    tuple_val.dport = ntohs(tcp_header->th_dport);
    int hash_index = mkHash(tuple_val);
    link = tcp_stream_hashtable[hash_index];
    tmp->next = link;
    tmp->prev = NULL;
    link->prev = tmp;
    tmp->client->state = TCP_SYN_SENT;
    tmp->client->absolute_seq = ntohl(tcp_header->th_seq);
    tmp->client->absolute_ack = ntohl(tcp_header->th_ack);

    return;
}

//流中的空间分配策略
void addReceiverDataBuff(single_direction_stream *receiver, u_char * data, u_int32 datalen) {
    int toalloc;
    if(datalen + receiver->datalen > receiver->buffsize) {//新+旧数据长度 > 有序数据空间大小
        if(!receiver->data) {//还没有任何数据
            if(datalen < 2048) 
                toalloc = 4096;
            else toalloc = datalen * 2;
            receiver->data = (u_char *)malloc(toalloc);
            receiver->buffsize = toalloc;
        }
        else {//接收方中data有数据
            if(datalen < receiver->buffsize) //新数据长度 < data当前已分配的空间
                toalloc = 2 * receiver->buffsize;
            else toalloc = receiver->buffsize + 2 * datalen;
            receiver->data = realloc(receiver->data, toalloc);
            receiver->buffsize = toalloc;
        }
        memcpy(receiver->data + receiver->datalen, data, datalen);
        receiver->datalen += datalen;

        return;
    }
}

//到达的数据包置于有序数据后面
void addToOrderData(single_direction_stream *receiver, u_int32 orderd_data_seq, u_int32 latest_seq, u_char *data, u_int32 datalen) {
    u_int32 substraction = orderd_data_seq - latest_seq;
    addReceiverDataBuff(receiver, data + substraction, datalen - substraction);

    return;
}

//处理到达的数据包,是直接置于有序数据后面,还是置于接收缓冲区中
void tcp_queue(single_direction_stream *receiver, u_int32 first_data_seq, tcp_hdr *tcp_header, u_char *data, u_int32 datalen) {
    u_int32 orderd_data_seq = first_data_seq + receiver->datalen;    //有序数据最后一个字节序列号,发送方seq + 接收方有序数据字节数

    if(ntohl(tcp_header->th_seq) <= orderd_data_seq) {//到达数据包序列号在有序数据最后一个字节序列号之前
        //情况一:重复包,不处理
        //情况二:重叠包,处理,直接添加到接收方的有序数据后面,此时有序数据最后一个字节的序列号更新了,需查询缓冲区中是否有能添加到有序数据中的
        if(ntohl(tcp_header->th_seq) + datalen + tcp_header->th_flags & TH_FIN > orderd_data_seq) {
            addToOrderData(receiver, orderd_data_seq, ntohl(tcp_header->th_seq), data, datalen);
            //此时,有序数据最后一个字节的序列号已更改,查询缓冲区中是否可提取数据到data中
            u_int32 substraction = orderd_data_seq - ntohl(tcp_header->th_seq);
            datalen -= substraction;
            orderd_data_seq += datalen;//更新后,有序数据最后一个字节的序列号
            tcp_buff *head = receiver->head;//从前往后查询
            while(head) {
                if(head->seq > orderd_data_seq) break;  //序列号在有序数据之后,终止
                if(head->seq + head->datalen + (head->flag & TH_FIN) > orderd_data_seq) {//具有重叠部分
                    addToOrderData(receiver, orderd_data_seq, head->seq, head->data, head->datalen);
                    datalen = head->datalen - (orderd_data_seq - head->seq);
                    orderd_data_seq += datalen;
                }
                //无论是重叠,还是重复,都需要处理,释放该部分内存
                tcp_buff *tmp = head;
                if(head->prev) 
                    head->prev->next = head->next;
                else 
                    receiver->head = head->next;
                if(head->next) 
                    head->next->prev = head->prev;
                else 
                    receiver->tail = head->next;   //尾部要置空
                head = head->next;  
                free(tmp->data);
                free(tmp);
            }
        }
        return;
    }
    else {//到达数据包序列号在有序数据最后一个字节序列号之后,将到达数据添加到接收缓冲区中
        tcp_buff *tmp = receiver->tail;//从后往前查询
        tcp_buff * new_buff = (tcp_buff *)malloc(sizeof(tcp_buff));
        new_buff->data = (u_char *)malloc(datalen);
        new_buff->datalen = datalen;
        new_buff->flag = tcp_header->th_flags;
        new_buff->seq = ntohl(tcp_header->th_seq);
        while(tmp) {
            if(!tmp || new_buff->seq >= tmp->seq)
                break;
            tmp = tmp->prev;
        }
        if(!tmp) {//双指针插入操作,插入位置:头
            new_buff->prev = NULL;
            new_buff->next = receiver->head;
            if(receiver->head) //缓冲区不为空
                receiver->head->prev = new_buff; 
            receiver->head = new_buff;
            if(!receiver->tail) {//缓冲区为空时,需要把尾也设置上
                receiver->tail = new_buff;
            }
        }
        else {//中间节点
            new_buff->next = tmp->next;
            new_buff->prev = tmp;
            tmp->next = new_buff;
            if(!new_buff->next) //若原缓冲区就一个包,尾需要更新
                receiver->tail = new_buff;
            else new_buff->next->prev = new_buff;
        }
        return;
    }

}

void processTcp(ip_hdr *ip_header, u_char *data) {
    tcp_hdr *tcp_header = (tcp_hdr *)data;
    u_int32 ip_len = ip_header->ip_hl * 4;
    u_int32 tcp_len = tcp_header->th_off * 4;
    u_int32 app_data_len = ntohs(ip_header->ip_len) - ip_len - tcp_len;
    //hash查询是否存在流 存在放进半流的缓冲区;不存在,新建流
    bool isClient = false; 
    tcp_stream *tmp = isTcpStreanExist(ip_header, tcp_header, &isClient);
    if(!tmp) {//不存在流,一次握手
        if((tcp_header->th_flags & TH_SYN) && !(tcp_header->th_flags & TH_ACK) && !(tcp_header->th_flags & TH_RST)) {
            addNewTcpStream(ip_header, tcp_header, data + tcp_len);
        }
        return;
    }
    //存在相应流
    if(tcp_header->th_flags & TH_SYN) {//如果是SYN包
        //情况一:来自客户端,已重复,不再处理
        //情况二:只能来自服务端,二次握手,此时客户端处在SYN_SENT;服务端处在TCP_LISTEN状态
        //情况三:端口的重新利用,旧流被抛弃,新流建立.这种情况还没考虑
        if(isClient) return;//情况一
        if(tmp->client->state != TCP_SYN_SENT || tmp->server->state != TCP_LISTEN || !(tcp_header->th_flags & TH_ACK))
            return;
        tmp->server->state = TCP_SYN_RECV;
        tmp->server->absolute_seq = ntohl(tcp_header->th_seq);
        tmp->server->absolute_ack = ntohl(tcp_header->th_ack);
        tmp->server->data = NULL;
        tmp->server->datalen = 0;
        
        return;
    }
    if(tcp_header->th_flags & TH_ACK) {//三次握手
        if(isClient && tmp->client->state == TCP_SYN_SENT && tmp->server->state == TCP_SYN_RECV) {
            if(ntohl(tcp_header->th_ack) == tmp->server->absolute_seq + 1) {
                tmp->client->state = tmp->server->state = TCP_ESTABLISHED; //修改状态
                if(app_data_len <= 0)return;
                //tmp->client->data = (u_char *)malloc(app_data_len);
                //memcpy(tmp->client->data, data + tcp_len, app_data_len);
                //tmp->client->datalen += app_data_len;
                //return;
            }
        }       
    }
    if(tcp_header->th_flags & TH_RST) {//RST包直接不处理
        return;
    }
    //处理数据部分
    if(app_data_len <= 0)return;
    if(isClient) {//客户端为发送方,服务端为接收方
        tcp_queue(tmp->server, tmp->client->absolute_seq + 1, tcp_header, data, app_data_len);
    }
    else //服务端为发送方,客户端为接收方
        tcp_queue(tmp->client, tmp->server->absolute_seq + 1, tcp_header, data, app_data_len);
    
    return;
}
