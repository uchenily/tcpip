/* raw_ping.c */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

// 校验和
unsigned short checksum(unsigned short* buf, int bufsz)
{
    unsigned long sum = 0xffff;

    while (bufsz > 1) {
        sum += *buf;
        buf++;
        bufsz -= 2;
    }

    // unsigned short 转为 unsigned char
    if (bufsz == 1)
        sum += *(unsigned char*)buf;

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}

int main(int argc, char* argv[])
{
    int sockfd;

    // 定义在 netinet/ip_icmp.h
    struct icmphdr hdr;

    struct sockaddr_in addr, src_addr;
    int n;

    char buf[2000];
    struct icmphdr* icmphdrptr;
    struct iphdr* iphdrptr;

    if (argc != 2) {
        printf("usage : %s IPADDR\n", argv[0]);
        return 1;
    }

    addr.sin_family = PF_INET; //IPv4
    //inet_pton() 可以把 点分十进制记法的ip 转为 network order 的形式
    n = inet_pton(PF_INET, argv[1], &addr.sin_addr);
    if (n < 0) {
        perror("inet_pton");
        return -1;
    }

    // 建立 RAW socket
    sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    //先清空 hdr(也可以不清零)
    memset(&hdr, 0, sizeof(hdr));

    // 设置 ICMP Header
    hdr.type = ICMP_ECHO;
    hdr.code = 0;
    hdr.checksum = 0;
    hdr.un.echo.id = 0;
    hdr.un.echo.sequence = 0;

    // 计算 ICMP Header 的 checksum
    hdr.checksum = checksum((unsigned short*)&hdr, sizeof(hdr));

    // 发送只有 ICMP Header 的 ICMP 封包
    n = sendto(sockfd, (char*)&hdr, sizeof(hdr), 0, (struct sockaddr*)&addr, sizeof(addr));
    if (n < 1) {
        perror("sendto");
        return -1;
    }

    // 接著當然要來接收 ICMP ECHO REPLY

    // 清空 buffer (也可以不清零)
    memset(buf, 0, sizeof(buf));

    // 接收來自对方主机的 ICMP ECHO REPLY
    // 如果是127.0.0.1, 那么这次的接收的echo request, 其他的情况为echo reply
    int src_addr_len = sizeof(src_addr);
    n = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr*)&src_addr, &src_addr_len);
    if (n < 1) {
        perror("recvfrom");
        return -1;
    }

    // 从接收到的数据中取出 IP Header 的部分
    iphdrptr = (struct iphdr*)buf;

    // 从接收到的数据中取出 ICMP Header 的部分
    icmphdrptr = (struct icmphdr*)(buf + (iphdrptr->ihl) * 4);

    printf("icmphdrptr->type: %d\n", icmphdrptr->type);
    if (icmphdrptr->type != 0) {
        if (icmphdrptr->type == 3) {
            printf("received ICMP %d, and the code is %d\n", icmphdrptr->type, icmphdrptr->code);
        }
        else {
            printf("received ICMP %d\n", icmphdrptr->type);
            printf("The host %s is alive\n", argv[1]);
        }
    }

    close(sockfd);
    return 0;
}

/*
 注意这里的拆ip包, icmp包的处理逻辑:

// 从接收到的数据中取出 IP Header 的部分
iphdrptr = (struct iphdr*)buf;

// 从接收到的数据中取出 ICMP Header 的部分
icmphdrptr = (struct icmphdr*)(buf + (iphdrptr->ihl) * 4);
*/
