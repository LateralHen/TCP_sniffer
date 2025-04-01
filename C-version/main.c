#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#define __FAVOR_BSD
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define BUFFER_SIZE 65536

int main() {
    int sock_raw;
    struct sockaddr_in source, dest;
    unsigned char *buffer = (unsigned char *)malloc(BUFFER_SIZE);

    if (!buffer) {
        perror("malloc");
        return 1;
    }

    // Crea una socket raw per il protocollo IP
    sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock_raw < 0) {
        perror("Socket");
        return 1;
    }

    printf("Sniffer avviato...\n");

    while (1) {
        socklen_t saddr_size = sizeof(struct sockaddr);
        int data_size = recvfrom(sock_raw, buffer, BUFFER_SIZE, 0, NULL, NULL);
        if (data_size < 0) {
            perror("recvfrom");
            break;
        }

        struct iphdr *ip = (struct iphdr*)buffer;
        if (ip->protocol != IPPROTO_TCP) continue; // solo TCP

        struct sockaddr_in src, dst;
        memset(&src, 0, sizeof(src));
        memset(&dst, 0, sizeof(dst));
        src.sin_addr.s_addr = ip->saddr;
        dst.sin_addr.s_addr = ip->daddr;

        struct tcphdr *tcp = (struct tcphdr*)(buffer + ip->ihl * 4);

        printf("\n[TCP] %s:%d --> %s:%d\n",
               inet_ntoa(src.sin_addr),
               ntohs(tcp->source),
               inet_ntoa(dst.sin_addr),
               ntohs(tcp->dest));
    }

    close(sock_raw);
    free(buffer);
    return 0;
}
