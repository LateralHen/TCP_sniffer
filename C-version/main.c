#define _GNU_SOURCE
#define __FAVOR_BSD

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <sys/select.h>
#include <errno.h>
#include <time.h>
#include <netdb.h>

#define BUFFER_SIZE 65536
#define PAYLOAD_PREVIEW 32
#define LOG_CAPACITY 1024

int sock_raw;
int running = 1;
unsigned short filter_port = 0;
char *filter_ip_src = NULL;
char *filter_ip_dst = NULL;

// Struttura per loggare i pacchetti
typedef struct {
    char timestamp[64];
    char src_ip[INET_ADDRSTRLEN];
    char src_hostname[NI_MAXHOST];
    unsigned short src_port;
    char dst_ip[INET_ADDRSTRLEN];
    char dst_hostname[NI_MAXHOST];
    unsigned short dst_port;
    char payload_hex[PAYLOAD_PREVIEW * 2 + 1];
} log_entry;

log_entry *log_entries = NULL;
size_t log_count = 0;
size_t log_capacity = 0;

// Gestione Ctrl+C
void handle_interrupt(int sig) {
    (void)sig;
    running = 0;
}

// Converte buffer binario in stringa esadecimale
void to_hex(const unsigned char *data, int len, char *output) {
    for (int i = 0; i < len; i++) {
        sprintf(output + (i * 2), "%02x", data[i]);
    }
    output[len * 2] = '\0';
}

// Ottiene orario corrente formattato
void get_time_string(char *buffer, size_t size, const char *fmt) {
    time_t rawtime = time(NULL);
    struct tm *tm_info = localtime(&rawtime);
    strftime(buffer, size, fmt, tm_info);
}

// Risolve l'hostname da IP
void resolve_hostname(char *ip, char *hostbuffer, size_t hostbuffer_len) {
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &sa.sin_addr);
    if (getnameinfo((struct sockaddr*)&sa, sizeof(sa), hostbuffer, hostbuffer_len, NULL, 0, 0) != 0) {
        strncpy(hostbuffer, "?", hostbuffer_len);
    }
}

// Aggiunge un pacchetto al log
void add_to_log(log_entry entry) {
    if (log_count >= log_capacity) {
        log_capacity = log_capacity == 0 ? LOG_CAPACITY : log_capacity * 2;
        log_entries = realloc(log_entries, log_capacity * sizeof(log_entry));
        if (!log_entries) {
            perror("realloc");
            exit(1);
        }
    }
    log_entries[log_count++] = entry;
}

// Chiede se salvare e scrive CSV
void ask_to_save_log() {
    if (log_count == 0) {
        printf("Nessun pacchetto da salvare.\n");
        return;
    }
    char choice = 0;
    printf("\nVuoi salvare i risultati in 'log.csv'? (y/n): ");
    fflush(stdout);
    if (read(STDIN_FILENO, &choice, 1) != 1) return;

    if (choice == 'y' || choice == 'Y') {
        FILE *f = fopen("log.csv", "w");
        if (!f) {
            perror("fopen");
            return;
        }
        fprintf(f, "timestamp,src_ip,src_hostname,src_port,dst_ip,dst_hostname,dst_port,payload_hex\n");
        for (size_t i = 0; i < log_count; i++) {
            log_entry *e = &log_entries[i];
            fprintf(f, "%s,%s,%s,%d,%s,%s,%d,%s\n",
                e->timestamp, e->src_ip, e->src_hostname, e->src_port,
                e->dst_ip, e->dst_hostname, e->dst_port, e->payload_hex);
        }
        fclose(f);
        printf("Log salvato in 'log.csv'\n");
    } else {
        printf("Log scartato.\n");
    }
    free(log_entries);
}

int main(int argc, char *argv[]) {
    int opt;
    while ((opt = getopt(argc, argv, "p:s:d:")) != -1) {
        switch (opt) {
            case 'p': filter_port = atoi(optarg); break;
            case 's': filter_ip_src = strdup(optarg); break;
            case 'd': filter_ip_dst = strdup(optarg); break;
            default:
                fprintf(stderr, "Uso: %s [-p porta] [-s ip_sorgente] [-d ip_dest] \n", argv[0]);
                exit(1);
        }
    }

    if (getuid() != 0) {
        fprintf(stderr, "Devi eseguire questo programma come root (usa sudo)\n");
        exit(1);
    }

    signal(SIGINT, handle_interrupt);

    unsigned char *buffer = malloc(BUFFER_SIZE);
    if (!buffer) exit(1);

    sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock_raw < 0) {
        perror("socket");
        exit(1);
    }

    while (running) {
        fd_set read_fds;
        struct timeval timeout;
        FD_ZERO(&read_fds);
        FD_SET(sock_raw, &read_fds);
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        int sel = select(sock_raw + 1, &read_fds, NULL, NULL, &timeout);
        if (sel < 0) {
            if (errno == EINTR) continue;
            perror("select");
            break;
        }
        if (sel == 0) continue;

        int data_size = recvfrom(sock_raw, buffer, BUFFER_SIZE, 0, NULL, NULL);
        if (data_size < 0) continue;

        struct iphdr *ip = (struct iphdr*)buffer;
        if (ip->protocol != IPPROTO_TCP) continue;

        struct sockaddr_in src, dst;
        src.sin_addr.s_addr = ip->saddr;
        dst.sin_addr.s_addr = ip->daddr;

        struct tcphdr *tcp = (struct tcphdr*)(buffer + ip->ihl * 4);
        unsigned short src_port = ntohs(tcp->source);
        unsigned short dst_port = ntohs(tcp->dest);

        char *src_ip = inet_ntoa(src.sin_addr);
        char *dst_ip = inet_ntoa(dst.sin_addr);

        // Applica filtri IP e porta
        if (filter_ip_src && strcmp(src_ip, filter_ip_src) != 0) continue;
        if (filter_ip_dst && strcmp(dst_ip, filter_ip_dst) != 0) continue;
        if (filter_port && src_port != filter_port && dst_port != filter_port) continue;

        // Costruisci l'entry
        log_entry entry;
        get_time_string(entry.timestamp, sizeof(entry.timestamp), "%Y-%m-%d %H:%M:%S");
        strncpy(entry.src_ip, src_ip, sizeof(entry.src_ip));
        strncpy(entry.dst_ip, dst_ip, sizeof(entry.dst_ip));
        entry.src_port = src_port;
        entry.dst_port = dst_port;
        resolve_hostname(src_ip, entry.src_hostname, sizeof(entry.src_hostname));
        resolve_hostname(dst_ip, entry.dst_hostname, sizeof(entry.dst_hostname));

        int iphdr_len = ip->ihl * 4;
        int tcphdr_len = tcp->doff * 4;
        int payload_offset = iphdr_len + tcphdr_len;
        int payload_len = data_size - payload_offset;
        to_hex(buffer + payload_offset, payload_len > PAYLOAD_PREVIEW ? PAYLOAD_PREVIEW : payload_len, entry.payload_hex);

        add_to_log(entry);

        // Output formattato
        char time_str[16];
        get_time_string(time_str, sizeof(time_str), "%H:%M:%S");
        printf("%s %s (%s):%d --> %s (%s):%d [TCP]\n",
               time_str,
               src_ip, entry.src_hostname, src_port,
               dst_ip, entry.dst_hostname, dst_port);
    }

    close(sock_raw);
    free(buffer);
    ask_to_save_log();
    free(filter_ip_src);
    free(filter_ip_dst);
    return 0;
}
