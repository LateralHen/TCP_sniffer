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
#include <time.h>  // ⏱️ per i timestamp

#define BUFFER_SIZE 65536
#define LOG_CAPACITY 1024

int sock_raw;
unsigned short filter_port = 0;
int running = 1;

// Timestamp globali
char start_timestamp[64];
char end_timestamp[64];

// Struttura per rappresentare ogni pacchetto da loggare
typedef struct {
    char src_ip[INET_ADDRSTRLEN];
    unsigned short src_port;
    char dst_ip[INET_ADDRSTRLEN];
    unsigned short dst_port;
} log_entry;

log_entry *log_entries = NULL;
size_t log_count = 0;
size_t log_capacity = 0;

// Funzione per ottenere un timestamp leggibile
void get_formatted_time(char *buffer, size_t size) {
    time_t rawtime = time(NULL);
    struct tm *timeinfo = localtime(&rawtime);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", timeinfo);
}

// Gestore di Ctrl+C
void handle_interrupt(int sig) {
    (void)sig;
    running = 0;
    get_formatted_time(end_timestamp, sizeof(end_timestamp));  // salva orario di stop
}

// Chiede se salvare il log in CSV, includendo i timestamp
void ask_to_save_log() {
    if (log_count == 0) {
        printf("Nessun pacchetto da salvare.\n");
        return;
    }

    char choice = 0;
    printf("\nVuoi salvare i risultati in 'log.csv'? (y/n): ");
    fflush(stdout);
    if (read(STDIN_FILENO, &choice, 1) != 1) {
        perror("Errore nella lettura dell'input");
        return;
    }

    if (choice == 'y' || choice == 'Y') {
        FILE *f = fopen("log.csv", "w");
        if (!f) {
            perror("Errore apertura file");
            return;
        }

        // Commenti CSV con i timestamp
        fprintf(f, "# Sniffer avviato: %s\n", start_timestamp);
        fprintf(f, "# Sniffer terminato: %s\n", end_timestamp);
        fprintf(f, "src_ip,src_port,dst_ip,dst_port\n");

        for (size_t i = 0; i < log_count; i++) {
            fprintf(f, "%s,%d,%s,%d\n",
                    log_entries[i].src_ip, log_entries[i].src_port,
                    log_entries[i].dst_ip, log_entries[i].dst_port);
        }

        fclose(f);
        printf("Log salvato in 'log.csv'\n");
    } else {
        printf("Log scartato.\n");
    }

    free(log_entries); // pulizia memoria
}

// Aggiunge una entry al log
void add_to_log(const char *src_ip, unsigned short src_port,
                const char *dst_ip, unsigned short dst_port) {
    if (log_count >= log_capacity) {
        log_capacity = log_capacity == 0 ? LOG_CAPACITY : log_capacity * 2;
        log_entries = realloc(log_entries, log_capacity * sizeof(log_entry));
        if (!log_entries) {
            perror("Errore realloc");
            exit(1);
        }
    }

    strncpy(log_entries[log_count].src_ip, src_ip, INET_ADDRSTRLEN);
    log_entries[log_count].src_port = src_port;
    strncpy(log_entries[log_count].dst_ip, dst_ip, INET_ADDRSTRLEN);
    log_entries[log_count].dst_port = dst_port;
    log_count++;
}

int main(int argc, char *argv[]) {
    // Parsing opzione -p <porta>
    int opt;
    while ((opt = getopt(argc, argv, "p:")) != -1) {
        switch (opt) {
            case 'p':
                filter_port = atoi(optarg);
                break;
            default:
                fprintf(stderr, "Uso: %s [-p porta]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    // Verifica permessi root
    if (getuid() != 0) {
        fprintf(stderr, "❌ Devi eseguire questo programma come root (usa sudo)\n");
        exit(1);
    }

    // Salva timestamp di avvio
    get_formatted_time(start_timestamp, sizeof(start_timestamp));
    printf("🟢 Sniffer avviato: %s\n", start_timestamp);

    signal(SIGINT, handle_interrupt);  // gestore Ctrl+C

    unsigned char *buffer = malloc(BUFFER_SIZE);
    if (!buffer) {
        perror("malloc");
        return 1;
    }

    sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock_raw < 0) {
        perror("Socket");
        return 1;
    }

    printf("🔍 Monitoraggio %s...\n",
           filter_port ? "su porta selezionata" : "su tutte le porte");

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
        if (data_size < 0) {
            if (errno == EINTR) continue;
            perror("recvfrom");
            break;
        }

        struct iphdr *ip = (struct iphdr *)buffer;
        if (ip->protocol != IPPROTO_TCP) continue;

        struct sockaddr_in src, dst;
        src.sin_addr.s_addr = ip->saddr;
        dst.sin_addr.s_addr = ip->daddr;

        struct tcphdr *tcp = (struct tcphdr *)(buffer + ip->ihl * 4);
        unsigned short src_port = ntohs(tcp->source);
        unsigned short dst_port = ntohs(tcp->dest);

        if (filter_port != 0 && src_port != filter_port && dst_port != filter_port) {
            continue;
        }

        printf("[TCP] %s:%d --> %s:%d\n",
               inet_ntoa(src.sin_addr), src_port,
               inet_ntoa(dst.sin_addr), dst_port);

        add_to_log(inet_ntoa(src.sin_addr), src_port,
                   inet_ntoa(dst.sin_addr), dst_port);
    }

    // Mostra orario di fine anche su terminale
    printf("🛑 Sniffer terminato: %s\n", end_timestamp);

    close(sock_raw);
    free(buffer);
    ask_to_save_log();

    return 0;
}
