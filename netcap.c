#include "netcap.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <linux/filter.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <signal.h>

#include <netinet/ip.h>

#define BUF_SIZE 65536
#define MIN(a, b) (((a) < (b)) ? (a) : (b))

static volatile uint8_t run = 1;

void intHandler(int dummy) { run = 0; }

int main(int argc, char *const *argv)
{
    int socket, opt;
    char *iface = calloc(1, sizeof(char));
    while ((opt = getopt(argc, argv, "i:")) != -1)
    {
        switch (opt)
        {
        case 'i':;
            uint16_t str_len = MIN(strlen(optarg), IF_NAMESIZE);
            iface = malloc(str_len);
            strncpy(iface, optarg, str_len);
            break;
        default:
            break;
        }
    }

    unsigned char *buffer = malloc(BUF_SIZE);

    if ((socket = create_socket(iface)) < 0)
        exit(errno);

    uint32_t data_size, icmp = 0, igmp = 0, tcp = 0, udp = 0, unknown = 0;
    signal(SIGINT, intHandler);
    while (run)
    {
        data_size = recvfrom(socket, buffer, BUF_SIZE, 0, NULL, NULL);

        /* Check to see if the packet contains at least
         * complete Ethernet (14), IP (20) and TCP/UDP
         * (8) headers.
         */
        if (data_size < 42)
        {
            perror("recvfrom():");
            printf("Incomplete packet (errno is %d)\n", errno);
            close(socket);
            exit(0);
        }

        // +14 due to the 802.3 Ethernet frame
        struct iphdr *iph = (struct iphdr *)(buffer + 14);
        switch (iph->protocol)
        {
        case 1:
            icmp++;
            break;
        case 2:
            igmp++;
            break;
        case 6:
            tcp++;
            break;
        case 17:
            udp++;
            break;
        default:
            unknown++;
            break;
        }
        printf("\rICMP: %d IGMP: %d, TCP: %d, UDP: %d, Unknown: %d", icmp, igmp, tcp, udp, unknown);
        fflush(stdout);
    }
    printf("\nCleaning up...\n");

    close(socket);

    return 0;
}

int create_socket(char const *iface)
{
    int sock;

    // AF_PACKET = address families packet
    // By using AF_PACKET we will get the raw Ethernet frame
    // which will bypass the TCP/IP stack
    // SOCK_RAW = raw network protocol access
    // It is here where the packet in sk_buff is cloned
    if ((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0)
    {
        perror("open socket");
        return -1;
    }

    // BPF filter for IP packets generate by: sudo tcpdump -dd ip
    struct sock_filter BPF_code[] = {
        {0x28, 0, 0, 0x0000000c},
        {0x15, 0, 1, 0x00000800},
        {0x6, 0, 0, 0x00040000},
        {0x6, 0, 0, 0x00000000},
    };

    struct sock_fprog Filter;
    Filter.len = sizeof(BPF_code) / sizeof(BPF_code[0]);
    Filter.filter = BPF_code;

    // Inject custom BPF filter into the kernel
    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &Filter, sizeof(Filter)) < 0)
    {
        perror("setsockopt attach filter");
        close(sock);
        return -1;
    }

    /* Return sice we don't want to bind the socket to a
    particular interface, and I'm not sure how I set up
    promiscuous mode without an interface name
    */
    if (strcmp(iface, "") == 0)
    {
        printf("Socket created listening on all interfaces\n");
        return sock;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, iface, strlen(iface)) < 0)
    {
        perror("setsockopt");
        close(sock);
        return -1;
    }

    // Configure the socket in promiscuous mode
    struct ifreq ethreq;
    strncpy(ethreq.ifr_name, iface, IF_NAMESIZE);
    if (ioctl(sock, SIOCGIFFLAGS, &ethreq) == -1) // Try to read the options
    {
        perror("ioctl");
        close(sock);
        exit(1);
    }

    ethreq.ifr_flags |= IFF_PROMISC;              // Add the promiscuous mode bit
    if (ioctl(sock, SIOCSIFFLAGS, &ethreq) == -1) // Try to set the options
    {
        perror("ioctl");
        close(sock);
        exit(1);
    }

    return sock;
}
