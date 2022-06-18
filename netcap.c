#include "netcap.h"
#include "ansi.h"
#include "smon.h"

void intHandler(int dummy) { run = 0; }

int main(int argc, char *const argv[])
{
    int socket, opt;
    char *iface = calloc(1, sizeof(char));
    uint8_t verbose = 0;
    while ((opt = getopt(argc, argv, "i:v")) != -1)
    {
        switch (opt)
        {
        case 'i':;
            uint16_t str_len = MIN(strlen(optarg), IF_NAMESIZE);
            iface = malloc(str_len);
            strncpy(iface, optarg, str_len);
            break;
        case 'v':;
            verbose = 1;
            break;
        default:
            break;
        }
    }

    if ((socket = create_socket(iface)) < 0)
        exit(errno);
    smon _smon = new_smon();
    _smon.socket = socket;
    _smon.verbose = verbose;
    _smon.icmp = 0;
    _smon.igmp = 0;
    _smon.tcp = 0;
    _smon.udp = 0;
    _smon.unknown = 0;
    smon *Smon = &_smon;

    if (verbose)
        ansi_clear();
    signal(SIGINT, intHandler);
    while (run)
    {
        if (loop(Smon) != 0)
            break;

        if (verbose)
        {
            ansi_save();
            ansi_goto(0, 0);
        }
        printf("\rICMP: %d IGMP: %d, TCP: %d, UDP: %d, Unknown: %d", Smon->icmp, Smon->igmp, Smon->tcp, Smon->udp, Smon->unknown);
        if (verbose)
            ansi_restore();
        else
            fflush(stdout);
    }

    printf("\nCleaning up...\n");
    free(Smon->src_buf);
    free(Smon->dst_buf);
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
