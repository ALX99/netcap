#include "smon.h"

smon new_smon()
{
    smon _smon;
    _smon.src_buf = malloc(sizeof(struct in_addr));
    _smon.dst_buf = malloc(sizeof(struct in_addr));
    return _smon;
}

int loop(smon *smon)
{
    unsigned char *buffer = malloc(BUF_SIZE);
    char *prot;
    uint32_t data_size;

    data_size = recvfrom(smon->socket, buffer, BUF_SIZE, 0, NULL, NULL);

    /* Check to see if the packet contains at least
     * complete Ethernet (14), IP (20) and TCP/UDP
     * (8) headers.
     */
    if (data_size < 42)
    {
        perror("recvfrom():");
        printf("Incomplete packet (errno is %d)\n", errno);
        return 1;
    }

    // +14 due to the 802.3 Ethernet frame
    struct iphdr *iph = (struct iphdr *)(buffer + 14);
    switch (iph->protocol)
    {
    case 1:
        prot = "ICMP";
        smon->icmp++;
        break;
    case 2:
        prot = "IGMP";
        smon->igmp++;
        break;
    case 6:
        prot = "TCP";
        smon->tcp++;
        break;
    case 17:
        prot = "UDP";
        smon->udp++;
        break;
    default:
        prot = "UKWN";
        smon->unknown++;
    }
    if (smon->verbose)
    {

        char *src, *dst;
        src = get_ip(smon->src_buf, iph->saddr),
        dst = get_ip(smon->dst_buf, iph->daddr);
        printf("%-4s %-15s -> %-15s\n", prot, smon->src_buf, smon->dst_buf);
    }
    return 0;
}

// inet_ntoa() is a non-reentrant function
char *get_ip(char *dest, unsigned int ip)
{
    struct in_addr in;
    in.s_addr = ip;
    return strcpy(dest, inet_ntoa(in));
}