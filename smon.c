#include "smon.h"

int loop(smon *smon)
{
    unsigned char *buffer = malloc(BUF_SIZE);
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
        smon->icmp++;
        break;
    case 2:
        smon->igmp++;
        break;
    case 6:
        smon->tcp++;
        break;
    case 17:
        smon->udp++;
        break;
    default:
        smon->unknown++;
    }
    return 0;
}