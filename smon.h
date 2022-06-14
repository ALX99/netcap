#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/ip.h>

#define BUF_SIZE 65536

typedef struct
{
    int socket;
    uint32_t icmp;
    uint32_t igmp;
    uint32_t tcp;
    uint32_t udp;
    uint32_t unknown;
} smon;

int loop(smon *smon);