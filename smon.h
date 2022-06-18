#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/ip.h>
#include <arpa/inet.h>

#define BUF_SIZE 65536

typedef struct
{
    int socket;
    uint8_t verbose;
    uint32_t icmp;
    uint32_t igmp;
    uint32_t tcp;
    uint32_t udp;
    uint32_t unknown;

    char* src_buf;
    char* dst_buf;
} smon;

smon new_smon();
int loop(smon *smon);
char *get_ip(char *dest, unsigned int ip);