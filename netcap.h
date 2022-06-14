#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/filter.h>
#include <arpa/inet.h>

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

static volatile uint8_t run = 1;

int create_socket(char const *iface);