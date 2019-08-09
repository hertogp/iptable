#include <stdio.h>
#include <sys/types.h>       // required for u_char
#include <stddef.h>          // offsetof
#include <stdlib.h>          // malloc
#include <netinet/in.h>      // sockaddr_in
#include <arpa/inet.h>       // inet_pton and friends
#include <string.h>          // strlen
#include <ctype.h>           // isdigit

#include "radix.h"           // the radix tree
#include "iptable.h"         // iptable layered on top of radix.c

#include "minunit.h"         // the mu_test macros
#include "test_c_key_bynum.h"

#include <math.h>
void
test_key_bylen_good(void)
{
    uint8_t addr[MAX_BINKEY];

    if (key_bynum(addr, 1*pow(256,3) + 2*pow(256,2) + 4*256 + 8, AF_INET)) {
        mu_true(*(addr+0) == 0x05);  // length byte
        mu_true(*(addr+1) == 0x01);
        mu_true(*(addr+2) == 0x02);
        mu_true(*(addr+3) == 0x04);
        mu_true(*(addr+4) == 0x08);
    }

}
