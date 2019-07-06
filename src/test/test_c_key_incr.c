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
#include "test_c_key_incr.h"      // a generated header file for this test runner

void
test_key_incr_ipv4_good(void)
{
    uint8_t *addr = malloc(5 * sizeof(uint8_t));

    *addr = IP4_KEYLEN + 1;  // i.e. 5

    // incr 0.0.0.0
    *(addr+1) = 0x00;
    *(addr+2) = 0x00;
    *(addr+3) = 0x00;
    *(addr+4) = 0x00;
    mu_true(key_incr(addr));
    mu_eq(0x01, *(addr+4), "%i");

    // incr 0.0.0.255 propagates
    *(addr+1) = 0x00;
    *(addr+2) = 0x00;
    *(addr+3) = 0x00;
    *(addr+4) = 0xff;
    mu_true(key_incr(addr));
    mu_eq(0x00, *(addr+1), "%i");
    mu_eq(0x00, *(addr+2), "%i");
    mu_eq(0x01, *(addr+3), "%i");
    mu_eq(0x00, *(addr+4), "%i");

    // incr 0.0.255.255 propagates
    *(addr+1) = 0x00;
    *(addr+2) = 0x00;
    *(addr+3) = 0xff;
    *(addr+4) = 0xff;
    mu_true(key_incr(addr));
    mu_eq(0x00, *(addr+1), "%i");
    mu_eq(0x01, *(addr+2), "%i");
    mu_eq(0x00, *(addr+3), "%i");
    mu_eq(0x00, *(addr+4), "%i");

    // incr 0.255.255.255 propagates
    *(addr+1) = 0x00;
    *(addr+2) = 0xff;
    *(addr+3) = 0xff;
    *(addr+4) = 0xff;
    mu_true(key_incr(addr));
    mu_eq(0x01, *(addr+1), "%i");
    mu_eq(0x00, *(addr+2), "%i");
    mu_eq(0x00, *(addr+3), "%i");
    mu_eq(0x00, *(addr+4), "%i");

    // incr 255.255.255.255 -> wraps to 0.0.0.0
    *(addr+1) = 0xff;
    *(addr+2) = 0xff;
    *(addr+3) = 0xff;
    *(addr+4) = 0xff;
    mu_true(key_incr(addr));
    mu_eq(0x00, *(addr+1), "%i");
    mu_eq(0x00, *(addr+2), "%i");
    mu_eq(0x00, *(addr+3), "%i");
    mu_eq(0x00, *(addr+4), "%i");

    free(addr);
}
