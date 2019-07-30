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
#include "test_c_key_decr.h"

void
test_key_decr_ipv4_good(void)
{
    uint8_t *addr = malloc(5 * sizeof(uint8_t));

    *addr = IP4_KEYLEN;  // set LEN byte to length of byte array

    // decr 0.0.0.0 should wrap around
    *(addr+1) = 0x00;
    *(addr+2) = 0x00;
    *(addr+3) = 0x00;
    *(addr+4) = 0x00;
    mu_true(key_decr(addr));
    mu_eq(0xff, *(addr+1), "%i");
    mu_eq(0xff, *(addr+2), "%i");
    mu_eq(0xff, *(addr+3), "%i");
    mu_eq(0xff, *(addr+4), "%i");

    // decr 255.0.0.0 -> 254.255.255.255
    *(addr+1) = 0xff;
    *(addr+2) = 0x00;
    *(addr+3) = 0x00;
    *(addr+4) = 0x00;
    mu_true(key_decr(addr));
    mu_eq(0xfe, *(addr+1), "%i");
    mu_eq(0xff, *(addr+2), "%i");
    mu_eq(0xff, *(addr+3), "%i");
    mu_eq(0xff, *(addr+4), "%i");

    // decr 255.255.0.0 -> 255.254.255.255
    *(addr+1) = 0xff;
    *(addr+2) = 0xff;
    *(addr+3) = 0x00;
    *(addr+4) = 0x00;
    mu_true(key_decr(addr));
    mu_eq(0xff, *(addr+1), "%i");
    mu_eq(0xfe, *(addr+2), "%i");
    mu_eq(0xff, *(addr+3), "%i");
    mu_eq(0xff, *(addr+4), "%i");

    // decr 255.255.255.0 -> 255.255.254.255
    *(addr+1) = 0xff;
    *(addr+2) = 0xff;
    *(addr+3) = 0xff;
    *(addr+4) = 0x00;
    mu_true(key_decr(addr));
    mu_eq(0xff, *(addr+1), "%i");
    mu_eq(0xff, *(addr+2), "%i");
    mu_eq(0xfe, *(addr+3), "%i");
    mu_eq(0xff, *(addr+4), "%i");

    free(addr);
}
