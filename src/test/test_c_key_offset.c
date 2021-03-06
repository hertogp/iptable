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
#include "test_c_key_offset.h"      // a generated header file for this test runner

void
test_key_incr_ipv4(void)
{
    uint8_t addr[5] = {IP4_KEYLEN,0,0,0,0};

    // offset 0.0.0.0
    *(addr+1) = 0x00;
    *(addr+2) = 0x00;
    *(addr+3) = 0x00;
    *(addr+4) = 0x00;
    mu_true(key_incr(addr, 1));
    mu_eq(0x05, *(addr+0), "keylength %i");
    mu_eq(0x00, *(addr+1), "%i");
    mu_eq(0x00, *(addr+2), "%i");
    mu_eq(0x00, *(addr+3), "%i");
    mu_eq(0x01, *(addr+4), "%i");

    // offset 0.0.0.255 propagates
    *(addr+1) = 0x00;
    *(addr+2) = 0x00;
    *(addr+3) = 0x00;
    *(addr+4) = 0xff;
    mu_true(key_incr(addr, 1));
    mu_eq(0x05, *(addr+0), "keylength %i");
    mu_eq(0x00, *(addr+1), "%i");
    mu_eq(0x00, *(addr+2), "%i");
    mu_eq(0x01, *(addr+3), "%i");
    mu_eq(0x00, *(addr+4), "%i");

    // offset 0.0.255.255 propagates
    *(addr+1) = 0x00;
    *(addr+2) = 0x00;
    *(addr+3) = 0xff;
    *(addr+4) = 0xff;
    mu_true(key_incr(addr, 1));
    mu_eq(0x05, *(addr+0), "keylength %i");
    mu_eq(0x00, *(addr+1), "%i");
    mu_eq(0x01, *(addr+2), "%i");
    mu_eq(0x00, *(addr+3), "%i");
    mu_eq(0x00, *(addr+4), "%i");

    // offset 0.255.255.255 propagates
    *(addr+1) = 0x00;
    *(addr+2) = 0xff;
    *(addr+3) = 0xff;
    *(addr+4) = 0xff;
    mu_true(key_incr(addr, 1));
    mu_eq(0x05, *(addr+0), "keylength %i");
    mu_eq(0x01, *(addr+1), "%i");
    mu_eq(0x00, *(addr+2), "%i");
    mu_eq(0x00, *(addr+3), "%i");
    mu_eq(0x00, *(addr+4), "%i");

    // offset 255.255.255.255 -> wraps to 0.0.0.0 but yields NULL
    *(addr+1) = 0xff;
    *(addr+2) = 0xff;
    *(addr+3) = 0xff;
    *(addr+4) = 0xff;
    mu_false(key_incr(addr, 1));
    mu_eq(0x05, *(addr+0), "keylength %i");
    mu_eq(0x00, *(addr+1), "%i");
    mu_eq(0x00, *(addr+2), "%i");
    mu_eq(0x00, *(addr+3), "%i");
    mu_eq(0x00, *(addr+4), "%i");
}

void
test_key_decr(void)
{
    uint8_t addr[5] = {IP4_KEYLEN, 0,0,0,0};

    // offset 0.0.0.0 -> 255.255.255.255
    *(addr+1) = 0x00;
    *(addr+2) = 0x00;
    *(addr+3) = 0x00;
    *(addr+4) = 0x00;
    mu_false(key_decr(addr, 1));  /* wrap around detection */
    /* even though wrap around occurred, key is a known value */
    mu_eq(IP4_KEYLEN, *(addr+0), "keylength %i");
    mu_eq(0xff, *(addr+1), "%i");
    mu_eq(0xff, *(addr+2), "%i");
    mu_eq(0xff, *(addr+3), "%i");
    mu_eq(0xff, *(addr+4), "%i");

    // offset 255.0.0.0 -> 254.255.255.255
    *(addr+1) = 0xff;
    *(addr+2) = 0x00;
    *(addr+3) = 0x00;
    *(addr+4) = 0x00;
    mu_true(key_decr(addr, 1));
    mu_eq(IP4_KEYLEN, *(addr+0), "keylength %i");
    mu_eq(0xfe, *(addr+1), "%i");
    mu_eq(0xff, *(addr+2), "%i");
    mu_eq(0xff, *(addr+3), "%i");
    mu_eq(0xff, *(addr+4), "%i");

    // offset 255.255.0.0 -> 255.254.255.255
    *(addr+1) = 0xff;
    *(addr+2) = 0xff;
    *(addr+3) = 0x00;
    *(addr+4) = 0x00;
    mu_true(key_decr(addr, 1));
    mu_eq(IP4_KEYLEN, *(addr+0), "keylength %i");
    mu_eq(0xff, *(addr+1), "%i");
    mu_eq(0xfe, *(addr+2), "%i");
    mu_eq(0xff, *(addr+3), "%i");
    mu_eq(0xff, *(addr+4), "%i");

    // offset 255.255.255.0 -> 255.255.254.255
    *(addr+1) = 0xff;
    *(addr+2) = 0xff;
    *(addr+3) = 0xff;
    *(addr+4) = 0x00;
    mu_true(key_decr(addr, 1));
    mu_eq(IP4_KEYLEN, *(addr+0), "keylength %i");
    mu_eq(0xff, *(addr+1), "%i");
    mu_eq(0xff, *(addr+2), "%i");
    mu_eq(0xfe, *(addr+3), "%i");
    mu_eq(0xff, *(addr+4), "%i");

}
