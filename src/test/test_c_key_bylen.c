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
#include "test_c_key_bylen.h"

void
test_key_bylen_good(void)
{
    uint8_t addr[MAX_BINKEY];

    // ipv4 masks

    if (key_bylen(addr, 0, AF_INET)) {
        mu_true(*(addr+0) == 0x05);  // length byte
        mu_true(*(addr+1) == 0x00);  // 0
        mu_true(*(addr+2) == 0x00);  // 0
        mu_true(*(addr+3) == 0x00);  // 0
        mu_true(*(addr+4) == 0x00);  // 0
    }

    if (key_bylen(addr, 1, AF_INET)) {
        mu_true(*(addr+0) == 0x05);  // length byte
        mu_true(*(addr+1) == 0x80);  // 128
        mu_true(*(addr+2) == 0x00);  // 0
        mu_true(*(addr+3) == 0x00);  // 0
        mu_true(*(addr+4) == 0x00);  // 0
    }

    if (key_bylen(addr, 9, AF_INET)) {
        mu_true(*(addr+0) == 0x05);  // length byte
        mu_true(*(addr+1) == 0xff);  // 255
        mu_true(*(addr+2) == 0x80);  // 128
        mu_true(*(addr+3) == 0x00);  // 0
        mu_true(*(addr+4) == 0x00);  // 0
    }

    if (key_bylen(addr, 24, AF_INET)) {
        mu_true(*(addr+0) == 0x05);  // length byte
        mu_true(*(addr+1) == 0xff);  // 255
        mu_true(*(addr+2) == 0xff);  // 255
        mu_true(*(addr+3) == 0xff);  // 255
        mu_true(*(addr+4) == 0x00);  //   0
    }

    if (key_bylen(addr, 30, AF_INET)) {
        mu_true(*(addr+0) == 0x05);  // length byte
        mu_true(*(addr+1) == 0xff);  // 255
        mu_true(*(addr+2) == 0xff);  // 255
        mu_true(*(addr+3) == 0xff);  // 255
        mu_true(*(addr+4) == 0xfc);  // 252
    }

    if (key_bylen(addr, 31, AF_INET)) {
        mu_true(*(addr+0) == 0x05);  // length byte
        mu_true(*(addr+1) == 0xff);  // 255
        mu_true(*(addr+2) == 0xff);  // 255
        mu_true(*(addr+3) == 0xff);  // 255
        mu_true(*(addr+4) == 0xfe);  // 254
    }

    if (key_bylen(addr, 32, AF_INET)) {
        mu_true(*(addr+0) == 0x05);  // length byte
        mu_true(*(addr+1) == 0xff);  // 255
        mu_true(*(addr+2) == 0xff);  // 255
        mu_true(*(addr+3) == 0xff);  // 255
        mu_true(*(addr+4) == 0xff);  // 255
    }
}

void
test_key_bylen_bad(void)
{
    uint8_t buf[MAX_BINKEY];
    uint8_t *addr;

    // invalid ipv4 masks

    addr = key_bylen(buf, -32, AF_INET);
    mu_true(addr == NULL);

    addr = key_bylen(buf, 33, AF_INET);
    mu_true(addr == NULL);

    addr = key_bylen(buf, 64, AF_INET);
    mu_true(addr == NULL);

    // invalid ipv6 masks

    addr = key_bylen(buf, -128, AF_INET6);
    mu_true(addr == NULL);

    addr = key_bylen(buf, 129, AF_INET6);
    mu_true(addr == NULL);

    addr = key_bylen(buf, 256, AF_INET6);
    mu_true(addr == NULL);
}
