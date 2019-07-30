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
#include "test_c_key_copy.h"

void
test_key_copy_good(void)
{
    uint8_t src[MAX_BINKEY], *key;

    // all zero bytes
    *(src+0) = 0x05;
    *(src+1) = 0x00;
    *(src+2) = 0x00;
    *(src+3) = 0x00;
    *(src+4) = 0x00;
    key = key_copy(src);
    for (int i=0; i < 5; i++)
        mu_eq(*(src+i), *(key+i), "%d");
    free(key);

    // all one bytes
    *(src+0) = 0x05;
    *(src+1) = 0xff;
    *(src+2) = 0xff;
    *(src+3) = 0xff;
    *(src+4) = 0xff;
    key = key_copy(src);
    for (int i=0; i < 5; i++)
        mu_eq(*(src+i), *(key+i), "%d");
    free(key);

    // mixed one/zero bytes
    *(src+0) = 0x05;
    *(src+1) = 0xff;
    *(src+2) = 0x00;
    *(src+3) = 0x00;
    *(src+4) = 0xff;
    key = key_copy(src);
    for (int i=0; i < 5; i++)
        mu_eq(*(src+i), *(key+i), "%d");
    free(key);

    // some random bytes
    *(src+0) = 0x05;
    *(src+1) = 0x01;
    *(src+2) = 0x12;
    *(src+3) = 0x00;
    *(src+4) = 0xf3;
    key = key_copy(src);
    for (int i=0; i < 5; i++)
        mu_eq(*(src+i), *(key+i), "%d");
    free(key);

    // some random bytes - ipv6
    IPT_KEYLEN(src) = IP6_KEYLEN;
    for(int i=0; i < MAX_BINKEY; i++)
        *(src+i) = 0x00;

    *(src+0) = 0x11;  // LEN is 17
    *(src+4) = 0xf3;
    *(src+9) = 0xe0;
    *(src+16) = 0x01;
    key = key_copy(src);
    for (int i=0; i < IPT_KEYLEN(src); i++)
        mu_eq(*(src+i), *(key+i), "%d");
    free(key);
}

void
test_key_copy_bad(void)
{
    uint8_t src[MAX_BINKEY], *key;

    // bad LEN's
    *(src+0) = 0x00;
    key = key_copy(src);
    mu_true(key == NULL);
    if (key) free(key);

    *(src+0) = 0x04;
    key = key_copy(src);
    mu_true(key == NULL);
    if (key) free(key);

    *(src+0) = 0xff;
    key = key_copy(src);
    mu_true(key == NULL);
    if (key) free(key);
}
