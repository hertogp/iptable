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
#include "test_c_key_masked.h"

void
test_key_masked_ipv4_good(void)
{
    uint8_t *a = malloc(5*sizeof(uint8_t));
    uint8_t *m = malloc(5*sizeof(uint8_t));

    // init key memory
    *a = *m = 1 + IP4_KEYLEN;

    // mask last byte
    *(a+1) = *(m+1) = 0xff;
    *(a+2) = *(m+2) = 0xff;
    *(a+3) = *(m+3) = 0xff;
    *(a+4) = 0xff;
    *(m+4) = 0x00;
    mu_true(key_network(a, m));
    mu_eq(0xff, *(a+1), "%i");
    mu_eq(0xff, *(a+2), "%i");
    mu_eq(0xff, *(a+3), "%i");
    mu_eq(0x00, *(a+4), "%i");

    // now mask first byte
    *(a+1) = 0xff;
    *(a+2) = 0xff;
    *(a+3) = 0xff;
    *(a+4) = 0xff;
    *(m+1) = 0x00;
    *(m+2) = 0xff;
    *(m+3) = 0xff;
    *(m+4) = 0xff;
    mu_true(key_network(a, m));
    mu_eq(0x00, *(a+1), "%i");
    mu_eq(0xff, *(a+2), "%i");
    mu_eq(0xff, *(a+3), "%i");
    mu_eq(0xff, *(a+4), "%i");

    // now mask 2nd byte
    *(a+1) = 0xff;
    *(a+2) = 0xff;
    *(a+3) = 0xff;
    *(a+4) = 0xff;
    *(m+1) = 0xff;
    *(m+2) = 0x00;
    *(m+3) = 0xff;
    *(m+4) = 0xff;
    mu_true(key_network(a, m));
    mu_eq(0xff, *(a+1), "%i");
    mu_eq(0x00, *(a+2), "%i");
    mu_eq(0xff, *(a+3), "%i");
    mu_eq(0xff, *(a+4), "%i");


    // zeros across byes
    *(a+1) = 0xff;
    *(a+2) = 0xff;
    *(a+3) = 0xff;
    *(a+4) = 0xff;
    *(m+1) = 0xff;
    *(m+2) = 0xf0;
    *(m+3) = 0x0f;
    *(m+4) = 0xff;
    mu_true(key_network(a, m));
    mu_eq(0xff, *(a+1), "%i");
    mu_eq(0xf0, *(a+2), "%i");
    mu_eq(0x0f, *(a+3), "%i");
    mu_eq(0xff, *(a+4), "%i");

    // shorter mask implies zeros for 'missing' mask bits
    *m = 3;        // only uses first 2 mask bytes
    *(a+1) = 0xff;
    *(a+2) = 0xff;
    *(a+3) = 0xff;
    *(a+4) = 0xff;
    *(m+1) = 0xff;
    *(m+2) = 0xff;
    *(m+3) = 0xff;  // not used, will be assumed zero's
    *(m+4) = 0xff;  // dito
    mu_true(key_network(a, m));
    mu_eq(0xff, *(a+1), "%i");
    mu_eq(0xff, *(a+2), "%i");
    mu_eq(0x00, *(a+3), "%i");
    mu_eq(0x00, *(a+4), "%i");

    free(a);
    free(m);
}

