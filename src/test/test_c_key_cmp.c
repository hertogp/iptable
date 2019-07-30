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
#include "test_c_key_cmp.h"

void
test_key_cmp_ipv4_good(void)
{
    uint8_t *a = malloc(5*sizeof(uint8_t));
    uint8_t *b = malloc(5*sizeof(uint8_t));

    *a = *b = IP4_KEYLEN;

    // a == b
    *(a+1) = *(b+1) = 0xff;
    *(a+2) = *(b+2) = 0xff;
    *(a+3) = *(b+3) = 0xff;
    *(a+4) = *(b+4) = 0xff;
    mu_true(key_cmp(a, b) == 0);

    // a < b, thus b > a
    *(a+4) = 0xfe;
    mu_true(key_cmp(a, b) == -1);
    mu_true(key_cmp(b, a) == 1);

    // now ignore last byte
    *a = *b = IP4_KEYLEN - 1;
    mu_true(key_cmp(a, b) == 0);


    // a == b
    *(a+0) = *(b+0) = 0x05;
    *(a+1) = *(b+1) = 0x0a;
    *(a+2) = *(b+2) = 0x0b;
    *(a+3) = *(b+3) = 0x0c;
    *(a+4) = *(b+4) = 0x00;
    *(b+3) = 0x0d;

    mu_true(key_cmp(a, b) < 0);
    mu_true(key_cmp(b, a) > 0);

    free(a);
    free(b);
}

void
test_key_cmp_ipv4_bad(void)
{
    uint8_t *a = malloc(5*sizeof(uint8_t));
    uint8_t *b = malloc(5*sizeof(uint8_t));

    // init key memory
    *a = *b = IP4_KEYLEN;
    *(a+1) = *(b+1) = 0xff;
    *(a+2) = *(b+2) = 0xff;
    *(a+3) = *(b+3) = 0xff;
    *(a+4) = *(b+4) = 0xff;

    // different keylengths should yield error
    *a = IP4_KEYLEN-1;
    mu_true(key_cmp(a, b) == -2);

    // a NULL ptr also yields an error
    mu_true(key_cmp(a, NULL) == -2);
    mu_true(key_cmp(NULL, b) == -2);

    // two NULL ptrs also considered an error
    mu_true(key_cmp(NULL, NULL) == -2);

    free(a);
    free(b);
}
