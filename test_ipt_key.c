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
#include "test_ipt_key_mu.h"   // a generated header file for this test runner

// helpers
char *mk_strptr(const char *);
char *mk_strptr(const char *s)
{
    char *sp = NULL;
    if (s==NULL) return NULL;

    int max = strlen(s);
    sp = malloc(1 + max * sizeof(char));
    strncpy(sp, s, max);
    sp[max] = '\0';
    return sp;  // caller must free(sp)
}

void
test_key_bystr_good(void)
{
    uint8_t *addr;
    char * str;
    int mlen = -2;

    // ipv4 with mask
    str = mk_strptr("10.10.10.0/24");
    addr = key_bystr(str, &mlen);
    mu_true(mlen == 24);
    mu_true(addr != NULL);
    if(addr != NULL) {
        mu_true(*(addr+0) == 0x05);  // length byte
        mu_true(*(addr+1) == 0x0a);  // 10  1st digit
        mu_true(*(addr+2) == 0x0a);  // 10  2nd digit
        mu_true(*(addr+3) == 0x0a);  // 10  3rd digit
        mu_true(*(addr+4) == 0x00);  // 0   4th digit
    }
    free(addr);
    free(str);

    // ipv4 without mask
    str = mk_strptr("10.10.10.0");
    addr = key_bystr(str, &mlen);
    mu_true(mlen == -1);
    mu_true(addr != NULL);
    if(addr != NULL) {
        mu_true(*(addr+0) == 0x05);  // length byte
        mu_true(*(addr+1) == 0x0a);  // 10  1st digit
        mu_true(*(addr+2) == 0x0a);  // 10  2nd digit
        mu_true(*(addr+3) == 0x0a);  // 10  3rd digit
        mu_true(*(addr+4) == 0x00);  // 0   4th digit
    }
    free(addr);
    free(str);

    // ipv4 hexadecimal notation
    str = mk_strptr("0xa.0xa.0xa.0");
    addr = key_bystr(str, &mlen);
    mu_true(mlen == -1);
    mu_true(addr != NULL);
    if(addr != NULL) {
        mu_true(*(addr+0) == 0x05);  // length byte
        mu_true(*(addr+1) == 0x0a);  // 10  1st digit
        mu_true(*(addr+2) == 0x0a);  // 10  2nd digit
        mu_true(*(addr+3) == 0x0a);  // 10  3rd digit
        mu_true(*(addr+4) == 0x00);  // 0   4th digit
    }
    free(addr);
    free(str);

    // ipv4 octal notation
    str = mk_strptr("012.012.012.00");
    addr = key_bystr(str, &mlen);
    mu_true(mlen == -1);
    mu_true(addr != NULL);
    if(addr != NULL) {
        mu_true(*(addr+0) == 0x05);  // length byte
        mu_true(*(addr+1) == 0x0a);  // 10  1st digit
        mu_true(*(addr+2) == 0x0a);  // 10  2nd digit
        mu_true(*(addr+3) == 0x0a);  // 10  3rd digit
        mu_true(*(addr+4) == 0x00);  // 0   4th digit
    }
    free(addr);
    free(str);
}

void
test_key_bystr_bad(void)
{
    uint8_t *addr;
    char * str;
    int mlen = -2;

    // -- ipv4 with bad masks

    str = mk_strptr("10.10.10.0/33");
    printf("str ptr %p\n", str);
    addr = key_bystr(str, &mlen);
    mu_true(addr == NULL);
    free(str);

    str = mk_strptr("10.10.10.0/-1");
    addr = key_bystr(str, &mlen);
    mu_true(addr == NULL);
    free(str);

    // -- ipv4 with bad digits

    // base 10 notation
    str = mk_strptr("256.10.10.0/32");
    addr = key_bystr(str, &mlen);
    mu_true(addr == NULL);
    free(str);

    // too many digits
    str = mk_strptr("1.2.3.4.5/32");
    addr = key_bystr(str, &mlen);
    mu_true(addr == NULL);
    free(str);

    // malformed digits (trailing dots)
    str = mk_strptr("1.2.3./32");
    addr = key_bystr(str, &mlen);
    mu_true(addr == NULL);
    free(str);

    // malformed digits (embedded letter
    str = mk_strptr("1a.2.3.4/32");
    addr = key_bystr(str, &mlen);
    mu_true(addr == NULL);
    free(str);

    // bad hexadecimal notation
    str = mk_strptr("0x0g.0x0a.0x0a.0/24");
    addr = key_bystr(str, &mlen);
    mu_true(addr == NULL);
    free(str);

    // bad octal notation
    str = mk_strptr("008.10.10.0/24");
    addr = key_bystr(str, &mlen);
    mu_true(addr == NULL);
    free(str);

}

void
test_key_bystr_shorthand_good(void)
{
    uint8_t *addr;
    char * str;
    int mlen = -2;

    // ipv4 with mask

    str = mk_strptr("10/8");
    addr = key_bystr(str, &mlen);
    mu_true(mlen == 8);
    mu_true(addr != NULL);
    if(addr != NULL) {
        mu_true(*(addr+0) == 0x05);  // length byte
        mu_true(*(addr+1) == 0x0a);  // 10  1st digit
        mu_true(*(addr+2) == 0x00);  //  0  2nd digit
        mu_true(*(addr+3) == 0x00);  //  0  3rd digit
        mu_true(*(addr+4) == 0x00);  //  0  4th digit
    }
    free(addr);
    free(str);

    // no automasking of the key
    str = mk_strptr("10.10/8");
    addr = key_bystr(str, &mlen);
    mu_true(mlen == 8);
    mu_true(addr != NULL);
    if(addr != NULL) {
        mu_true(*(addr+0) == 0x05);  // length byte
        mu_true(*(addr+1) == 0x0a);  // 10  1st digit
        mu_true(*(addr+2) == 0x0a);  // 10  2nd digit
        mu_true(*(addr+3) == 0x00);  //  0  3rd digit
        mu_true(*(addr+4) == 0x00);  //  0  4th digit
    }
    free(addr);
    free(str);

    str = mk_strptr("10.10/14");
    addr = key_bystr(str, &mlen);
    mu_true(mlen == 14);
    mu_true(addr != NULL);
    if(addr != NULL) {
        mu_true(*(addr+0) == 0x05);  // length byte
        mu_true(*(addr+1) == 0x0a);  // 10  1st digit
        mu_true(*(addr+2) == 0x0a);  // 10  2nd digit
        mu_true(*(addr+3) == 0x00);  //  0  3rd digit
        mu_true(*(addr+4) == 0x00);  //  0  4th digit
    }
    free(addr);
    free(str);

    str = mk_strptr("10.10/24");
    addr = key_bystr(str, &mlen);
    mu_true(mlen == 24);
    mu_true(addr != NULL);
    if(addr != NULL) {
        mu_true(*(addr+0) == 0x05);  // length byte
        mu_true(*(addr+1) == 0x0a);  // 10  1st digit
        mu_true(*(addr+2) == 0x0a);  //  0  2nd digit
        mu_true(*(addr+3) == 0x00);  //  0  3rd digit
        mu_true(*(addr+4) == 0x00);  //  0  4th digit
    }
    free(addr);
    free(str);

    // ipv4 shorthand, no mask
    // 10 -> 10.0.0.0

    str = mk_strptr("10");
    addr = key_bystr(str, &mlen);
    mu_true(mlen == -1);
    mu_true(addr != NULL);
    if(addr != NULL) {
        mu_true(*(addr+0) == 0x05);  // length byte
        mu_true(*(addr+1) == 0x0a);  // 10  1st digit
        mu_true(*(addr+2) == 0x00);  //  0  2nd digit
        mu_true(*(addr+3) == 0x00);  //  0  3rd digit
        mu_true(*(addr+4) == 0x00);  //  0  4th digit
    }
    free(addr);
    free(str);

    // 10.10 -> 10.10.0.0, not 10.0.0.10
    str = mk_strptr("10.10");
    addr = key_bystr(str, &mlen);
    mu_true(mlen == -1);
    mu_true(addr != NULL);
    if(addr != NULL) {
        mu_true(*(addr+0) == 0x05);  // length byte
        mu_true(*(addr+1) == 0x0a);  // 10  1st digit
        mu_true(*(addr+2) == 0x0a);  // 10  2nd digit
        mu_true(*(addr+3) == 0x00);  //  0  3rd digit
        mu_true(*(addr+4) == 0x00);  //  0  4th digit
    }
    free(addr);
    free(str);
}

void
test_key_bylen_good(void)
{
    uint8_t *addr;

    // ipv4 masks

    addr = key_bylen(AF_INET, 0);
    if(addr != NULL) {
        mu_true(*(addr+0) == 0x05);  // length byte
        mu_true(*(addr+1) == 0x00);  // 0
        mu_true(*(addr+2) == 0x00);  // 0
        mu_true(*(addr+3) == 0x00);  // 0
        mu_true(*(addr+4) == 0x00);  // 0
        free(addr);
    }

    addr = key_bylen(AF_INET, 1);
    if(addr != NULL) {
        mu_true(*(addr+0) == 0x05);  // length byte
        mu_true(*(addr+1) == 0x80);  // 128
        mu_true(*(addr+2) == 0x00);  // 0
        mu_true(*(addr+3) == 0x00);  // 0
        mu_true(*(addr+4) == 0x00);  // 0
        free(addr);
    }

    addr = key_bylen(AF_INET, 9);
    if(addr != NULL) {
        mu_true(*(addr+0) == 0x05);  // length byte
        mu_true(*(addr+1) == 0xff);  // 255
        mu_true(*(addr+2) == 0x80);  // 128
        mu_true(*(addr+3) == 0x00);  // 0
        mu_true(*(addr+4) == 0x00);  // 0
        free(addr);
    }

    addr = key_bylen(AF_INET, 24);
    if(addr != NULL) {
        mu_true(*(addr+0) == 0x05);  // length byte
        mu_true(*(addr+1) == 0xff);  // 255
        mu_true(*(addr+2) == 0xff);  // 255
        mu_true(*(addr+3) == 0xff);  // 255
        mu_true(*(addr+4) == 0x00);  //   0
        free(addr);
    }

    addr = key_bylen(AF_INET, 30);
    if(addr != NULL) {
        mu_true(*(addr+0) == 0x05);  // length byte
        mu_true(*(addr+1) == 0xff);  // 255
        mu_true(*(addr+2) == 0xff);  // 255
        mu_true(*(addr+3) == 0xff);  // 255
        mu_true(*(addr+4) == 0xfc);  // 252
        free(addr);
    }

    addr = key_bylen(AF_INET, 31);
    if(addr != NULL) {
        mu_true(*(addr+0) == 0x05);  // length byte
        mu_true(*(addr+1) == 0xff);  // 255
        mu_true(*(addr+2) == 0xff);  // 255
        mu_true(*(addr+3) == 0xff);  // 255
        mu_true(*(addr+4) == 0xfe);  // 254
        free(addr);
    }

    addr = key_bylen(AF_INET, 32);
    if(addr != NULL) {
        mu_true(*(addr+0) == 0x05);  // length byte
        mu_true(*(addr+1) == 0xff);  // 255
        mu_true(*(addr+2) == 0xff);  // 255
        mu_true(*(addr+3) == 0xff);  // 255
        mu_true(*(addr+4) == 0xff);  // 255
        free(addr);
    }
}

void
test_key_bylen_bad(void)
{
    uint8_t *addr;

    // invalid ipv4 masks

    addr = key_bylen(AF_INET, -32);
    mu_true(addr == NULL);

    addr = key_bylen(AF_INET, 33);
    mu_true(addr == NULL);

    addr = key_bylen(AF_INET, 64);
    mu_true(addr == NULL);

    // invalid ipv6 masks

    addr = key_bylen(AF_INET6, -128);
    mu_true(addr == NULL);

    addr = key_bylen(AF_INET6, 129);
    mu_true(addr == NULL);

    addr = key_bylen(AF_INET6, 256);
    mu_true(addr == NULL);
}

void
test_key_tolen_good(void)
{
    int mlen;
    uint8_t *addr = malloc(5 * sizeof(uint8_t));

    // - all tests set *bytes*, so network byte order is ensured

    // set IPv4 addr keylen
    *addr = 1 + IP4_KEYLEN;

    // len 0
    *(addr+1) = 0x00;
    *(addr+2) = 0x00;
    *(addr+3) = 0x00;
    *(addr+4) = 0x00;
    mlen = key_tolen(addr);
    mu_eq(0, mlen, "%i");

    // len 1
    *(addr+1) = 0x80;
    mlen = key_tolen(addr);
    mu_eq(1, mlen, "%i");

    // len 9
    *(addr+1) = 0xff;
    *(addr+2) = 0x80;
    mlen = key_tolen(addr);
    mu_eq(9, mlen, "%i");

    // len 16
    *(addr+1) = 0xff;
    *(addr+2) = 0xff;
    mlen = key_tolen(addr);
    mu_eq(16, mlen, "%i");

    // len 32
    *(addr+1) = 0xff;
    *(addr+2) = 0xff;
    *(addr+3) = 0xff;
    *(addr+4) = 0xff;
    mlen = key_tolen(addr);
    mu_eq(32, mlen, "%i");

    // count 1's from msb downto lsb?
    // len 32
    *(addr+1) = 0x00;
    *(addr+2) = 0xff;
    *(addr+3) = 0xff;
    *(addr+4) = 0xff;
    mlen = key_tolen(addr);
    mu_eq(0, mlen, "%i");

    free(addr);
}

void
test_key_tolen_bad(void)
{
    // NULL key
    int mlen = key_tolen(NULL);
    mu_eq(-1, mlen, "%i");
}

void
test_key_tostr_good(void)
{
    uint8_t *addr;
    int mlen, equal = 0;
    char buf[IP6_PFXSTRLEN];  // large enough to include /128
    char sp[IP6_PFXSTRLEN];   // dito

    snprintf(sp, IP6_PFXSTRLEN, "0.0.0.0");
    addr = key_bystr(sp, &mlen);
    mu_true(key_tostr(addr, buf));
    equal = strncmp(buf, sp, IP6_PFXSTRLEN);
    mu_true(equal == 0);
    free(addr);

    snprintf(sp, IP6_PFXSTRLEN, "1.128.192.255");
    addr = key_bystr(sp, &mlen);
    mu_true(key_tostr(addr, buf));
    equal = strncmp(buf, sp, IP6_PFXSTRLEN);
    mu_true(equal == 0);
    free(addr);

    snprintf(sp, IP6_PFXSTRLEN, "255.255.255.255");
    addr = key_bystr(sp, &mlen);
    mu_true(key_tostr(addr, buf));
    equal = strncmp(buf, sp, IP6_PFXSTRLEN);
    mu_true(equal == 0);
    free(addr);

    // octal and/or hexadecimal turns into normal dotted quad
    snprintf(sp, IP6_PFXSTRLEN, "0xa.0xb.014.015");
    addr = key_bystr(sp, &mlen);
    snprintf(sp, IP6_PFXSTRLEN, "10.11.12.13");
    mu_true(key_tostr(addr, buf));
    equal = strncmp(buf, sp, IP6_PFXSTRLEN);
    mu_true(equal == 0);
    free(addr);

    // shorthand turns into normal dotted quad
    snprintf(sp, IP6_PFXSTRLEN, "0xa.0xb");
    addr = key_bystr(sp, &mlen);
    snprintf(sp, IP6_PFXSTRLEN, "10.11.0.0");
    mu_true(key_tostr(addr, buf));
    equal = strncmp(buf, sp, IP6_PFXSTRLEN);
    mu_true(equal == 0);
    free(addr);

    // mask is read, but not part of returned string
    snprintf(sp, IP6_PFXSTRLEN, "1.2.3.4/32");
    addr = key_bystr(sp, &mlen);
    snprintf(sp, IP6_PFXSTRLEN, "1.2.3.4");
    mu_true(key_tostr(addr, buf));
    mu_true(mlen == 32);
    equal = strncmp(buf, sp, IP6_PFXSTRLEN);
    mu_true(equal == 0);
    free(addr);

    // ipv6 strings

    // ipv6 zero's collapse
    snprintf(sp, IP6_PFXSTRLEN, "2f:aa:00:00:00::");
    addr = key_bystr(sp, &mlen);
    snprintf(sp, IP6_PFXSTRLEN, "2f:aa::");
    mu_true(key_tostr(addr, buf));
    mu_eq(-1, mlen, "%i");
    equal = strncmp(buf, sp, IP6_PFXSTRLEN);
    mu_true(equal == 0);
    free(addr);

    // ipv6 longest series of zero's collapse
    snprintf(sp, IP6_PFXSTRLEN, "2f:aa:00:00:00:aa::");
    addr = key_bystr(sp, &mlen);
    snprintf(sp, IP6_PFXSTRLEN, "2f:aa::aa:0:0");
    mu_true(key_tostr(addr, buf));
    mu_eq(-1, mlen, "%i");
    equal = strncmp(buf, sp, IP6_PFXSTRLEN);
    mu_true(equal == 0);
    free(addr);
}

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

void
test_key_decr_ipv4_good(void)
{
    uint8_t *addr = malloc(5 * sizeof(uint8_t));

    *addr = IP4_KEYLEN + 1;  // i.e. 5

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

void
test_key_cmp_ipv4_good(void)
{
    uint8_t *a = malloc(5*sizeof(uint8_t));
    uint8_t *b = malloc(5*sizeof(uint8_t));

    *a = *b = 1 + IP4_KEYLEN;

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
    *a = *b = IP4_KEYLEN;
    mu_true(key_cmp(a, b) == 0);

    free(a);
    free(b);
}

void
test_key_cmp_ipv4_bad(void)
{
    uint8_t *a = malloc(5*sizeof(uint8_t));
    uint8_t *b = malloc(5*sizeof(uint8_t));

    // init key memory
    *a = *b = 1 + IP4_KEYLEN;
    *(a+1) = *(b+1) = 0xff;
    *(a+2) = *(b+2) = 0xff;
    *(a+3) = *(b+3) = 0xff;
    *(a+4) = *(b+4) = 0xff;

    // different keylengths should yield error
    *a = IP4_KEYLEN;
    mu_true(key_cmp(a, b) == -2);

    // a NULL ptr also yields an error
    mu_true(key_cmp(a, NULL) == -2);
    mu_true(key_cmp(NULL, b) == -2);

    // two NULL ptrs also considered an error
    mu_true(key_cmp(NULL, NULL) == -2);

    free(a);
    free(b);
}


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
    mu_true(key_masked(a, m));
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
    mu_true(key_masked(a, m));
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
    mu_true(key_masked(a, m));
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
    mu_true(key_masked(a, m));
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
    mu_true(key_masked(a, m));
    mu_eq(0xff, *(a+1), "%i");
    mu_eq(0xff, *(a+2), "%i");
    mu_eq(0x00, *(a+3), "%i");
    mu_eq(0x00, *(a+4), "%i");

    free(a);
    free(m);
}
