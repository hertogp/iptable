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
#include "test_c_key_tostr.h"

void
test_key_tostr_good(void)
{
    uint8_t addr[MAX_BINKEY];
    int mlen, af, equal = 0;
    char buf[IP6_PFXSTRLEN];  // large enough to include /128
    char sp[IP6_PFXSTRLEN];   // dito

    snprintf(sp, IP6_PFXSTRLEN, "0.0.0.0");
    key_bystr(addr, &mlen, &af, sp);
    mu_true(key_tostr(buf, addr));
    equal = strncmp(buf, sp, IP6_PFXSTRLEN);
    mu_true(equal == 0);

    snprintf(sp, IP6_PFXSTRLEN, "1.128.192.255");
    key_bystr(addr, &mlen, &af, sp);
    mu_true(key_tostr(buf, addr));
    equal = strncmp(buf, sp, IP6_PFXSTRLEN);
    mu_true(equal == 0);

    snprintf(sp, IP6_PFXSTRLEN, "255.255.255.255");
    key_bystr(addr, &mlen, &af, sp);
    mu_true(key_tostr(buf, addr));
    equal = strncmp(buf, sp, IP6_PFXSTRLEN);
    mu_true(equal == 0);

    // octal and/or hexadecimal turns into normal dotted quad
    snprintf(sp, IP6_PFXSTRLEN, "0xa.0xb.014.015");
    key_bystr(addr, &mlen, &af, sp);
    snprintf(sp, IP6_PFXSTRLEN, "10.11.12.13");
    mu_true(key_tostr(buf, addr));
    equal = strncmp(buf, sp, IP6_PFXSTRLEN);
    mu_true(equal == 0);

    // shorthand turns into normal dotted quad
    snprintf(sp, IP6_PFXSTRLEN, "0xa.0xb");
    key_bystr(addr, &mlen, &af, sp);
    snprintf(sp, IP6_PFXSTRLEN, "10.11.0.0");
    mu_true(key_tostr(buf, addr));
    equal = strncmp(buf, sp, IP6_PFXSTRLEN);
    mu_true(equal == 0);

    // mask is read, but not part of returned string
    snprintf(sp, IP6_PFXSTRLEN, "1.2.3.4/32");
    key_bystr(addr, &mlen, &af, sp);
    snprintf(sp, IP6_PFXSTRLEN, "1.2.3.4");
    mu_true(key_tostr(buf, addr));
    mu_true(mlen == 32);
    equal = strncmp(buf, sp, IP6_PFXSTRLEN);
    mu_true(equal == 0);

    // ipv6 strings

    // ipv6 zero's collapse
    snprintf(sp, IP6_PFXSTRLEN, "2f:aa:00:00:00::");
    key_bystr(addr, &mlen, &af, sp);
    snprintf(sp, IP6_PFXSTRLEN, "2f:aa::");
    mu_true(key_tostr(buf, addr));
    mu_eq(-1, mlen, "%i");
    equal = strncmp(buf, sp, IP6_PFXSTRLEN);
    mu_true(equal == 0);

    // ipv6 longest series of zero's collapse
    snprintf(sp, IP6_PFXSTRLEN, "2f:aa:00:00:00:aa::");
    key_bystr(addr, &mlen, &af, sp);
    snprintf(sp, IP6_PFXSTRLEN, "2f:aa::aa:0:0");
    mu_true(key_tostr(buf, addr));
    mu_eq(-1, mlen, "%i");
    equal = strncmp(buf, sp, IP6_PFXSTRLEN);
    mu_true(equal == 0);
}
