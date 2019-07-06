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
#include "test_c_key_bystr.h"

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
    uint8_t addr[MAX_BINKEY];
    char *str;
    int mlen = -2, af=0;

    // ipv4 with mask
    str = mk_strptr("10.10.10.0/24");
    key_bystr(addr, &mlen, &af, str);
    mu_true(mlen == 24);
    mu_true(addr != NULL);
    mu_true(af == AF_INET);
    mu_true(*(addr+0) == 0x05);  // length byte
    mu_true(*(addr+1) == 0x0a);  // 10  1st digit
    mu_true(*(addr+2) == 0x0a);  // 10  2nd digit
    mu_true(*(addr+3) == 0x0a);  // 10  3rd digit
    mu_true(*(addr+4) == 0x00);  // 0   4th digit
    free(str);

    // ipv4 without mask
    str = mk_strptr("10.10.10.0");
    key_bystr(addr, &mlen, &af, str);
    mu_true(mlen == -1);
    mu_true(addr != NULL);
    mu_true(af == AF_INET);
    mu_true(*(addr+0) == 0x05);  // length byte
    mu_true(*(addr+1) == 0x0a);  // 10  1st digit
    mu_true(*(addr+2) == 0x0a);  // 10  2nd digit
    mu_true(*(addr+3) == 0x0a);  // 10  3rd digit
    mu_true(*(addr+4) == 0x00);  // 0   4th digit
    free(str);

    // ipv4 hexadecimal notation
    str = mk_strptr("0xa.0xa.0xa.0");
    key_bystr(addr, &mlen, &af, str);
    mu_true(mlen == -1);
    mu_true(addr != NULL);
    mu_true(af == AF_INET);
    mu_true(*(addr+0) == 0x05);  // length byte
    mu_true(*(addr+1) == 0x0a);  // 10  1st digit
    mu_true(*(addr+2) == 0x0a);  // 10  2nd digit
    mu_true(*(addr+3) == 0x0a);  // 10  3rd digit
    mu_true(*(addr+4) == 0x00);  // 0   4th digit
    free(str);

    // ipv4 octal notation
    str = mk_strptr("012.012.012.00");
    key_bystr(addr, &mlen, &af, str);
    mu_true(mlen == -1);
    mu_true(addr != NULL);
    mu_true(af == AF_INET);
    mu_true(*(addr+0) == 0x05);  // length byte
    mu_true(*(addr+1) == 0x0a);  // 10  1st digit
    mu_true(*(addr+2) == 0x0a);  // 10  2nd digit
    mu_true(*(addr+3) == 0x0a);  // 10  3rd digit
    mu_true(*(addr+4) == 0x00);  // 0   4th digit
    free(str);
}

void
test_key_bystr_bad(void)
{
    uint8_t *addr, buf[MAX_BINKEY];
    char * str;
    int mlen = -2, af = 0;

    // -- ipv4 with bad masks

    str = mk_strptr("10.10.10.0/33");
    addr = key_bystr(buf, &mlen, &af, str);
    mu_true(addr == NULL);
    mu_true(af == AF_UNSPEC);
    free(str);

    str = mk_strptr("10.10.10.0/-1");
    addr = key_bystr(buf, &mlen, &af, str);
    mu_true(addr == NULL);
    mu_true(af == AF_UNSPEC);
    free(str);

    // -- ipv4 with bad digits

    // base 10 notation
    str = mk_strptr("256.10.10.0/32");
    addr = key_bystr(buf, &mlen, &af, str);
    mu_true(addr == NULL);
    mu_true(af == AF_UNSPEC);
    free(str);

    // too many digits
    str = mk_strptr("1.2.3.4.5/32");
    addr = key_bystr(buf, &mlen, &af, str);
    mu_true(addr == NULL);
    mu_true(af == AF_UNSPEC);
    free(str);

    // malformed digits (trailing dots)
    str = mk_strptr("1.2.3./32");
    addr = key_bystr(buf, &mlen, &af, str);
    mu_true(addr == NULL);
    mu_true(af == AF_UNSPEC);
    free(str);

    // malformed digits (embedded letter
    str = mk_strptr("1a.2.3.4/32");
    addr = key_bystr(buf, &mlen, &af, str);
    mu_true(addr == NULL);
    mu_true(af == AF_UNSPEC);
    free(str);

    // bad hexadecimal notation
    str = mk_strptr("0x0g.0x0a.0x0a.0/24");
    addr = key_bystr(buf, &mlen, &af, str);
    mu_true(addr == NULL);
    mu_true(af == AF_UNSPEC);
    free(str);

    // bad octal notation
    str = mk_strptr("008.10.10.0/24");
    addr = key_bystr(buf, &mlen, &af, str);
    mu_true(addr == NULL);
    mu_true(af == AF_UNSPEC);
    free(str);

    // empty string
    addr = key_bystr(buf, &mlen, &af, "");
    mu_true(addr == NULL);
    mu_true(af == AF_UNSPEC);

    // empty string
    addr = key_bystr(buf, &mlen, &af, "a_name");
    mu_true(addr == NULL);
    mu_true(af == AF_UNSPEC);

    // NULL
    addr = key_bystr(buf, &mlen, &af, NULL);
    mu_true(addr == NULL);
    mu_true(af == AF_UNSPEC);

}

void
test_key_bystr_shorthand_good(void)
{
    uint8_t addr[MAX_BINKEY];
    char * str;
    int mlen = -2, af = 0;

    // ipv4 with mask

    str = mk_strptr("10/8");
    key_bystr(addr, &mlen, &af, str);
    mu_true(mlen == 8);
    mu_true(af == AF_INET);
    mu_true(*(addr+0) == 0x05);  // length byte
    mu_true(*(addr+1) == 0x0a);  // 10  1st digit
    mu_true(*(addr+2) == 0x00);  //  0  2nd digit
    mu_true(*(addr+3) == 0x00);  //  0  3rd digit
    mu_true(*(addr+4) == 0x00);  //  0  4th digit
    free(str);

    // no automasking of the key
    str = mk_strptr("10.10/8");
    key_bystr(addr, &mlen, &af, str);
    mu_true(mlen == 8);
    mu_true(af == AF_INET);
    mu_true(*(addr+0) == 0x05);  // length byte
    mu_true(*(addr+1) == 0x0a);  // 10  1st digit
    mu_true(*(addr+2) == 0x0a);  // 10  2nd digit
    mu_true(*(addr+3) == 0x00);  //  0  3rd digit
    mu_true(*(addr+4) == 0x00);  //  0  4th digit
    free(str);

    str = mk_strptr("10.10/14");
    key_bystr(addr, &mlen, &af, str);
    mu_true(mlen == 14);
    mu_true(af == AF_INET);
    mu_true(*(addr+0) == 0x05);  // length byte
    mu_true(*(addr+1) == 0x0a);  // 10  1st digit
    mu_true(*(addr+2) == 0x0a);  // 10  2nd digit
    mu_true(*(addr+3) == 0x00);  //  0  3rd digit
    mu_true(*(addr+4) == 0x00);  //  0  4th digit
    free(str);

    str = mk_strptr("10.10/24");
    key_bystr(addr, &mlen, &af, str);
    mu_true(mlen == 24);
    mu_true(af == AF_INET);
    mu_true(*(addr+0) == 0x05);  // length byte
    mu_true(*(addr+1) == 0x0a);  // 10  1st digit
    mu_true(*(addr+2) == 0x0a);  //  0  2nd digit
    mu_true(*(addr+3) == 0x00);  //  0  3rd digit
    mu_true(*(addr+4) == 0x00);  //  0  4th digit
    free(str);

    // ipv4 shorthand, no mask
    // 10 -> 10.0.0.0

    str = mk_strptr("10");
    key_bystr(addr, &mlen, &af, str);
    mu_true(mlen == -1);
    mu_true(af == AF_INET);
    mu_true(*(addr+0) == 0x05);  // length byte
    mu_true(*(addr+1) == 0x0a);  // 10  1st digit
    mu_true(*(addr+2) == 0x00);  //  0  2nd digit
    mu_true(*(addr+3) == 0x00);  //  0  3rd digit
    mu_true(*(addr+4) == 0x00);  //  0  4th digit
    free(str);

    // 10.10 -> 10.10.0.0, not 10.0.0.10
    str = mk_strptr("10.10");
    key_bystr(addr, &mlen, &af, str);
    mu_true(mlen == -1);
    mu_true(af == AF_INET);
    mu_true(*(addr+0) == 0x05);  // length byte
    mu_true(*(addr+1) == 0x0a);  // 10  1st digit
    mu_true(*(addr+2) == 0x0a);  // 10  2nd digit
    mu_true(*(addr+3) == 0x00);  //  0  3rd digit
    mu_true(*(addr+4) == 0x00);  //  0  4th digit
    free(str);
}

