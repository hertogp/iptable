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
#include "test_c_key_alloc.h"

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
test_key_alloc_good(void)
{
    uint8_t *key;

    // keys are allocated with appropiate LEN byte set (total array length)
    key = key_alloc(AF_INET);
    mu_eq(1 + IP4_KEYLEN, IPT_KEYLEN(key), "%d");
    mu_eq(AF_INET, KEY_AF_FAM(key), "%d");   // same test
    mu_true(KEY_IS_IP4(key));                // same test
    free(key);

    key = key_alloc(AF_INET6);
    mu_eq(1 + IP6_KEYLEN, IPT_KEYLEN(key), "%d");
    mu_eq(AF_INET6, KEY_AF_FAM(key), "%d");  // same test
    mu_true(KEY_IS_IP6(key));                // same test
    free(key);
}

void
test_key_alloc_bad(void)
{
    uint8_t *key;

    // unknown AF's yield NULL
    key = key_alloc(AF_UNSPEC);
    mu_eq(NULL, key, "%p");
    if (key) free(key);
}

