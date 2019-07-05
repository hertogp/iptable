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
#include "test_c_destroy.h"  // a generated header file for this test runner

/*
 * Test table->destroy()
 */


typedef struct testpfx_t {
    const char *pfx;
    int  dta;
} testpfx_t;

#define NELEMS(x) (int)(sizeof(x) / sizeof(x[0]))

// purge counter
void purge(void *args, void **dta);
void purge(void *args, void **dta)
{
    *(int *)args += 1;
    dta = dta ? dta : dta; /* not used */
}


void
test_emptytable(void)
{

    table_t *t = tbl_create(purge);
    int purge_cnt = 0;

    tbl_destroy(&t, &purge_cnt);
    mu_eq(NULL, (void *)t, "%p");
    mu_eq(0, purge_cnt, "%d");
}

void
test_host0(void)
{

    table_t *t = tbl_create(purge);
    testpfx_t pfx[] = { {"0.0.0.0/32", 1} };
    int purge_cnt = 0;

    mu_assert(tbl_set(t, pfx[0].pfx, &pfx[0].dta, NULL));
    tbl_destroy(&t, &purge_cnt);
    mu_eq(NULL, (void *)t, "%p");
    mu_eq(1, purge_cnt, "%d");
}

void
test_nxhost0(void)
{

    table_t *t = tbl_create(purge);
    testpfx_t pfx[] = {
        {"0.0.0.0/0",  1},
        {"0.0.0.0/7",  2},
        {"0.0.0.0/32", 8},
    };
    int purge_cnt = 0;

    for (int i = 0; i < NELEMS(pfx); i++)
        mu_assert(tbl_set(t, pfx[i].pfx, &pfx[i].dta, NULL));
    tbl_destroy(&t, &purge_cnt);
    mu_eq(NULL, (void *)t, "%p");
    mu_eq(NELEMS(pfx), purge_cnt, "%d");
}

void
test_host255(void)
{

    table_t *t = tbl_create(purge);
    testpfx_t pfx[] = { {"255.255.255.255/32", 1} };
    int purge_cnt = 0;

    mu_assert(tbl_set(t, pfx[0].pfx, &pfx[0].dta, NULL));
    tbl_destroy(&t, &purge_cnt);
    mu_eq(NULL, (void *)t, "%p");
    mu_eq(1, purge_cnt, "%d");
}
