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
#include "test_c_tbl_lsm.h"

#define NELEMS(x) ((int)(sizeof x / sizeof(x[0])))
/*
 * Test cases
 *
 * Tests store references to local numbers on the stack and thus use:
 *   t = tbl_create(NULL)           - no purge function needed
 *   tbl_set(t, pfx, &number, NULL) - and no purge args needed.
 * to create an iptable t & fill it with prefixes.
 */

typedef struct testpfx_t {
    const char *pfx;
    int  dta;
} testpfx_t;

/*
 * INT_VALUE provides easy access to an entry_t's integer value
 * SIZE_T casts an int to size_t to matchup with ipt->count{4,6} values
 */

#define INT_VALUE(x) (*(int *)x->value)
#define SIZE_T(x) ((size_t)x)

void
test_tbl_lsm_good(void)
{

    table_t *ipt = tbl_create(NULL);
    entry_t *e = NULL;
    testpfx_t pfx[6] = {
        {"1.2.3.0/24",  1},
        {"1.2.3.0/25",  2},
        {"1.2.3.0/26",  4},
        {"1.2.3.0/27",  8},
        {"1.2.3.0/28", 16},
        {"1.2.3.0/29", 32},
    };

    for (int i=0; i < 6; i++)
        mu_assert(tbl_set(ipt, pfx[i].pfx, &pfx[i].dta, NULL));

    mu_eq(SIZE_T(6), ipt->count4, "%lu");

    /* get radix node of specific subnet */
    for (int i=5; i > 0; i--) {
        e = tbl_get(ipt, pfx[i].pfx);
        if(e) {
            mu_eq(pfx[i].dta, INT_VALUE(e), "%d");  /* check right pfx was found */
            e = (entry_t *)tbl_lsm(e->rn);          /* should find less specific */
            mu_eq(pfx[i-1].dta, INT_VALUE(e), "%d");
        }
        else mu_failed("tbl_get should %s", "NOT have failed");
    }


    tbl_destroy(&ipt, NULL);
}

void
test_tbl_lsm_zeromask(void)
{
    /* search for a less specific prefix should find 0/0 if it exists */
    table_t *ipt = tbl_create(NULL);
    entry_t *e = NULL;
    testpfx_t pfx[] = {
        {"0.0.0.0/0",   1},
        {"1.2.3.0/29", 32},
    };

    mu_assert(ipt);
    for (int i=0; i < 2; i++)
        mu_assert(tbl_set(ipt, pfx[i].pfx, &pfx[i].dta, NULL));

    mu_eq(SIZE_T(2), ipt->count4, "%lu");

    /* get radix node of specific subnet */
    e = tbl_get(ipt, pfx[1].pfx);
    if(e) {
        mu_eq(pfx[1].dta, INT_VALUE(e), "%d");  /* check right pfx was found */

        /* tbl_lsm should find explicit 0/0 */
        e = (entry_t *)tbl_lsm(e->rn);
        if(e) {
            mu_eq(pfx[0].dta, INT_VALUE(e), "%d");
        }
        else mu_failed("tbl_lsm should %s have failed", "NOT");
    }
    else mu_failed("tbl_get should %s have failed", "NOT");

    tbl_destroy(&ipt, NULL);
}

