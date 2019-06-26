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
#include "test_c_lsm.h"    // a generated header file for this test runner

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
    entry_t *itm = NULL;
    testpfx_t pfx[6] = {
        {"1.2.3.0/24",    1},   /* the least specific */
        {"1.2.3.0/25",    2},
        {"1.2.3.128/25",  4},
        {"1.2.3.128/26",  8},
        {"1.2.3.128/27", 16},
        {"1.2.3.128/28", 32},
    };

    for (int i=0; i < 6; i++)
        mu_assert(tbl_set(ipt, pfx[i].pfx, &pfx[i].dta, NULL));

    mu_eq(SIZE_T(6), ipt->count4, "%lu");

    /* start search from a host address covered by almost all prefixes */
    itm = tbl_lsm(ipt, "1.2.3.128");
    if(itm) mu_eq(1, INT_VALUE(itm), "%d");
    else mu_failed("lsm should %s", "NOT have failed");

    /* start search from host address covered by 2 prefixes*/
    itm = tbl_lsm(ipt, "1.2.3.4");
    if(itm) mu_eq(1, INT_VALUE(itm), "%d");
    else mu_failed("lsm should %s", "NOT have failed");

    tbl_destroy(&ipt, NULL);
}

void
test_tbl_lsm_zeromask(void)
{

    entry_t *itm = NULL;
    table_t *ipt = tbl_create(NULL);

    mu_assert(ipt);
    testpfx_t pfx[6] = {
        {"0.0.0.0/0",     1},   /* the least specific */
        {"1.2.3.0/25",    2},
        {"1.2.3.128/25",  4},
        {"1.2.3.128/26",  8},
        {"1.2.3.128/27", 16},
        {"1.2.3.128/28", 32},
    };

    for (int i=0; i < 6; i++)
        mu_assert(tbl_set(ipt, pfx[i].pfx, &pfx[i].dta, NULL));

    itm = tbl_lsm(ipt, "1.2.3.128");
    if(itm) mu_eq(1, INT_VALUE(itm), "%d");
    else mu_failed("lsm should %s", "NOT have failed");

    itm = tbl_lsm(ipt, "1.2.3.5");
    if(itm) mu_eq(1, INT_VALUE(itm), "%d");
    else mu_failed("lsm should %s", "NOT have failed");

    itm = tbl_lsm(ipt, "0/0");
    if(itm) mu_eq(1, INT_VALUE(itm), "%d");
    else mu_failed("lsm should %s", "NOT have failed");

    tbl_destroy(&ipt, NULL);
}

void
test_tbl_lsm_withmask(void)
{
    /* lsm for a.b.c.d/e should honor the mask */
    entry_t *itm = NULL;
    table_t *ipt = tbl_create(NULL);

    testpfx_t pfx[6] = {
        {"1.2.3.0/24",    1},   /* the least specific */
        {"1.2.3.0/25",    2},
        {"1.2.3.128/25",  4},
        {"1.2.3.128/26",  8},
        {"1.2.3.128/27", 16},
        {"1.2.3.128/28", 32},
    };

    for (int i=0; i < 6; i++)
        mu_assert(tbl_set(ipt, pfx[i].pfx, &pfx[i].dta, NULL));

    /* search prefixes may have a mask */
    itm = tbl_lsm(ipt, "1.2.3.128/25");
    if(itm) mu_eq(1, INT_VALUE(itm), "%d");
    else mu_failed("lsm should %s", "NOT have failed");

    itm = tbl_lsm(ipt, "1.2.3.0/24");
    if(itm) mu_eq(1, INT_VALUE(itm), "%d");
    else mu_failed("lsm should %s", "NOT have failed");

    /* lsm honors search mask (ie result's mask <= search mask) */
    mu_assert(NULL == tbl_lsm(ipt, "1.2.3.0/23"));
    mu_assert(NULL == tbl_lsm(ipt, "1.2.3.4/8"));

    /* search prefixes not covered by any entry in the table */
    mu_assert(NULL == tbl_lsm(ipt, "3.2.3.0/24"));
    mu_assert(NULL == tbl_lsm(ipt, "3.2.3.0/24"));
    mu_assert(NULL == tbl_lsm(ipt, "3.2.3.4"));
    mu_assert(NULL == tbl_lsm(ipt, "3.2.3.0/25"));

    tbl_destroy(&ipt, NULL);
}

