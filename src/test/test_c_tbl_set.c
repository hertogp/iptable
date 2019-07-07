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
#include "test_c_tbl_set.h"

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
    int dta;
} testpfx_t;

/*
 * INT_VALUE provides easy access to an entry_t's integer value
 * SIZE_T casts an int to size_t to matchup with ipt->count{4,6} values
 */

#define INT_VALUE(x) (*(int *)x->value)
#define SIZE_T(x) ((size_t)(x))

// Tests

void
test_tbl_set_one(void)
{
    table_t *t = tbl_create(NULL);
    entry_t *itm = NULL;
    testpfx_t pfx[] = {
        {"1.2.3.0/24",  1},
        {"2f::/104",    2},
    };

    for (size_t i=0; i < sizeof(pfx)/sizeof(pfx[0]); i++)
        mu_assert(tbl_set(t, pfx[i].pfx, &pfx[i].dta, NULL));

    mu_eq(SIZE_T(1), t->count4, "%lu");
    mu_eq(SIZE_T(1), t->count6, "%lu");

    itm = tbl_lpm(t, "1.2.3.0");
    if (itm) mu_eq(1, INT_VALUE(itm), "%d");
    else mu_failed("tbl_lpm should %s", "NOT have failed");

    itm = tbl_lpm(t, "2f::");
    if (itm) mu_eq(2, INT_VALUE(itm), "%d");
    else mu_failed("tbl_lpm should %s", "NOT have failed");

    tbl_destroy(&t, NULL);
}

void
test_tbl_set_good(void)
{
    table_t *t = tbl_create(NULL);
    entry_t *itm = NULL;
    testpfx_t pfx[6] = {
        {"1.2.2.4/24",  1},
        {"1.2.3.4/24",  2},
        {"1.2.4.4/24",  4},
        {"1.2.5.4/24",  8},
        {"1.2.6.4/24",  16},
        {"1.2.7.4/24",  32},
    };

    for (size_t i=0; i < sizeof(pfx)/sizeof(pfx[0]); i++)
        mu_assert(tbl_set(t, pfx[i].pfx, &pfx[i].dta, NULL));

    mu_assert(SIZE_T(6) == t->count4);
    mu_eq(SIZE_T(0), t->count6, "%lu");

    // adding an existing entry, wont increase the count
    mu_assert(tbl_set(t, pfx[1].pfx, &pfx[1].dta, NULL));
    mu_eq(SIZE_T(6), t->count4, "%lu");

    // assign to an existing entry, overwrites its data
    mu_assert(tbl_set(t, pfx[1].pfx, &pfx[2].dta, NULL));
    itm = tbl_lpm(t, pfx[1].pfx);
    if (itm) mu_eq(pfx[2].dta, INT_VALUE(itm), "%d");
    else mu_failed("lpm shoud %s", "NOT have failed");

    tbl_destroy(&t, NULL);
}
