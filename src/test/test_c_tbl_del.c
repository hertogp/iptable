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
#include "test_c_tbl_del.h"    // a generated header file for this test runner

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
test_tbl_del_good(void)
{
    // these tests don't store any user data.  Freeing a node will free the
    // pointer to the user data so we would need to allocate new pointers to
    // some data, each time a prefix is added.
    table_t *ipt;
    char pfx[MAX_STRKEY];

    ipt = tbl_create(NULL);

    // add one, del one
    snprintf(pfx, MAX_STRKEY, "1.2.3.4/32");
    mu_assert(tbl_set(ipt, pfx, NULL, NULL));
    mu_assert(tbl_del(ipt, pfx, NULL));
    mu_assert(ipt->count4 == 0);

    // add two, del two
    snprintf(pfx, MAX_STRKEY, "11.12.13.14");
    mu_assert(tbl_set(ipt, pfx, NULL, NULL));
    snprintf(pfx, MAX_STRKEY, "10.11.12.13");
    mu_assert(tbl_set(ipt, pfx, NULL, NULL));
    mu_assert(ipt->count4 == 2);

    mu_assert(tbl_del(ipt, pfx, NULL));
    snprintf(pfx, MAX_STRKEY, "11.12.13.14");
    mu_assert(tbl_del(ipt, pfx, NULL));
    mu_assert(ipt->count4 == 0);


    tbl_destroy(&ipt, NULL);
}

void
test_tbl_del_bad(void)
{
    // these tests don't store any user data.  Freeing a node will free the
    // pointer to the user data so we would need to allocate new pointers to
    // some data, each time a prefix is added.

    char pfx[MAX_STRKEY];
    table_t *ipt = tbl_create(NULL);

    mu_assert(ipt);

    // try to delete non-existing pfx's

    snprintf(pfx, MAX_STRKEY, "1.2.3.4/32");
    mu_assert(tbl_set(ipt, pfx, NULL, NULL));
    mu_assert(ipt->count4 == 1);

    snprintf(pfx, MAX_STRKEY, "11.12.13.14");
    mu_assert(tbl_set(ipt, pfx, NULL, NULL));
    mu_assert(ipt->count4 == 2);

    snprintf(pfx, MAX_STRKEY, "10.11.12.13");
    mu_assert(tbl_set(ipt, pfx, NULL, NULL));
    mu_assert(ipt->count4 == 3);

    // now delete non-existing pfx's

    snprintf(pfx, MAX_STRKEY, "11.12.13.140");
    mu_assert(tbl_del(ipt, pfx, NULL) == 0);
    mu_assert(ipt->count4 == 3);

    snprintf(pfx, MAX_STRKEY, "11.12.130.14");
    mu_assert(tbl_del(ipt, pfx, NULL) == 0);
    mu_assert(ipt->count4 == 3);


    tbl_destroy(&ipt, NULL);
}
