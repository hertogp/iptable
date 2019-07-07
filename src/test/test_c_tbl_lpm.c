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
#include "test_c_tbl_lpm.h"

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

// Helpers

void purge(void *, void **);
void purge(void *args, void **dta)
{
  // user purge data callback func
  // args not needed to free dta (in this case)
  args = args ? args : args;  // no 'unused' args
  if (*dta) free(*dta);
  *dta = NULL;
}

// Tests

void
test_tbl_lpm_good(void)
{

    char pfx[MAX_STRKEY];
    entry_t *itm = NULL;
    table_t *ipt = tbl_create(purge);
    int *a = malloc(sizeof(int)), *b = malloc(sizeof(int));

    *a = 24;
    *b = 30;

    mu_assert(ipt);

    snprintf(pfx, MAX_STRKEY, "1.2.3.0/24");
    mu_assert(tbl_set(ipt, pfx, a, NULL));

    snprintf(pfx, MAX_STRKEY, "1.2.3.0/30");
    mu_assert(tbl_set(ipt, pfx, b, NULL));
    mu_assert(ipt->count4 == 2);

    snprintf(pfx, MAX_STRKEY, "1.2.3.3");
    itm = tbl_lpm(ipt, pfx);
    mu_assert(itm);
    mu_assert(itm->value == b);

    snprintf(pfx, MAX_STRKEY, "1.2.3.5");
    itm = tbl_lpm(ipt, pfx);
    mu_assert(itm);
    mu_assert(itm->value == a);


    tbl_destroy(&ipt, NULL);
}
