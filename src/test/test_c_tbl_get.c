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
#include "test_c_tbl_get.h"

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

int *mk_data(int);
void purge(void *, void **);

int *mk_data(int num) {
  int *value = calloc(1, sizeof(int));
  *value = num;
  return value;
}

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
test_tbl_get_good(void)
{
    table_t *ipt = NULL;
    entry_t *e = NULL;
    char pfx[MAX_STRKEY];

    ipt = tbl_create(purge);

    // set 4 pfx's
    snprintf(pfx, MAX_STRKEY, "1.2.3.4/32");
    mu_assert(tbl_set(ipt, pfx, mk_data(4), NULL));
    mu_assert(ipt->count4 == 1);

    snprintf(pfx, MAX_STRKEY, "4.3.2.1/32");
    mu_assert(tbl_set(ipt, pfx, mk_data(1), NULL));
    mu_assert(ipt->count4 == 2);

    snprintf(pfx, MAX_STRKEY, "10.11.12.13/24");
    mu_assert(tbl_set(ipt, pfx, mk_data(31), NULL));
    mu_assert(ipt->count4 == 3);

    snprintf(pfx, MAX_STRKEY, "10.11.12.14");
    mu_assert(tbl_set(ipt, pfx, mk_data(41), NULL));
    mu_assert(ipt->count4 == 4);

    // now go get some!

    snprintf(pfx, MAX_STRKEY, "1.2.3.4/32");
    e = tbl_get(ipt, pfx);
    mu_eq(4, *(int *)e->value, "%d");

    snprintf(pfx, MAX_STRKEY, "10.11.12.14");
    e = tbl_get(ipt, pfx);
    mu_eq(41, *(int *)e->value, "%d");
    // get/set apply max mask if missing
    snprintf(pfx, MAX_STRKEY, "10.11.12.14/32");
    e = tbl_get(ipt, pfx);
    mu_eq(41, *(int *)e->value, "%d");

    snprintf(pfx, MAX_STRKEY, "10.11.12.13/24");
    e = tbl_get(ipt, pfx);
    mu_eq(31, *(int *)e->value, "%d");
    // get/set apply mask prior to operations
    snprintf(pfx, MAX_STRKEY, "10.11.12.0/24");
    e = tbl_get(ipt, pfx);
    mu_eq(31, *(int *)e->value, "%d");

    snprintf(pfx, MAX_STRKEY, "4.3.2.1/32");
    e = tbl_get(ipt, pfx);
    mu_eq(1, *(int *)e->value, "%d");

    // setting an existing prefix updates its value, does not increase count
    snprintf(pfx, MAX_STRKEY, "1.2.3.4/32");
    mu_assert(tbl_set(ipt, pfx, mk_data(42), NULL));
    mu_eq((size_t)4, ipt->count4, "%lu");
    e = tbl_get(ipt, pfx);
    mu_eq(42, *(int *)e->value, "%d");

    tbl_destroy(&ipt, NULL);
}
