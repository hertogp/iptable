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
#include "test_c_tbl.h"    // a generated header file for this test runner

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
  // mandatory user purge data callback func
  // args not needed to free dta (in this case)
  args = args ? args : args;  // no 'unused' args
  if (*dta) free(*dta);
  *dta = NULL;
}

// Tests

void
test_tbl_setup(void)
{
    table_t *ipt;

    mu_assert((ipt = tbl_create(purge)));
    tbl_destroy(&ipt, NULL);
    mu_true(ipt == NULL);
}

void
test_tbl_set_one(void)
{
    table_t *ipt;
    char pfx4[] = "10.10.10.0/24";
    char pfx6[] = "2f:aa:bb::/128";

    ipt = tbl_create(purge);
    mu_assert(tbl_set(ipt, pfx4, mk_data(42), NULL));
    mu_assert(tbl_set(ipt, pfx6, mk_data(62), NULL));

    tbl_destroy(&ipt, NULL);
}

void
test_tbl_set_good(void)
{
    table_t *ipt;
    char pfx[IP6_PFXSTRLEN];

    ipt = tbl_create(purge);

    snprintf(pfx, IP6_PFXSTRLEN, "1.2.3.4/32");
    mu_assert(tbl_set(ipt, pfx, mk_data(1234), NULL));
    mu_assert(ipt->count4 == 1);

    snprintf(pfx, IP6_PFXSTRLEN, "4.3.2.1/32");
    mu_assert(tbl_set(ipt, pfx, mk_data(4321), NULL));
    mu_assert(ipt->count4 == 2);

    snprintf(pfx, IP6_PFXSTRLEN, "10.11.12.13/24");
    mu_assert(tbl_set(ipt, pfx, mk_data(1213), NULL));
    mu_assert(ipt->count4 == 3);

    snprintf(pfx, IP6_PFXSTRLEN, "10.11.12.14");
    mu_assert(tbl_set(ipt, pfx, mk_data(1214), NULL));
    mu_assert(ipt->count4 == 4);

    // adding an existing entry, wont increase the count
    snprintf(pfx, IP6_PFXSTRLEN, "1.2.3.4/32");
    mu_assert(tbl_set(ipt, pfx, mk_data(1235), NULL));
    mu_assert(ipt->count4 == 4);

    tbl_destroy(&ipt, NULL);
}

void
test_tbl_get_good(void)
{
    table_t *ipt = NULL;
    entry_t *e = NULL;
    char pfx[IP6_PFXSTRLEN];

    ipt = tbl_create(purge);

    // set 4 pfx's
    snprintf(pfx, IP6_PFXSTRLEN, "1.2.3.4/32");
    mu_assert(tbl_set(ipt, pfx, mk_data(4), NULL));
    mu_assert(ipt->count4 == 1);

    snprintf(pfx, IP6_PFXSTRLEN, "4.3.2.1/32");
    mu_assert(tbl_set(ipt, pfx, mk_data(1), NULL));
    mu_assert(ipt->count4 == 2);

    snprintf(pfx, IP6_PFXSTRLEN, "10.11.12.13/24");
    mu_assert(tbl_set(ipt, pfx, mk_data(31), NULL));
    mu_assert(ipt->count4 == 3);

    snprintf(pfx, IP6_PFXSTRLEN, "10.11.12.14");
    mu_assert(tbl_set(ipt, pfx, mk_data(41), NULL));
    mu_assert(ipt->count4 == 4);

    // now go get some!

    snprintf(pfx, IP6_PFXSTRLEN, "1.2.3.4/32");
    e = tbl_get(ipt, pfx);
    mu_eq(4, *(int *)e->value, "%d");

    snprintf(pfx, IP6_PFXSTRLEN, "10.11.12.14");
    e = tbl_get(ipt, pfx);
    mu_eq(41, *(int *)e->value, "%d");
    // get/set apply max mask if missing
    snprintf(pfx, IP6_PFXSTRLEN, "10.11.12.14/32");
    e = tbl_get(ipt, pfx);
    mu_eq(41, *(int *)e->value, "%d");

    snprintf(pfx, IP6_PFXSTRLEN, "10.11.12.13/24");
    e = tbl_get(ipt, pfx);
    mu_eq(31, *(int *)e->value, "%d");
    // get/set apply mask prior to operations
    snprintf(pfx, IP6_PFXSTRLEN, "10.11.12.0/24");
    e = tbl_get(ipt, pfx);
    mu_eq(31, *(int *)e->value, "%d");

    snprintf(pfx, IP6_PFXSTRLEN, "4.3.2.1/32");
    e = tbl_get(ipt, pfx);
    mu_eq(1, *(int *)e->value, "%d");

    // setting an existing prefix updates its value, does not increase count
    snprintf(pfx, IP6_PFXSTRLEN, "1.2.3.4/32");
    mu_assert(tbl_set(ipt, pfx, mk_data(42), NULL));
    mu_eq((size_t)4, ipt->count4, "%lu");
    e = tbl_get(ipt, pfx);
    mu_eq(42, *(int *)e->value, "%d");

    tbl_destroy(&ipt, NULL);
}

void
test_tbl_del_good(void)
{
    // these tests don't store any user data.  Freeing a node will free the
    // pointer to the user data so we would need to allocate new pointers to
    // some data, each time a prefix is added.
    table_t *ipt;
    char pfx[IP6_PFXSTRLEN];

    ipt = tbl_create(purge);

    // add one, del one
    snprintf(pfx, IP6_PFXSTRLEN, "1.2.3.4/32");
    mu_assert(tbl_set(ipt, pfx, NULL, NULL));
    mu_assert(tbl_del(ipt, pfx, NULL));
    mu_assert(ipt->count4 == 0);

    // add two, del two
    snprintf(pfx, IP6_PFXSTRLEN, "11.12.13.14");
    mu_assert(tbl_set(ipt, pfx, NULL, NULL));
    snprintf(pfx, IP6_PFXSTRLEN, "10.11.12.13");
    mu_assert(tbl_set(ipt, pfx, NULL, NULL));
    mu_assert(ipt->count4 == 2);

    mu_assert(tbl_del(ipt, pfx, NULL));
    snprintf(pfx, IP6_PFXSTRLEN, "11.12.13.14");
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

    char pfx[IP6_PFXSTRLEN];
    table_t *ipt = tbl_create(purge);

    mu_assert(ipt);

    // try to delete non-existing pfx's

    snprintf(pfx, IP6_PFXSTRLEN, "1.2.3.4/32");
    mu_assert(tbl_set(ipt, pfx, NULL, NULL));
    mu_assert(ipt->count4 == 1);

    snprintf(pfx, IP6_PFXSTRLEN, "11.12.13.14");
    mu_assert(tbl_set(ipt, pfx, NULL, NULL));
    mu_assert(ipt->count4 == 2);

    snprintf(pfx, IP6_PFXSTRLEN, "10.11.12.13");
    mu_assert(tbl_set(ipt, pfx, NULL, NULL));
    mu_assert(ipt->count4 == 3);

    // now delete non-existing pfx's

    snprintf(pfx, IP6_PFXSTRLEN, "11.12.13.140");
    mu_assert(tbl_del(ipt, pfx, NULL) == 0);
    mu_assert(ipt->count4 == 3);

    snprintf(pfx, IP6_PFXSTRLEN, "11.12.130.14");
    mu_assert(tbl_del(ipt, pfx, NULL) == 0);
    mu_assert(ipt->count4 == 3);


    tbl_destroy(&ipt, NULL);
}

void
test_tbl_lpm_good(void)
{
    // these tests don't store any user data.  Freeing a node will free the
    // pointer to the user data so we would need to allocate new pointers to
    // some data, each time a prefix is added.

    char pfx[IP6_PFXSTRLEN];
    entry_t *itm = NULL;
    table_t *ipt = tbl_create(purge);
    int *a = malloc(sizeof(int)), *b = malloc(sizeof(int));

    *a = 24;
    *b = 30;

    mu_assert(ipt);

    snprintf(pfx, IP6_PFXSTRLEN, "1.2.3.0/24");
    mu_assert(tbl_set(ipt, pfx, a, NULL));

    snprintf(pfx, IP6_PFXSTRLEN, "1.2.3.0/30");
    mu_assert(tbl_set(ipt, pfx, b, NULL));
    mu_assert(ipt->count4 == 2);

    snprintf(pfx, IP6_PFXSTRLEN, "1.2.3.3");
    itm = tbl_lpm(ipt, pfx);
    mu_assert(itm);
    mu_assert(itm->value == b);

    snprintf(pfx, IP6_PFXSTRLEN, "1.2.3.5");
    itm = tbl_lpm(ipt, pfx);
    mu_assert(itm);
    mu_assert(itm->value == a);


    tbl_destroy(&ipt, NULL);
}
