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
#include "test_ipt_tbl_mu.h"   // a generated header file for this test runner

// free_userdata callback
// In this unit test, our data is a simple int, so entry->value is a pointer
// to int.
void purge(void **);
void purge(void **dta)
{
  printf("purge -1-> %d @ %p\n", *(int *)*dta, *dta);
  if(*dta) free(*dta);
  *dta = NULL;
  printf("purge -2-> %p\n", *dta);
}

void
test_tbl_setup(void)
{
    table_t *ipt;

    mu_assert((ipt = tbl_create(purge)));
    tbl_destroy(&ipt);
    mu_true(ipt == NULL);
}

void
test_tbl_add_one(void)
{
    table_t *ipt;
    int *value4 = malloc(sizeof(int));  // freed by tbl_destroy
    int *value6 = malloc(sizeof(int));  // freed by tbl_destroy
    *value4 = 42;
    *value6 = 62;
    char pfx4[] = "10.10.10.0/24";
    char pfx6[] = "2f:aa:bb::/128";

    ipt = tbl_create(purge);
    mu_assert(tbl_add(ipt, pfx4, value4));
    mu_assert(tbl_add(ipt, pfx6, value6));

    tbl_destroy(&ipt);
}

void
test_tbl_add_good(void)
{
    // these tests don't store any user data.  Freeing a node will free the
    // pointer to the user data so we would need to allocate new pointers to
    // some data, each time a prefix is added.
    table_t *ipt;
    char pfx[IP6_PFXSTRLEN];

    ipt = tbl_create(purge);

    snprintf(pfx, IP6_PFXSTRLEN, "1.2.3.4/32");
    mu_assert(tbl_add(ipt, pfx, NULL));
    mu_assert(ipt->count4 == 1);

    snprintf(pfx, IP6_PFXSTRLEN, "4.3.2.1/32");
    mu_assert(tbl_add(ipt, pfx, NULL));
    mu_assert(ipt->count4 == 2);

    snprintf(pfx, IP6_PFXSTRLEN, "10.11.12.13/24");
    mu_assert(tbl_add(ipt, pfx, NULL));
    mu_assert(ipt->count4 == 3);

    snprintf(pfx, IP6_PFXSTRLEN, "10.11.12.14");
    mu_assert(tbl_add(ipt, pfx, NULL));
    mu_assert(ipt->count4 == 4);

    // adding an existing entry, wont increase the count
    snprintf(pfx, IP6_PFXSTRLEN, "1.2.3.4/32");
    mu_assert(tbl_add(ipt, pfx, NULL));
    mu_assert(ipt->count4 == 4);

    tbl_destroy(&ipt);
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
    mu_assert(tbl_add(ipt, pfx, NULL));
    mu_assert(tbl_del(ipt, pfx));
    mu_assert(ipt->count4 == 0);

    // add two, del two
    snprintf(pfx, IP6_PFXSTRLEN, "11.12.13.14");
    mu_assert(tbl_add(ipt, pfx, NULL));
    snprintf(pfx, IP6_PFXSTRLEN, "10.11.12.13");
    mu_assert(tbl_add(ipt, pfx, NULL));
    mu_assert(ipt->count4 == 2);

    mu_assert(tbl_del(ipt, pfx));
    snprintf(pfx, IP6_PFXSTRLEN, "11.12.13.14");
    mu_assert(tbl_del(ipt, pfx));
    mu_assert(ipt->count4 == 0);


    tbl_destroy(&ipt);
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
    mu_assert(tbl_add(ipt, pfx, NULL));
    mu_assert(ipt->count4 == 1);

    snprintf(pfx, IP6_PFXSTRLEN, "11.12.13.14");
    mu_assert(tbl_add(ipt, pfx, NULL));
    mu_assert(ipt->count4 == 2);

    snprintf(pfx, IP6_PFXSTRLEN, "10.11.12.13");
    mu_assert(tbl_add(ipt, pfx, NULL));
    mu_assert(ipt->count4 == 3);

    // now delete non-existing pfx's

    snprintf(pfx, IP6_PFXSTRLEN, "11.12.13.140");
    mu_assert(tbl_del(ipt, pfx) == 0);
    mu_assert(ipt->count4 == 3);

    snprintf(pfx, IP6_PFXSTRLEN, "11.12.130.14");
    mu_assert(tbl_del(ipt, pfx) == 0);
    mu_assert(ipt->count4 == 3);


    tbl_destroy(&ipt);
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
    mu_assert(tbl_add(ipt, pfx, a));

    snprintf(pfx, IP6_PFXSTRLEN, "1.2.3.0/30");
    mu_assert(tbl_add(ipt, pfx, b));
    mu_assert(ipt->count4 == 2);

    snprintf(pfx, IP6_PFXSTRLEN, "1.2.3.3");
    itm = tbl_lpm(ipt, pfx);
    mu_assert(itm);
    mu_assert(itm->value == b);

    snprintf(pfx, IP6_PFXSTRLEN, "1.2.3.5");
    itm = tbl_lpm(ipt, pfx);
    mu_assert(itm);
    mu_assert(itm->value == a);


    tbl_destroy(&ipt);
}
