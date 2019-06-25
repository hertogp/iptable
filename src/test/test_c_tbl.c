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

    // create an ipt table with a purge function
    mu_assert((ipt = tbl_create(purge)));
    mu_assert(tbl_destroy(&ipt, NULL));
    mu_true(ipt == NULL);

    // create/destroy an ipt table without a purge function
    mu_assert((ipt = tbl_create(NULL)));
    mu_assert(tbl_destroy(&ipt, NULL));
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
    char pfx[MAX_STRKEY];

    ipt = tbl_create(purge);

    snprintf(pfx, MAX_STRKEY, "1.2.3.4/32");
    mu_assert(tbl_set(ipt, pfx, mk_data(1234), NULL));
    mu_assert(ipt->count4 == 1);

    snprintf(pfx, MAX_STRKEY, "4.3.2.1/32");
    mu_assert(tbl_set(ipt, pfx, mk_data(4321), NULL));
    mu_assert(ipt->count4 == 2);

    snprintf(pfx, MAX_STRKEY, "10.11.12.13/24");
    mu_assert(tbl_set(ipt, pfx, mk_data(1213), NULL));
    mu_assert(ipt->count4 == 3);

    snprintf(pfx, MAX_STRKEY, "10.11.12.14");
    mu_assert(tbl_set(ipt, pfx, mk_data(1214), NULL));
    mu_assert(ipt->count4 == 4);

    // adding an existing entry, wont increase the count
    snprintf(pfx, MAX_STRKEY, "1.2.3.4/32");
    mu_assert(tbl_set(ipt, pfx, mk_data(1235), NULL));
    mu_assert(ipt->count4 == 4);

    tbl_destroy(&ipt, NULL);
}

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

void
test_tbl_del_good(void)
{
    // these tests don't store any user data.  Freeing a node will free the
    // pointer to the user data so we would need to allocate new pointers to
    // some data, each time a prefix is added.
    table_t *ipt;
    char pfx[MAX_STRKEY];

    ipt = tbl_create(purge);

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
    table_t *ipt = tbl_create(purge);

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

int cb_sum(struct radix_node *rn, void *runtotal);
int
cb_sum(struct radix_node *rn, void *runtotal)
{
    // return 0 on success, else walktree will quit walking
    // cb_sum assumes both runtotal and entry->value are (int *)

    if (rn == NULL || runtotal == NULL) return 1; // breaks off the walkabout

    entry_t *itm = (entry_t *)rn;
    *(int *)runtotal += *(int *)itm->value;

    return 0;
}

void
test_tbl_walk_good(void)
{
    // these tests store int data from a int char on the stack, rather than the
    // heap, so we donot need a purge fuction
    char pfx[MAX_STRKEY];
    int number[5] = {1, 2, 4, 8, 16};
    int total[1] = {0};
    table_t *ipt = tbl_create(NULL);

    mu_assert(ipt);

    // add a few prefixes

    snprintf(pfx, MAX_STRKEY, "0.0.0.0/0");
    mu_assert(tbl_set(ipt, pfx, number+0, NULL));

    snprintf(pfx, MAX_STRKEY, "1.1.1.1/8");
    mu_assert(tbl_set(ipt, pfx, number+1, NULL));

    snprintf(pfx, MAX_STRKEY, "2.2.2.2/16");
    mu_assert(tbl_set(ipt, pfx, number+2, NULL));

    snprintf(pfx, MAX_STRKEY, "3.3.3.3/24");
    mu_assert(tbl_set(ipt, pfx, number+3, NULL));

    snprintf(pfx, MAX_STRKEY, "4.4.4.4/32");
    mu_assert(tbl_set(ipt, pfx, number+4, NULL));

    // we should have 5 prefixes
    mu_assert(5 == ipt->count4);

    // walkabout and sum the values associated with all prefixes
    mu_assert(tbl_walk(ipt, cb_sum, total));
    mu_assert(1+2+4+8+16 == *total);

    tbl_destroy(&ipt, NULL);

    return;
}

void
test_tbl_less_good(void)
{
    // these tests store int data from a int char on the stack, rather than the
    // heap, so we donot need a purge fuction
    char pfx[MAX_STRKEY];
    int number[5] = {1, 2, 4, 8, 16};
    int total[1] = {0}, include = 0;
    table_t *ipt = tbl_create(NULL);

    mu_assert(ipt);

    // add a few prefixes

    snprintf(pfx, MAX_STRKEY, "0.0.0.0/0");
    mu_assert(tbl_set(ipt, pfx, number+0, NULL));

    snprintf(pfx, MAX_STRKEY, "10.0.0.0/8");
    mu_assert(tbl_set(ipt, pfx, number+1, NULL));
    snprintf(pfx, MAX_STRKEY, "11.0.0.0/8");
    mu_assert(tbl_set(ipt, pfx, number+4, NULL));

    snprintf(pfx, MAX_STRKEY, "10.10.0.0/16");
    mu_assert(tbl_set(ipt, pfx, number+2, NULL));
    snprintf(pfx, MAX_STRKEY, "11.10.0.0/16");
    mu_assert(tbl_set(ipt, pfx, number+4, NULL));

    snprintf(pfx, MAX_STRKEY, "10.10.10.0/24");
    mu_assert(tbl_set(ipt, pfx, number+3, NULL));
    snprintf(pfx, MAX_STRKEY, "11.10.10.0/24");
    mu_assert(tbl_set(ipt, pfx, number+4, NULL));

    snprintf(pfx, MAX_STRKEY, "10.10.10.128/25");
    mu_assert(tbl_set(ipt, pfx, number+4, NULL));
    snprintf(pfx, MAX_STRKEY, "11.10.10.128/25");
    mu_assert(tbl_set(ipt, pfx, number+4, NULL));

    mu_assert(9 == ipt->count4);

    // walkabout and sum the values associated with all prefixes

    // less than /32
    include = 0; // don't include search pfx in results
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.129", include, cb_sum, total));
    mu_eq(1+2+4+8+16, *total, "%d");

    include = 1; // include /32 won't change anything, it's not in iptable
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.129", include, cb_sum, total));
    mu_eq(1+2+4+8+16, *total, "%d");

    // 11.x.y.z crosscheck, should find 0/0 & 4 * an 11.10.10.x/y prefix
    include = 0; // don't include search pfx in results
    *total = 0;
    mu_assert(tbl_less(ipt, "11.10.10.129", include, cb_sum, total));
    mu_eq(1+16+16+16+16, *total, "%d");

    // less than /25
    include = 0; // don't include search pfx in results
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.128/25", include, cb_sum, total));
    mu_eq(1+2+4+8+0, *total, "%d");

    include = 1; // now include search pfx in results
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.128/25", include, cb_sum, total));
    mu_eq(1+2+4+8+16, *total, "%d");

    // less than /24
    include = 0; // don't include search pfx in results
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.128/24", include, cb_sum, total));
    mu_eq(1+2+4+0+0, *total, "%d");

    include = 1; // now include search pfx in results
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.128/24", include, cb_sum, total));
    mu_eq(1+2+4+8+0, *total, "%d");

    // less than /16
    include = 0; // don't include search pfx in results
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.128/16", include, cb_sum, total));
    mu_eq(1+2+0+0+0, *total, "%d");

    include = 1; // now include search pfx in results
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.128/16", include, cb_sum, total));
    mu_eq(1+2+4+0+0, *total, "%d");

    // less than /8
    include = 0; // don't include search pfx in results
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.128/8", include, cb_sum, total));
    mu_eq(1+0+0+0+0, *total, "%d");

    include = 1; // now include search pfx in results
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.128/8", include, cb_sum, total));
    mu_eq(1+2+0+0+0, *total, "%d");

    // less than /8
    include = 0; // don't include search pfx in results
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.128/0", include, cb_sum, total));
    mu_eq(0+0+0+0+0, *total, "%d");

    include = 1; // now include search pfx in results
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.128/0", include, cb_sum, total));
    mu_eq(1+0+0+0+0, *total, "%d");

    tbl_destroy(&ipt, NULL);
}

int cb_count(struct radix_node *rn, void *runtotal);
int
cb_count(struct radix_node *rn, void *runtotal)
{
    // return 0 on success, else walktree will quit walking
    // cb_count assumes both runtotal and entry->value are (int *)
    // `-> counts the number of times cb_count is called

    if (rn == NULL || runtotal == NULL) return 1; // breaks off the walkabout

    *(int *)runtotal += 1;

    return 0;
}

void
test_tbl_less_traversal(void)
{
    // these tests store int data from a int char on the stack, rather than the
    // heap, so we donot need a purge fuction
    // Check how many times the callback is called
    char pfx[MAX_STRKEY];
    int number[5] = {1, 2, 4, 8, 16};
    int total[1] = {0}, include = 0;
    table_t *ipt = tbl_create(NULL);

    mu_assert(ipt);

    // add a few prefixes

    snprintf(pfx, MAX_STRKEY, "0.0.0.0/0");
    mu_assert(tbl_set(ipt, pfx, number+0, NULL));

    snprintf(pfx, MAX_STRKEY, "10.0.0.0/8");
    mu_assert(tbl_set(ipt, pfx, number+1, NULL));
    snprintf(pfx, MAX_STRKEY, "11.0.0.0/8");
    mu_assert(tbl_set(ipt, pfx, number+4, NULL));

    snprintf(pfx, MAX_STRKEY, "10.10.0.0/16");
    mu_assert(tbl_set(ipt, pfx, number+2, NULL));
    snprintf(pfx, MAX_STRKEY, "11.10.0.0/16");
    mu_assert(tbl_set(ipt, pfx, number+4, NULL));

    snprintf(pfx, MAX_STRKEY, "10.10.10.0/24");
    mu_assert(tbl_set(ipt, pfx, number+3, NULL));
    snprintf(pfx, MAX_STRKEY, "11.10.10.0/24");
    mu_assert(tbl_set(ipt, pfx, number+4, NULL));

    snprintf(pfx, MAX_STRKEY, "10.10.10.128/25");
    mu_assert(tbl_set(ipt, pfx, number+4, NULL));
    snprintf(pfx, MAX_STRKEY, "11.10.10.128/25");
    mu_assert(tbl_set(ipt, pfx, number+4, NULL));

    mu_assert(9 == ipt->count4);

    // walkabout and count the num of times the callback is called

    // less than /32
    include = 0; // don't include search pfx in results
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.129", include, cb_count, total));
    mu_eq(5, *total, "%d");

    include = 1; // won't change anything, since the /32 is not in the tree
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.129", include, cb_count, total));
    mu_eq(5, *total, "%d");

    // less than /25
    include = 0; // don't include search pfx in results
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.129/25", include, cb_count, total));
    mu_eq(4, *total, "%d");

    include = 1; // won't change anything, since the /32 is not in the tree
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.129/25", include, cb_count, total));
    mu_eq(5, *total, "%d");

    // less than /24
    include = 0; // don't include search pfx in results
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.129/24", include, cb_count, total));
    mu_eq(3, *total, "%d");

    include = 1; // won't change anything, since the /32 is not in the tree
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.129/24", include, cb_count, total));
    mu_eq(4, *total, "%d");

    // less than /16
    include = 0; // don't include search pfx in results
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.129/16", include, cb_count, total));
    mu_eq(2, *total, "%d");

    include = 1; // won't change anything, since the /32 is not in the tree
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.129/16", include, cb_count, total));
    mu_eq(3, *total, "%d");

    // less than /8
    include = 0; // don't include search pfx in results
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.129/8", include, cb_count, total));
    mu_eq(1, *total, "%d");

    include = 1; // won't change anything, since the /32 is not in the tree
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.129/8", include, cb_count, total));
    mu_eq(2, *total, "%d");

    // less than /0
    include = 0; // don't include search pfx in results
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.129/0", include, cb_count, total));
    mu_eq(0, *total, "%d");

    include = 1; // won't change anything, since the /32 is not in the tree
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.129/0", include, cb_count, total));
    mu_eq(1, *total, "%d");

    tbl_destroy(&ipt, NULL);
}

void
test_tbl_more_good(void)
{
    // these tests store int data from a int char on the stack, rather than the
    // heap, so we donot need a purge fuction
    char pfx[MAX_STRKEY];
    int number[5] = {1, 2, 4, 8, 16};
    int total[1] = {0}, include = 0;
    table_t *ipt = tbl_create(NULL);

    mu_assert(ipt);

    // add a few prefixes

    snprintf(pfx, MAX_STRKEY, "0.0.0.0/0");
    mu_assert(tbl_set(ipt, pfx, number+0, NULL));
    snprintf(pfx, MAX_STRKEY, "10.0.0.0/8");
    mu_assert(tbl_set(ipt, pfx, number+1, NULL));
    snprintf(pfx, MAX_STRKEY, "10.10.0.0/16");
    mu_assert(tbl_set(ipt, pfx, number+2, NULL));
    snprintf(pfx, MAX_STRKEY, "10.10.10.0/24");
    mu_assert(tbl_set(ipt, pfx, number+3, NULL));
    snprintf(pfx, MAX_STRKEY, "10.10.10.128/32");
    mu_assert(tbl_set(ipt, pfx, number+4, NULL));

    snprintf(pfx, MAX_STRKEY, "11.0.0.0/8");
    mu_assert(tbl_set(ipt, pfx, number+4, NULL));
    snprintf(pfx, MAX_STRKEY, "11.10.0.0/16");
    mu_assert(tbl_set(ipt, pfx, number+4, NULL));
    snprintf(pfx, MAX_STRKEY, "11.10.10.0/24");
    mu_assert(tbl_set(ipt, pfx, number+4, NULL));
    snprintf(pfx, MAX_STRKEY, "11.10.10.128/32");
    mu_assert(tbl_set(ipt, pfx, number+4, NULL));

    mu_assert(9 == ipt->count4);

    // more than /32
    include = 0; // don't include search pfx in results
    *total = 0;
    mu_assert(tbl_more(ipt, "10.10.10.128", include, cb_sum, total));
    mu_eq(0+0+0+0+0, *total, "%d");

    include = 1; // this time include search key (host ip) i/t results
    *total = 0;
    mu_assert(tbl_more(ipt, "10.10.10.128", include, cb_sum, total));
    mu_eq(0+0+0+0+16, *total, "%d");

    // more than /24
    include = 0; // don't include search pfx in results
    *total = 0;
    mu_assert(tbl_more(ipt, "10.10.10.128/24", include, cb_sum, total));
    mu_eq(0+0+0+0+16, *total, "%d");

    include = 1; // this time include search key (host ip) i/t results
    *total = 0;
    mu_assert(tbl_more(ipt, "10.10.10.128/24", include, cb_sum, total));
    mu_eq(0+0+0+8+16, *total, "%d");

    // more than /16
    include = 0; // don't include search pfx in results
    *total = 0;
    mu_assert(tbl_more(ipt, "10.10.10.128/16", include, cb_sum, total));
    mu_eq(0+0+0+8+16, *total, "%d");

    include = 1; // this time include search key (host ip) i/t results
    *total = 0;
    mu_assert(tbl_more(ipt, "10.10.10.128/16", include, cb_sum, total));
    mu_eq(0+0+4+8+16, *total, "%d");

    // more than /8
    include = 0; // don't include search pfx in results
    *total = 0;
    mu_assert(tbl_more(ipt, "10.10.10.128/8", include, cb_sum, total));
    mu_eq(0+0+4+8+16, *total, "%d");

    include = 1; // this time include search key (host ip) i/t results
    *total = 0;
    mu_assert(tbl_more(ipt, "10.10.10.128/8", include, cb_sum, total));
    mu_eq(0+2+4+8+16, *total, "%d");

    // more than /0
    include = 0; // anything more specific than /0, means all pfx's but 0/0
    *total = 0;  // so all 4 11.x.y.z/m (4*16) and all 10.x.y.z/m (1+2+4+8+16)
    mu_assert(tbl_more(ipt, "10.10.10.128/0", include, cb_sum, total));
    mu_eq(0+2+4+8+16+4*16, *total, "%d");

    include = 1; // this time include 0/0 as well
    *total = 0;
    mu_assert(tbl_more(ipt, "10.10.10.128/0", include, cb_sum, total));
    mu_eq(1+2+4+8+16+4*16, *total, "%d");

    tbl_destroy(&ipt, NULL);
}

void
test_tbl_more_again(void)
{
    // these tests store int data from a int char on the stack, rather than the
    // heap, so we donot need a purge fuction
    char pfx[MAX_STRKEY];
    int number[7] = {1, 2, 4, 8, 16, 32, 64};
    int total[1] = {0}, include = 0;
    table_t *ipt = tbl_create(NULL);

    mu_assert(ipt);

    // add a few prefixes

    snprintf(pfx, MAX_STRKEY, "1.1.1.0/24");
    mu_assert(tbl_set(ipt, pfx, number+0, NULL));

    snprintf(pfx, MAX_STRKEY, "1.1.1.0/25");
    mu_assert(tbl_set(ipt, pfx, number+1, NULL));
    snprintf(pfx, MAX_STRKEY, "1.1.1.128/25");
    mu_assert(tbl_set(ipt, pfx, number+2, NULL));

    snprintf(pfx, MAX_STRKEY, "1.1.1.0/26");
    mu_assert(tbl_set(ipt, pfx, number+3, NULL));
    snprintf(pfx, MAX_STRKEY, "1.1.1.64/26");
    mu_assert(tbl_set(ipt, pfx, number+4, NULL));
    snprintf(pfx, MAX_STRKEY, "1.1.1.128/26");
    mu_assert(tbl_set(ipt, pfx, number+5, NULL));
    snprintf(pfx, MAX_STRKEY, "1.1.1.192/26");
    mu_assert(tbl_set(ipt, pfx, number+6, NULL));

    mu_assert(7 == ipt->count4);

    // more than /24
    include = 0; // search pfx /24 is excluded
    *total = 0;
    mu_assert(tbl_more(ipt, "1.1.1.0/24", include, cb_sum, total));
    mu_eq(0+2+4+8+16+32+64, *total, "%d");

    tbl_destroy(&ipt, NULL);
}

void
test_tbl_stackpush_pop(void)
{
    // check the typed Element stack associated with an iptable instance
    int num[5] = {0,1,2,3,4};
    table_t *ipt = tbl_create(NULL);

    mu_assert(ipt);

    tbl_stackpush(ipt, 0, &num[0]);
    tbl_stackpush(ipt, 1, &num[1]);
    tbl_stackpush(ipt, 2, &num[2]);
    tbl_stackpush(ipt, 3, &num[3]);
    tbl_stackpush(ipt, 4, &num[4]);
    mu_assert(ipt->size == 5);
    mu_assert(ipt->top != NULL);

    mu_assert(*(int *)ipt->top->elm == 4);
    tbl_stackpop(ipt);
    mu_assert(*(int *)ipt->top->elm == 3);
    tbl_stackpop(ipt);
    mu_assert(*(int *)ipt->top->elm == 2);
    tbl_stackpop(ipt);
    mu_assert(*(int *)ipt->top->elm == 1);
    tbl_stackpop(ipt);
    mu_assert(*(int *)ipt->top->elm == 0);
    tbl_stackpop(ipt);

    mu_assert(ipt->size == 0);
    mu_assert(ipt->top == NULL);

    tbl_destroy(&ipt, NULL);
}

void
test_tbl_stack_pop(void)
{
    // check the typed Element stack associated with an iptable instance
    table_t *ipt = tbl_create(NULL);
    mu_assert(ipt);

    mu_false(tbl_stackpop(ipt));  // popping an empty stack yields 0

    tbl_destroy(&ipt, NULL);
}

void
test_rdx_firstnode(void)
{
    table_t *ipt = tbl_create(NULL);
    mu_assert(ipt);

    mu_assert(rdx_firstnode(ipt, IPT_INET|IPT_INET6));
    mu_assert(ipt->size == 2);
    mu_assert(ipt->top->type == TRDX_NODE_HEAD);
    mu_assert(ipt->top->elm  == ipt->head4);

    mu_assert(tbl_stackpop(ipt));
    mu_assert(ipt->size == 1);
    mu_assert(ipt->top->type == TRDX_NODE_HEAD);
    mu_assert(ipt->top->elm  == ipt->head6);

    tbl_destroy(&ipt, NULL);
}

void
test_rdx_nextnode(void)
{
    struct radix_node_head *rnh = NULL;
    struct radix_mask_head *rmh = NULL;
    int type;
    table_t *ipt = tbl_create(NULL);  // empty but valid iptable instance

    mu_assert(ipt);
    mu_assert(rdx_firstnode(ipt, IPT_INET|IPT_INET6));
    mu_assert(ipt->size == 2);  // [head4 head6]

    // pop head4, its progeny should have been pushed
    mu_assert(rdx_nextnode(ipt, &type, (void **)&rnh));
    // stack -> [head4->rh.rnh_masks head6]
    mu_eq(TRDX_NODE_HEAD, type, "%d");
    mu_assert(ipt->head4 == rnh);
    mu_assert(ipt->size == 2);

    // pop head4's radix_mask_head, no progeny pushed (empty table)
    mu_assert(rdx_nextnode(ipt, &type, (void **)&rmh));
    // stack -> [head6]
    mu_eq(TRDX_MASK_HEAD, type, "%d");
    mu_assert(ipt->head4->rh.rnh_masks == rmh);
    mu_assert(ipt->size == 1);


    // pop head6, its progeny should have been pushed
    mu_assert(rdx_nextnode(ipt, &type, (void **)&rnh));
    // stack -> [head6->rh.rnh_masks]
    mu_eq(TRDX_NODE_HEAD, type, "%d");
    mu_assert(ipt->head6 == rnh);
    mu_assert(ipt->size == 1);

    // pop head6's radix_mask_head, no progeny pushed (empty table)
    mu_assert(rdx_nextnode(ipt, &type, (void **)&rmh));
    // stack -> []
    mu_eq(TRDX_MASK_HEAD, type, "%d");
    mu_assert(ipt->head6->rh.rnh_masks == rmh);
    mu_assert(ipt->size == 0);
    mu_assert(ipt->top == NULL);

    tbl_destroy(&ipt, NULL);
}

void
test_tbl_stack_again(void)
{
    // these tests store int data from a int char on the stack, rather than the
    // heap, so we donot need a purge fuction

    char pfx[MAX_STRKEY];
    int type, types[5] = {0,0,0,0,0}, number[7] = {1, 2, 4, 8, 16, 32, 64};
    int leafs = 0;
    table_t *ipt = tbl_create(NULL);
    void *ptr;

    mu_assert(ipt);

    // add a few prefixes and test number of certain node types

    // 4 ipv4 prefixes, with 4 unique masks
    snprintf(pfx, MAX_STRKEY, "1.1.1.0/24");
    mu_assert(tbl_set(ipt, pfx, number+0, NULL));
    snprintf(pfx, MAX_STRKEY, "1.1.1.0/25");  // dupedkey w/ different mask
    mu_assert(tbl_set(ipt, pfx, number+1, NULL));
    snprintf(pfx, MAX_STRKEY, "1.1.1.0/26");  // dupedkey w/ different mask
    mu_assert(tbl_set(ipt, pfx, number+1, NULL));
    snprintf(pfx, MAX_STRKEY, "2.1.1.0/27");
    mu_assert(tbl_set(ipt, pfx, number+2, NULL));

    // 2 ipv6 prefixes, with 2 unique masks
    snprintf(pfx, MAX_STRKEY, "2f:aa:bb::/120");
    mu_assert(tbl_set(ipt, pfx, number+5, NULL));
    snprintf(pfx, MAX_STRKEY, "3f:aa:bb::/128");
    mu_assert(tbl_set(ipt, pfx, number+6, NULL));

    leafs = 0;
    mu_assert(rdx_firstnode(ipt, IPT_INET|IPT_INET6));
    while(ipt->top) {
        mu_assert(rdx_nextnode(ipt, &type, &ptr));
        if (type > -1 && type < 5)
            types[type] += 1;
        else
            mu_false("unknown TRDX-type encountered!");
        if (type == TRDX_NODE &&
            RDX_ISLEAF(((struct radix_node *)ptr)) &&
            !RDX_ISROOT(((struct radix_node *)ptr)))
                leafs += 1;
    }
    // stack must exhausted
    mu_assert(ipt->top == NULL);
    mu_eq((size_t)0, ipt->size, "stack size (%lu)");

    // The tree will have:
    // - 1 ipv4 radix_node_head and 1 ipv4 radix_mask_head, plus
    // - 1 ipv6 radix_node_head and 1 ipv6 radix_mask_head
    mu_eq(1+1, types[TRDX_NODE_HEAD], "%d radix_node_head's");
    mu_eq(1+1, types[TRDX_MASK_HEAD], "%d radix_mask_head's");

    // The tree will have:
    // - 3 ipv4 prefix-leafs + 3 ipv4 mask-leafs (num of different ipv4 masks)
    // - 2 ipv6 prefix-leafs + 2 ipv6 mask-leafs (num of different ipv6 masks)
    mu_eq(4+4+2+2, leafs, "%d node leafs");

    tbl_destroy(&ipt, NULL);
}
