#include <sys/types.h>       // required for u_char
#include <stdlib.h>          // malloc
#include <netinet/in.h>      // sockaddr_in

#include "radix.h"           // the radix tree
#include "iptable.h"         // iptable layered on top of radix.c

#include "minunit.h"         // the mu_test macros
#include "test_c_tbl_create.h"

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
test_tbl_create_with_purge(void)
{
    table_t *ipt;

    // create an ipt table with a purge function
    mu_assert((ipt = tbl_create(purge)));
    mu_assert(tbl_destroy(&ipt, NULL));
    mu_true(ipt == NULL);
}

void
test_tbl_create_no_purge(void)
{
    // create/destroy an ipt table without a purge function

    table_t *ipt;

    mu_assert((ipt = tbl_create(NULL)));
    mu_assert(tbl_destroy(&ipt, NULL));
    mu_true(ipt == NULL);

}

