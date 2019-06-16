#include <stdio.h>        // printf
#include <sys/types.h>    // u_char
/* #include <sys/socket.h> */
#include <stddef.h>       // offsetof
#include <stdlib.h>       // malloc / calloc
// #include <netinet/in.h>   // sockaddr_in
#include <arpa/inet.h>    // inet_pton and friends
#include <string.h>       // strlen
#include <ctype.h>        // isdigit

#include "radix.h"
#include "iptable.h"

/* static char rn_zeros[RDX_MAX_KEYLEN]; */
// all_ones used as max mask in some cases where none was supplied
uint8_t  all_ones[RDX_MAX_KEYLEN] = {
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
};

// -- helpers

// -- KEY funcs
uint8_t *
key_alloc(int af)
{
    uint8_t *key = NULL, keylen = 0;

    if (af == AF_INET)
        keylen = 1 + IP4_KEYLEN;               // 5
    else if (af == AF_INET6)
        keylen = 1 + IP6_KEYLEN;               // 17
    else return NULL;                          // unknown AF family

    key = calloc(sizeof(uint8_t), keylen);     // zero initialized
    if (key) IPT_KEYLEN(key) = keylen;         // set LEN byte

    return key;
}

uint8_t *
key_copy(uint8_t *src)
{
    // assumes proper LEN-byte in the src byte array
    uint8_t *key = key_alloc(KEY_AF_FAM(src));
    if (key == NULL) return NULL;
    memcpy(key, src, IPT_KEYLEN(key));

    return key;
}

uint8_t *
key_bystr(const char *s, int *mlen, int *af, uint8_t *dst)
{
    // Store string s' binary key in dst. Returns NULL on failure
    // Also sets mlen and  af. mlen=-1 when no mask was supplied
    // assumes dst -> uint8_t dst[MAX_BINKEY], to fit both ipv4/ipv6

    *mlen = -1;                                   // the mask as length
    *af = AF_UNSPEC;
    char buf[MAX_STRKEY];

    int a, b, c, d, n;
    char *slash;

    if (dst == NULL) return NULL;                 // lame dst buffer check
    if (s == NULL) return NULL;                   // need prefix string
    if (strlen(s) > MAX_STRKEY) return NULL;   // invalid string length
    if (strlen(s) < 1) return NULL;               // invalid string length

    slash = strchr(s, '/');                       // pick up mask, if any
    if (slash) {
        sscanf(slash, "/%i%n", mlen, &n);
        if (*(slash + n)) return NULL;            // no valid /mask ending
        if (*mlen < 0) return NULL;               // dito
    }

    if (STR_IS_IP6(s)) {
        if (*mlen > IP6_MAXMASK) return NULL;
        strncpy(buf, s, INET6_ADDRSTRLEN);
        if(slash) buf[slash - s]='\0';
        IPT_KEYLEN(dst) = FAM_BINKEY(AF_INET6);
        inet_pton(AF_INET6, buf, IPT_KEYPTR(dst));
        *af = AF_INET6;
        return dst;

    } else {
        // use scanf to support shorthand notation: 10.10/16 is 10.10.0.0/16
        // %i scans hex (0x..), octal (0..) or base 10 ([1-9]..)
        if (strlen(s) > IP4_PFXSTRLEN) return NULL;
        if (*mlen > IP4_MAXMASK) return NULL;
        if (!isdigit(*s)) return NULL; // must start with 0x, 0, or [1-9]

        a = b = c = d = n = 0;
        sscanf(s, "%i%n.%i%n.%i%n.%i%n", &a, &n, &b, &n, &c, &n, &d, &n);
        if(n > 0 && *(s+n) != '/' && *(s+n) != '\0')
            return NULL; // malformed digits (or too many)

        // check validity of digits
        if(a < 0 || a > 255) return NULL;
        if(b < 0 || b > 255) return NULL;
        if(c < 0 || c > 255) return NULL;
        if(d < 0 || d > 255) return NULL;

        IPT_KEYLEN(dst) = FAM_BINKEY(AF_INET);
        *(dst+1) = a;  // bigendian, so 'a' goes first
        *(dst+2) = b;
        *(dst+3) = c;
        *(dst+4) = d;
        *af = AF_INET;
        return dst;
    }

    return NULL;  // failed
}

uint8_t *
key_bylen(int af, int mlen, uint8_t *buf)
{
    // create key by masklength, store result in buf.  Retuns NULL on failure.
    // buf is typically uint8_t buf[MAX_BINKEY]
    uint8_t *cp;
    int keylen;

    // check: valid mask length, corresponding to valid AF_family
    if(af == AF_INET6) {
        mlen = mlen == -1 ? IP6_MAXMASK : mlen;
        if (mlen < 0 || mlen > IP6_MAXMASK) return NULL;
        keylen = 1 + IP6_KEYLEN;
    } else if (af == AF_INET) {
        mlen = mlen == -1 ? IP4_MAXMASK : mlen;
        if (mlen < 0 || mlen > IP4_MAXMASK) return NULL;
        keylen = 1 + IP4_KEYLEN;
    } else return NULL;

    IPT_KEYLEN(buf) = keylen;
    cp = IPT_KEYPTR(buf);
    while (--keylen > 0) {                              // set all key bytes
        *(cp++) = mlen > 8 ? 0xff : ~((1 << (8 - mlen))-1);
        mlen = mlen > 8 ? mlen - 8 : 0;
    }

    return buf;
}

int key_tolen(void *key)
{
    // counts the nr of consequtive 1-bits starting with the MSB first.
    // - a radix mask key's KEYLEN indicates the num of non-zero bytes in the
    //   mask.  Hence, it may be smaller than 1+IP{4,6}_KEYLEN

    int size = 0, cnt = 0;
    uint8_t *cp;

    // sanity check
    if (key == NULL) return -1;

    size = IPT_KEYLEN((uint8_t *)key);        // nr of bytes in key
    cp = IPT_KEYPTR((uint8_t *)key);          // pick up start of key

    // count bits of all-1's bytes
    for(; --size > 0 && *cp == 0xff; cnt += 8, cp++)
        ;

    if (size <= 0) return cnt;               // got them all

    // count 1-bits from MSB to LSB stopping at first 0-bit
    for (uint8_t m=0x80; m > 0 && *cp & m; m = m >> 1, cnt++)
        ;

    return cnt;
}

const char *
key_tostr(void *k, char *s)
{
    // uses void *k so rn-keys (char *) are handled as well
    // user supplied buffer s must be large enough to hold an IPv6 prefix
    uint8_t *key = k;

    if (s == NULL || k == NULL) return NULL;

    if(KEY_IS_IP6(key)) {
        return inet_ntop(AF_INET6, IPT_KEYPTR(key), s, INET6_ADDRSTRLEN);
    }
    return inet_ntop(AF_INET, IPT_KEYPTR(key), s, INET_ADDRSTRLEN);
}

int
key_incr(void *key)
{
    // 1 on success, 0 on failure (incr key, flips around from max to 0)
    uint8_t *k = key;
    if (k == NULL) return 0;

    int off = IPT_KEYLEN(k);
    if (off < 1) return 0;

    while(!(*(k + --off)+=1))
        ;

    return 1;
}

int
key_decr(void *key)
{
    // decrement the key, flips around from 0 to max
    uint8_t *k = key;
    if (k == NULL) return 0;

    int off = IPT_KEYLEN(k);
    while(--off > 0 && ((*(k+off)-=1)==255))
        ;

    return 1;
}

int
key_invert(void *key)
{
  // invert a key, usefull for a mask.  LEN-byte does not change, so that
  // disrupts the idea that, for a mask, the LEN-byte indicates the number of
  // non-zero's bytes in the array, counting from the left.
  uint8_t *k = key;
  int klen;

  if (k == NULL) return 0;
  klen = IPT_KEYLEN(k);
  while(--klen > 0 && k++) *k = ~*k;

  return 1;
}

int
key_network(void *key, void *mask)
{
    // apply mask to key, 1 on success, 0 on failure
    // - a mask's length may indicate the num of non-zero bytes instead of the
    //   entire length of the mask byte array.  Such 'missing' bytes are taken
    //   to be 0x00 (some radix tree masks seem to do this).
    int klen, mlen;
    uint8_t *k = key, *m = mask;

    // sanity check
    if (k == NULL || m == NULL) return 0;
    klen = IPT_KEYLEN(k);
    mlen = IPT_KEYLEN(m);
    k = IPT_KEYPTR(k);      // skip LEN byte
    m = IPT_KEYPTR(m);      // skip LEN byte

    if (klen < mlen) return 0;  // donot overrun key
    for(mlen--; --klen; mlen--)
        *(k++) &= mlen > 0 ? *(m++) : 0x00;

    return 1;
}

int
key_broadcast(void *key, void *mask)
{
    // apply (xor) inv.mask to key, 1 on success, 0 on failure
    // - a mask's length may indicate the num of non-zero bytes instead of the
    //   entire length of the mask byte array.  Such 'missing' bytes are taken
    //   to be 0xff (some radix tree masks seem to do this).
    int klen, mlen;
    uint8_t *k = key, *m = mask;

    // sanity check
    if (k == NULL || m == NULL) return 0;
    klen = IPT_KEYLEN(k);
    mlen = IPT_KEYLEN(m);
    k = IPT_KEYPTR(k);      // skip LEN byte
    m = IPT_KEYPTR(m);      // skip LEN byte

    if (klen < mlen) return 0;  // donot overrun key
    for(mlen--; --klen; mlen--)
        *(k++) |= mlen > 0 ? ~*(m++) : 0xff;

    return 1;
}

int
key_cmp(void *a, void *b)
{
    // -1 if a<b, 0 if a==b, 1 if a>b, -2 on errors
    uint8_t keylen, *aa = a, *bb = b;

    if (aa == NULL || bb == NULL) return -2;       // need real keys
    keylen = IPT_KEYLEN(aa);
    if (keylen != IPT_KEYLEN(bb)) return -2;       // different AF_families

    for(; --keylen > 0 && *aa==*bb; aa++, bb++)
        ;

    if (*aa < *bb) return -1;
    if (*aa > *bb) return 1;
    return 0;
}

int
key_isin(void *a, void *b, void *m)
{
    // 1 iff a & m == b & m, 0 otherwise
    // note: any radix keys/masks may have short(er) KEYLEN's than usual
    uint8_t *aa = a, *bb = b, *mm = m;
    int matchlen = 0;  // how many bytes to match depends on mask

    // sanity checks
    if(aa == NULL || bb == NULL) return 0;

    // if((matchlen = IPT_KEYLEN(aa)) != IPT_KEYLEN(bb)) return 0;
    matchlen = min(IPT_KEYLEN(aa), IPT_KEYLEN(bb));
    matchlen = mm ? min(matchlen, IPT_KEYLEN(mm)) : matchlen;
    mm = mm ? mm+1 : all_ones;

    aa++; bb++;
    for (; --matchlen > 0; aa++, bb++, mm++)
        if ((*aa ^ *bb) & *mm) return 0;

    return 1;
}

// radix node functions

int
rdx_flush(struct radix_node *rn, void *args)
{
    // return 0 on success, 1 on failure (see rnh_walktree)
    // - rdx_flush is called only on  _LEAF_ nodes (rn points to entry->rn[0])
    struct entry_t *entry = NULL;
    purge_t *arg = (purge_t *)args;
    struct radix_node_head *rnh = arg->head;

    if (rn == NULL) return 0;
    entry = (entry_t *)rnh->rnh_deladdr(rn->rn_key, rn->rn_mask, &rnh->rh);
    if (entry == NULL) return 0;

    free(entry->rn[0].rn_key);
    if (entry->value != NULL && arg->purge != NULL)
        arg->purge(arg->args, &entry->value);

    free(entry);

    return 0;
}

struct radix_node *
rdx_first(struct radix_node_head *rnh)
{
    // find first leaf in tree
    struct radix_node *rn = NULL;

    if (rnh == NULL) return rn;

    rn = rnh->rh.rnh_treetop;
    while(rn->rn_bit >= 0)
        rn = rn->rn_left;

    while(RDX_ISRIGHT_CHILD(rn))
        rn = rn->rn_parent;

    for(rn = rn->rn_parent->rn_right; rn->rn_bit >=0;)
        rn = rn->rn_left;

    if(RDX_ISROOT(rn)) return NULL;

    return rn;
}

struct radix_node *
rdx_next(struct radix_node *rn)
{
    // find next leaf, given a leaf
    if (rn == NULL) return NULL;

    if (rn->rn_dupedkey)
        return rn->rn_dupedkey;

    while(RDX_ISRIGHT_CHILD(rn))
        rn = rn->rn_parent;

    for(rn = rn->rn_parent->rn_right; rn->rn_bit >=0;)
      rn = rn->rn_left;

    if (RDX_ISROOT(rn)) rn = NULL;

    return rn;
}

// tbl functions

table_t *
tbl_create(purge_f_t *fp)
{
    // create a new iptable with 2 radix trees
    table_t *tbl = NULL;

    tbl = calloc(sizeof(*tbl), 1);  // sets count's to zero & ptr's to NULL
    if (tbl == NULL) return NULL;

    if (rn_inithead((void **)&tbl->head4, 8) == 0) { // IPv4 radix tree
        free(tbl);
        return NULL;
    }
    if (rn_inithead((void **)&tbl->head6, 8) == 0) { // IPv6 radix tree
        rn_detachhead((void **)&tbl->head4);
        free(tbl);
        return NULL;
    }
    tbl->purge = fp;

    return tbl;
}


int
tbl_walk(table_t *t, walktree_f_t *f, void *fargs)
{
    // run f(args, leaf) on leafs in IPv4 tree and IPv6 tree
    if (t == NULL) return 0;
    t->head4->rnh_walktree(&t->head4->rh, f, fargs);
    t->head6->rnh_walktree(&t->head6->rh, f, fargs);

   return 1;
}

int
tbl_destroy(table_t **t, void *pargs)
{
    // utterly destroy the entire table; 1 on success, 0 on errors

    purge_t args;  // args to flush radix nodes & free userdata

    if (t == NULL || *t == NULL) return 0;  // nothing to free

    args.purge = (*t)->purge;          // the user callback to free userdata
    args.args = pargs;                 // context for purge callback

    args.head = (*t)->head4;
    (*t)->head4->rnh_walktree(&(*t)->head4->rh, rdx_flush, &args);
    rn_detachhead((void **)&(*t)->head4);

    args.head = (*t)->head6;
    (*t)->head6->rnh_walktree(&(*t)->head6->rh, rdx_flush, &args);
    rn_detachhead((void **)&(*t)->head6);

    free(*t);
    *t = NULL;

    return 1;
}

entry_t *
tbl_get(table_t *t, const char *s)
{
    // An exact lookup for addr/mask, missing mask is set to AF's max mask
    // uint8_t *addr = NULL;
    uint8_t addr[MAX_BINKEY];
    uint8_t mask[MAX_BINKEY];
    int mlen = -1, af = AF_UNSPEC;
    struct radix_node_head *head = NULL;
    entry_t *entry = NULL;

    // get head, af, addr, mask, or bail on error
    if (t == NULL || s == NULL) return NULL;
    if (! key_bystr(s, &mlen, &af, addr)) return NULL;

    if (af == AF_INET) head = t->head4;
    else if (af == AF_INET6) head = t->head6;
    else return NULL;

    if (! key_bylen(af, mlen, mask)) return NULL;
    if (! key_network(addr, mask)) return NULL;

    entry = (entry_t *)head->rnh_lookup(addr, mask, &head->rh); // exact match for pfx

    return entry;
}

int
tbl_set(table_t *t, const char *s, void *v, void *pargs)
{
    // A missing mask is taken to mean AF's max mask
    // - applies mask before searching/setting the tree
    /* uint8_t *addr = NULL; */

    uint8_t addr[MAX_BINKEY], mask[MAX_BINKEY], *treekey = NULL;
    int mlen = -1, af = AF_UNSPEC;
    entry_t *entry = NULL;
    struct radix_node *rn = NULL;
    struct radix_node_head *head = NULL;

    // get head, af, addr, mask, or bail on error
    if (t == NULL || s == NULL) return 0;
    if (! key_bystr(s, &mlen, &af, addr)) return 0;
    if (! key_bylen(af, mlen, mask)) return 0;
    if (! key_network(addr, mask)) return 0;

    if (af == AF_INET) head = t->head4;
    else if (af == AF_INET6) head = t->head6;
    else return 0;

    entry = (entry_t *)head->rnh_lookup(addr, mask, &head->rh); // exact match
    if (entry) {
        // update existing entry
        if(entry->value) t->purge(pargs, &entry->value); // free userdata
        entry->value = v;                                // set new userdata

    } else {
        // add new entry, need to donate a new key for the tree to keep
        if (!(entry = calloc(sizeof(*entry),1))) return 0;
        entry->value = v;
        treekey = key_copy(addr);

        rn = head->rnh_addaddr(treekey, mask, &head->rh, entry->rn);
        if (!rn) {
            t->purge(pargs, &entry->value);
            free(entry);
            free(treekey); // t'was not stored
            return 0;
        }

        if (af == AF_INET) t->count4++;
        else t->count6++;
    }

    return 1;
}

int
tbl_del(table_t *t, const char *s, void *pargs)
{
    // Deletion requires exact match on prefix
    // - a missing mask is set to AF's max mask
    entry_t *e;
    struct radix_node_head *head = NULL;
    uint8_t addr[MAX_BINKEY], mask[MAX_BINKEY];
    int mlen = -1, af = AF_UNSPEC;

    // get head, af, addr, mask, or bail on error
    if (t == NULL || s == NULL) return 0;
    if (! key_bystr(s, &mlen, &af, addr)) return 0;
    if (! key_bylen(af, mlen, mask)) return 0;
    if (! key_network(addr, mask)) return 0;

    if (af == AF_INET) head = t->head4;
    else if (af == AF_INET6) head = t->head6;
    else return 0;

    e = (entry_t *)head->rnh_deladdr(addr, mask, &head->rh);
    if (! e) return 0;

    if (af == AF_INET) t->count4--;
    else t->count6--;

    free(e->rn[0].rn_key);                      // free the key
    if(e->value) t->purge(pargs, &e->value);    // free the user data
    free(e);                                    // free the entry

    return 1;
}

entry_t *
tbl_lpm(table_t *t, const char *s)
{
    // longest prefix match for address (a /mask is ignored)
    struct radix_node_head *head = NULL;
    uint8_t addr[MAX_BINKEY];
    int mlen = -1, af = AF_UNSPEC;
    entry_t *rv = NULL;

    if (t == NULL || s == NULL) return NULL;
    if (! key_bystr(s, &mlen, &af, addr)) return NULL;

    if (af == AF_INET) head = t->head4;
    else if (af == AF_INET6) head = t->head6;
    else return NULL;

    rv = (entry_t *)head->rnh_matchaddr(addr, &head->rh);

    return rv;
}

int
tbl_less(table_t *t, const char *s, int include, walktree_f_t *f, void *fargs)
{
    // find less specific prefixes relative to s & call f(fargs, rn)
    // return 0 on failure, 1 on success
    // - actually traverses almost the entire tree to find all candidates
    struct radix_node_head *head = NULL;
    struct radix_node *rn = NULL, *base = NULL;
    uint8_t addr[MAX_BINKEY];
    int mlen = -1, af = AF_UNSPEC, done = 0;
    // include = include > 0 ? -2 : -1;
    include = include > 0 ? -2 : -1;

    // sanity checks
    if (t == NULL || s == NULL) return 0;
    if (f == NULL) return 0;
    if (! key_bystr(s, &mlen, &af, addr)) return 0;

    if (af == AF_INET) {
        head = t->head4;
        mlen = mlen < 0 ? IP4_MAXMASK : mlen;
    } else if (af == AF_INET6) {
        head = t->head6;
        mlen = mlen < 0 ? IP6_MAXMASK : mlen;
    } else return 0;

    if (mlen == 0 && include == -1) return 1;  // nothing is less specific than /0
    mlen += IPT_KEYOFFSET;

    // goto left most leaf
    for(rn = head->rh.rnh_treetop; !RDX_ISLEAF(rn);)
        rn = rn->rn_left;

    // how to limit running around the tree for less specific prefixes?
    /* rn = head->rnh_matchaddr(addr, &head->rh); */
    /* if(rn == NULL) return 1; */
    if (rn == NULL) return 1;

    done = 0;
    while (!done) {
        base = rn;
        // process leaf & its duplicates
        for(; rn; rn = rn->rn_dupedkey) {
            if (! RDX_ISROOT(rn) && rn->rn_bit + mlen > include)
                if (key_isin(addr, rn->rn_key, rn->rn_mask))
                    f(rn, fargs);
        }
        rn = base;

        // go up while "I am a right->child" & "not a ROOT" node
        while(RDX_ISRIGHT_CHILD(rn) && !RDX_ISROOT(rn))
            rn = rn->rn_parent;

        // go 1 up, then right & find the next left most *leaf*
        for (rn = rn->rn_parent->rn_right; !RDX_ISLEAF(rn); )
            rn = rn->rn_left;

        if (rn->rn_flags & RNF_ROOT)
            done = 1;
    }

    return 1;
}

int
tbl_more(table_t *t, const char *s, int include, walktree_f_t *f, void *fargs)
{
    // find more specific prefixes relative to s & call f(fargs, rn)
    // return 0 on failure, 1 on success
    // - actually traverses almost the entire tree to find all candidates
    struct radix_node_head *head = NULL;
    struct radix_node *rn = NULL, *base = NULL, *top = NULL;
    uint8_t addr[MAX_BINKEY], mask[MAX_BINKEY];
    int mlen = -1, af = AF_UNSPEC, done = 0;
    include = include > 0 ? 0 : -1;
    /* char buf[MAX_STRKEY]; // TODO: delme after debugging */

    // sanity checks
    if (t == NULL || s == NULL) return 0;
    if (f == NULL) return 0;
    if (! key_bystr(s, &mlen, &af, addr)) return 0;

    if (mlen < 0 && include == -1) return 1; // host ip, no include -> done
    if (af == AF_INET) {
        head = t->head4;
        mlen = mlen < 0 ? IP4_MAXMASK : mlen;
    } else if (af == AF_INET6) {
        head = t->head6;
        mlen = mlen < 0 ? IP6_MAXMASK : mlen;
    } else return 0;
    if (! key_bylen(af, mlen, mask)) return 0;
    if (! key_network(addr, mask)) return 0;

    mlen += IPT_KEYOFFSET;

    // descend tree while key-bits are non-masked
    for (top = head->rh.rnh_treetop; !RDX_ISLEAF(top) && (top->rn_bit < mlen);)
        if (addr[top->rn_offset] & top->rn_bmask)
            top = top->rn_right;  // bit is on
        else
            top = top->rn_left;   // bit is off

    if (top == NULL) return 0;

    // goto left most leaf
    for(rn = top; !RDX_ISLEAF(rn);)
        rn = rn->rn_left;

    // ensure we're in the right subtree (prefix s may not be in the tree)
    if (!key_isin(addr, rn->rn_key, mask)) return 0;
    /* if(rn) { */
    /*     printf("Subtree @ %s ", key_tostr(rn->rn_key, buf)); */
    /*     if (rn->rn_mask) printf("%s\n", key_tostr(rn->rn_mask, buf)); */
    /*     else printf("\n"); */
    /* } */

    done = 0;
    while (!done) {
        base = rn;
        // process leaf & its duplicates
        for(; rn; rn = rn->rn_dupedkey) {
            if (!RDX_ISROOT(rn) && rn->rn_bit + mlen < include) {
                /* printf("- visiting %s\n", key_tostr(rn->rn_key, buf)); */
                f(rn, fargs);
            } else if (!RDX_ISROOT(rn) && mlen + include == 8) {
                // TODO: this is a hack for when:
                // - 0/0 is present in the tree, and
                // - 0/0 is used as search key (ehmm...), and
                // - include-flag is on -> 0/0 should be included in results
                // After dotify is added => re-investigate this!
                f(rn, fargs);
            }
        }
        if (base == top) break;  // no more leaves to visit
        rn = base;

        // go up while "I am a right->child" & "not a ROOT" node
        while (!done && RDX_ISRIGHT_CHILD(rn) && !RDX_ISROOT(rn)) {
            rn = rn->rn_parent;
            done = (rn == top);
        }
        if (done) break;  // no need to goto any next leaf

        // go 1 up, then right & find the next left most *leaf*
        for (rn = rn->rn_parent->rn_right; !RDX_ISLEAF(rn);)
            rn = rn->rn_left;

        done = RDX_ISROOT(rn);
    }

    return 1;
}
