/* file lua_iptable.c --  Lua bindings for iptable */

#include <malloc.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <string.h>

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#include "radix.h"
#include "iptable.h"
#include "debug.h"

/* lua_iptable identity */

#define LUA_IPTABLE_ID "iptable"

/* lua functions */

int luaopen_iptable(lua_State *);

/* helper funtions */

table_t *check_table(lua_State *, int);
static int check_binkey(lua_State *, int, uint8_t *, size_t *);
const char *check_pfxstr(lua_State *, int, size_t *);
static int *refp_create(lua_State *);
static void refp_delete(void *, void **);
static int isvalid(struct radix_node *);
static int iter_bail(lua_State *);
static int iter_fail(lua_State *);
static inline int subtree_fail(struct radix_node *, int);

/* iter_radix() helpers */

static void iptL_push_fstr(lua_State *, const char *, const char *, const void *);
static void iptL_push_int(lua_State *, const char *, int);
static int push_rdx_node_head(lua_State *, struct radix_node_head *);
static int push_rdx_node(lua_State *, struct radix_node *);
static int push_rdx_head(lua_State *, struct radix_head *);
static int push_rdx_mask_head(lua_State *, struct radix_mask_head *);
static int push_rdx_mask(lua_State *, struct radix_mask *);


/* iterators */

static int iter_hosts(lua_State *);
static int iter_kv(lua_State *);
static int iter_less(lua_State *);
static int iter_masks(lua_State *);
static int iter_merge(lua_State *);
static int iter_more(lua_State *);
static int iter_more_org(lua_State *);
static int iter_radix(lua_State *);

/* iptable module functions */

static int ipt_address(lua_State *);
static int ipt_broadcast(lua_State *);
static int ipt_hosts(lua_State *);
static int ipt_mask(lua_State *);
static int ipt_neighbor(lua_State *L);
static int ipt_network(lua_State *);
static int ipt_new(lua_State *);
static int ipt_size(lua_State *);
static int ipt_tobin(lua_State *);
static int ipt_tolen(lua_State *);
static int ipt_tostr(lua_State *);

/* iptable instance methods */

static int _gc(lua_State *);
static int _index(lua_State *);
static int _newindex(lua_State *);
static int _len(lua_State *);
static int _tostring(lua_State *);
static int _pairs(lua_State *);
static int counts(lua_State *);
static int less(lua_State *);
static int masks(lua_State *);
static int merge(lua_State *);
static int more(lua_State *);
static int more_org(lua_State *);
static int radixes(lua_State *);

/* iptable module function array */

static const struct luaL_Reg funcs [] = {
    {"address", ipt_address},
    {"broadcast", ipt_broadcast},
    {"hosts", ipt_hosts},
    {"mask", ipt_mask},
    {"neighbor", ipt_neighbor},
    {"network", ipt_network},
    {"new", ipt_new},
    {"size", ipt_size},
    {"tobin", ipt_tobin},
    {"tolen", ipt_tolen},
    {"tostr", ipt_tostr},
    {NULL, NULL}
};

/* iptable instance methods array */

static const struct luaL_Reg meths [] = {
    {"__gc", _gc},
    {"__index", _index},
    {"__newindex", _newindex},
    {"__len", _len},
    {"__tostring", _tostring},
    {"__pairs", _pairs},
    {"counts", counts},
    {"masks", masks},
    {"merge", merge},
    {"more", more},
    {"more_org", more_org},
    {"less", less},
    {"radixes", radixes},
    {NULL, NULL}
};

/* libopen */

/*
 * require("iptable")  <--  ['iptable', '<path>/iptable.so']
 *
 * Return iptable's module-table which holds the module functions and
 * constants.  Instance methods go into the module-table's metatable.
 *
 */

int
luaopen_iptable (lua_State *L)
{
    dbg_stack("inc(.) <--");

    luaL_newmetatable(L, LUA_IPTABLE_ID);   // [.., {} ]
    lua_pushvalue(L, -1);                   // [.., {}, {} ]
    lua_setfield(L, -2, "__index");         // [.., {__index={}} ]
    luaL_setfuncs(L, meths, 0);             // [.., {__index={m's}} ]
    luaL_newlib(L, funcs);                  // [.., {__index={m's}, f's} ]

    // lib AF constants
    lua_pushinteger(L, AF_INET);
    lua_setfield(L, -2, "AF_INET");
    lua_pushinteger(L, AF_INET6);
    lua_setfield(L, -2, "AF_INET6");

    // lib RDX node type constants
    lua_pushinteger(L, TRDX_NODE_HEAD);
    lua_setfield(L, -2, "RDX_NODE_HEAD");
    lua_pushinteger(L, TRDX_MASK_HEAD);
    lua_setfield(L, -2, "RDX_MASK_HEAD");
    lua_pushinteger(L, TRDX_NODE);
    lua_setfield(L, -2, "RDX_NODE");
    lua_pushinteger(L, TRDX_MASK);
    lua_setfield(L, -2, "RDX_MASK");
    lua_pushinteger(L, TRDX_HEAD);
    lua_setfield(L, -2, "RDX_HEAD");


    dbg_stack("out(1) ==>");

    return 1;
}

/* helpers */

/*
 * check_table()  <--  [ .. t ..]
 *
 * Check element at given idx is table with the correct metatable and thus is
 * an iptable.  May throw an error through luaL_argcheck back to caller.
 *
 */

table_t *
check_table (lua_State *L, int index)
{
    void **t = luaL_checkudata(L, index, LUA_IPTABLE_ID);
    luaL_argcheck(L, t != NULL, index, "`iptable' expected");
    return (table_t *)*t;
}

/*
 * check_binkey()  <--  [ .. k ..]
 *
 * Copy a binary key, either an address or a mask, at given 'idx' into given
 * 'buf'.  'buf' size is assumed to be MAX_BINKEY.  A binary key is a byte
 * array [LEN | key bytes] and LEN is total length.  However, radix masks may
 * have set their LEN-byte equal to the nr of non-zero bytes in the array
 * instead.
 *
 */

static int
check_binkey(lua_State *L, int idx, uint8_t *buf, size_t *len)
{
    const char *key = NULL;

    if (!lua_isstring(L, idx)) return 0;

    key = lua_tolstring(L, idx, len);
    if (key == NULL) return 0;

    if (IPT_KEYLEN(key) > MAX_BINKEY) return 0;
    if (*len < 1 || *len > MAX_BINKEY) return 0;

    memcpy(buf, key, *len);

    return 1;
}

/*
 * check_pfxstr()  <--  [.. s ..]
 *
 * Checks if given index is a string and yields a const char ptr to it or NULL.
 * Sets len to the string length reported by Lua's stack manager.  Lua owns the
 * memory pointed to by the return value (no free by caller needed).
 *
 */

const char *
check_pfxstr(lua_State *L, int idx, size_t *len)
{
    /* return const char to a (prefix) string.  NULL on failure. */
    const char *pfx = NULL;
    if (! lua_isstring(L, idx)) return NULL;
    pfx = lua_tolstring(L, idx, len);  // donot use luaL_tolstring!

    return pfx;
}

/*
 * ud_create()
 *
 * Stores a given int value in newly allocated memory and returns its pointer.
 *
 * The int value is a LUA_REGISTRYINDEX reference value where the actual
 * userdata is stored.  The ref-value's pointer is part of an entry_t which is
 * what is stored/retrieved from the radix tree by casting radix node pointers
 * to pointer to entry_t.  See _index().
 *
 */

/*
 * refp_create()  <--  [.. v ..]
 *
 * Store value at given index in the LUA_REGISTRY (a lua table), and return a
 * pointer to its reference value which is stored in new allocated memory.
 *
 */

static int *
refp_create(lua_State *L)
{
    int *refp = calloc(1, sizeof(int));
    *refp = luaL_ref(L, LUA_REGISTRYINDEX);
    return refp;
}

/*
 * refp_delete()
 *
 * Delete a value from LUA_REGISTRYINDEX indexed by **r (which is treated as an
 * **int).  This function acts as the purge_f_t (see iptable.h) for the table.
 *
 */

static void refp_delete(void *L, void **r)
{
    lua_State *LL = L;
    int **refp = (int **)r;

    if(refp == NULL || *refp == NULL) return;
    luaL_unref(LL, LUA_REGISTRYINDEX, **refp);
    free(*refp);
    *refp = NULL;
}

/*
 * isvalid(rn) -> checks if rn is still a valid child and parent i/t tree
 *
 * - a valid child is pointed to by its parent
 * - a valid parent is pointed to by its child(ren)
 *
 * this attempts to detect if rn was deleted; used by iter_xxx functions
 * which store the *next* leaf node to process, which might get deleted by some
 * user action during iteration.  Not fullproof, but better than nothing.
 *
 */

static int isvalid(struct radix_node *rn)
{
    int valid = 1;

    if(rn == NULL || rn->rn_parent == NULL) return 0;

    // rn is pointed to by its children (if any)
    if (RDX_ISLEAF(rn)) {
        if (rn->rn_dupedkey)
            valid &= rn->rn_dupedkey->rn_parent == rn;
    } else {
        valid &= rn->rn_left->rn_parent == rn;
        valid &= rn->rn_right->rn_parent == rn;
    }

    // and rn is pointed to by its parent
    if(RDX_ISLEAF(rn->rn_parent))
        valid &= rn->rn_parent->rn_dupedkey == rn;
    else
        valid &= (rn->rn_parent->rn_left == rn
                  || rn->rn_parent->rn_right == rn);

    return valid;
}

/*
* iter_bail(L)  <--  [..]
*
* Helper function to bail out of an iteration factory function.
*
* An iteration factory function MUST return a valid [iter_f] and optionally
* an invariant and ctl_var. By returning iter_fail as [iter_f] we ensure
* the iteration in question will yield no results in Lua.
*
*/
static int
iter_bail(lua_State *L)
{
    dbg_stack("inc(.) ->");

    lua_pop(L, lua_gettop(L));               /* clear the stack */
    lua_pushcclosure(L, iter_fail, 0);       /* the iteration blocker */

    dbg_stack("out(1) ==>");

    return 1;
}

/*
* iter_fail  <--  [..], stack is ignored
*
* An iteration func that terminates any iteration.
*
*/

static int
iter_fail(lua_State *L)
{
    dbg_stack("ignored ->");

    lua_pop(L, lua_gettop(L));
    return 0;
}

/*
 * iter_hosts()  <--  [h], h is nil on first call.
 *
 * The iter_f for iptable.hosts(pfx), yields the next host ip until stop value
 * is reached.  Ignores the stack: it uses upvalues for next, stop
 *
 */

static int
iter_hosts(lua_State *L)
{
    dbg_stack("inc(.) <--");

    size_t nlen = 0, slen = 0;
    uint8_t next[MAX_BINKEY], stop[MAX_BINKEY];
    char buf[MAX_STRKEY];

    if (!check_binkey(L, lua_upvalueindex(1), next, &nlen)) return 0;
    if (!check_binkey(L, lua_upvalueindex(2), stop, &slen)) return 0;
    if (key_cmp(next, stop) == 0) return 0;

    key_tostr(buf, next);                               /* return cur val */
    lua_pushstring(L, buf);

    key_incr(next);                                     /* setup next val */
    lua_pushlstring(L, (const char *)next, (size_t)IPT_KEYLEN(next));
    lua_replace(L, lua_upvalueindex(1));

    dbg_stack("out(1) ==>");

    return 1;
}

/*
 * iter_kv()  <--  [t k]
 *
 * The iter_f for __pairs(), yields all k,v pairs in the tree(s).
 * - upvalue(1) is the leaf to process.
 *
 */

static int
iter_kv(lua_State *L)
{
    dbg_stack("inc(.) <--");

    char saddr[MAX_STRKEY];

    table_t *t = check_table(L, 1);
    struct radix_node *rn = lua_touserdata(L, lua_upvalueindex(1));
    entry_t *e = (entry_t *)rn;

    if (rn == NULL || RDX_ISROOT(rn)) return 0; // we're done
    if (!isvalid(rn)) return 0;                 // next rn got deleted

    /* push the next key, value onto stack */
    key_tostr(saddr, rn->rn_key);
    lua_pushfstring(L, "%s/%d", saddr, key_tolen(rn->rn_mask)); // [t k k']
    lua_rawgeti(L, LUA_REGISTRYINDEX, *(int *)e->value);        // [t k k' v']

    /* get next leaf node, switch to ipv6 tree when ipv4 has been traversed */
    rn = rdx_nextleaf(rn);
    if (rn == NULL && KEY_IS_IP4(e->rn[0].rn_key))
        rn = rdx_firstleaf(&t->head6->rh);

    lua_pushlightuserdata(L, rn);                            // [t k k' v' rn]
    lua_replace(L, lua_upvalueindex(1));                     // [t_ud k k' v']

    dbg_stack("out(2) ==>");

    return 2;                                                // [.., k', v']
}

/*
 * iter_less()  <--  [t k], k is ignored
 *
 * Iterate across less specific prefixes relative to a given prefix.
 *
 */

static int
iter_less(lua_State *L)
{
    char buf[MAX_STRKEY];
    table_t *t = check_table(L, 1);
    entry_t *e;
    const char *pfx = lua_tostring(L, lua_upvalueindex(1));
    int mlen = lua_tointeger(L, lua_upvalueindex(2));

    /* negative mlen means no more matches to try */
    if (mlen < 0) return 0;
    if (pfx == NULL) return 0;

    for(; mlen >= 0; mlen--) {
        snprintf(buf, sizeof(buf), "%s/%d", pfx, mlen);
        buf[MAX_STRKEY-1] = '\0';

        if ((e = tbl_get(t, buf))) {
            lua_pushfstring(L, "%s/%d",
                    key_tostr(buf, e->rn[0].rn_key),
                    key_tolen(e->rn[0].rn_mask));
            lua_rawgeti(L, LUA_REGISTRYINDEX, *(int *)e->value);
            lua_pushinteger(L, mlen-1);
            lua_replace(L, lua_upvalueindex(2));
            return 2;
        }
    }
    return 0;  // all done
}

/*
 * iter_masks(lua_State *);
 *
 * iter_f for :masks(af), yields all masks used in af's radix mask tree.
 *
 */

static int iter_masks(lua_State *L)
{
    dbg_stack("inc(.) <--");                       // [t m']

    struct radix_node *rn = lua_touserdata(L, lua_upvalueindex(1));
    int af = lua_tointeger(L, lua_upvalueindex(2));
    const char *zeromask = lua_tostring(L, lua_upvalueindex(3));
    uint8_t binmask[MAX_BINKEY];
    char strmask[MAX_STRKEY];
    int mlen;

    lua_pop(L, 1);                                 // [t]

    /* return zeromask as first result, if available */
    if (zeromask && strlen(zeromask)) {
        lua_pushstring(L, zeromask);
        lua_pushinteger(L, 0);
        /* once is enough */
        lua_pushliteral(L, "");
        lua_replace(L, lua_upvalueindex(3));
        return 2;
    }

    if (rn == NULL || !isvalid(rn) || RDX_ISROOT(rn))
        return 0;          // we're done (or next rn was deleted ...)

    /* process current mask leaf node */
    mlen = key_tolen(rn->rn_key);              // contiguous masks only
    key_bylen(binmask, mlen, af);              // fresh mask due to deviating
    key_tostr(strmask, binmask);               // keylen's of masks

    lua_pushstring(L, strmask);                // [t m]
    lua_pushinteger(L, mlen);                  // [t m l]

    /* get next leaf (mask) node */
    rn = rdx_nextleaf(rn);
    lua_pushlightuserdata(L, rn);              // [t m l rn]
    lua_replace(L, lua_upvalueindex(1));       // [t m l]

    dbg_stack("out(2) ==>");

    return 2;                                      // [.., m l]
}

/*
 * helper to dedup a leaf
 * - puts all pfx,v in table on stack L
 * - returns last leaf of chain if duplicates were found, NULL otherwise
 */

/* static struct radix_node *ipt_merge_dedup(lua_State *, struct radix_node *); */
/* static struct radix_node * */
/* ipt_merge_dedup(lua_State *L, struct radix_node *rn) { */
/*     char buf[MAX_STRKEY]; */
/*     struct radix_node *last = NULL; */
/*     entry_t *e; */

/*     dbg_stack("inc(.) <--"); */
/*     if (rn == NULL) return NULL; */
/*     if (!RDX_ISLEAF(rn)) return NULL; */

/*     /1* goto top of dupedkey chain, if possible *1/ */
/*     while(!RDX_ISROOT(rn->rn_parent) && RDX_ISLEAF(rn->rn_parent)) */
/*         rn = rn->rn_parent; */
/*     if (rn->rn_dupedkey == NULL) return NULL;  /1* no dupedkeys *1/ */

/*     /1* collect (pfx, v) into lua table on stack L *1/ */
/*     lua_newtable(L);                                        // [.. {}] */
/*     last = rn; */
/*     while(rn) { */
/*         lua_pushfstring(L, "%s/%d", */
/*                 key_tostr(buf, rn->rn_key), key_tolen(rn->rn_mask)); */
/*         e = (entry_t *)rn; */
/*         lua_rawgeti(L, LUA_REGISTRYINDEX, *(int *)e->value); */
/*         lua_settable(L, -3); */
/*         last = rn; */
/*         rn = rn->rn_dupedkey; */
/*     } */

/*     lua_pushfstring(L, "%s/%d", */
/*             key_tostr(buf, last->rn_key), */
/*             key_tolen(last->rn_mask));                      // [.. {} pfx] */
/*     dbg_stack("dupedkeys"); */
/*     lua_rotate(L, lua_gettop(L) - 1, 1);                    // [.. pfx {}] */
/*     dbg_stack("dupedkeys"); */
/*     return last; */
/* } */

static struct radix_node *ipt_merge_largest(struct radix_node *);
static struct radix_node *
ipt_merge_largest(struct radix_node *rn) {
    /* return largest leaf in subtree starting at rn */

    while(!RDX_ISLEAF(rn)) rn = rn->rn_left;
    while(rn->rn_dupedkey) rn = rn->rn_dupedkey;
    return rn;
}

/*
 * Iterate across prefixes that may be combined.
 *
 * Returns the supernet and a regular table w/ pfx->value.  Caller may decide
 * to keep only the supernet or parts of the group.  If the supernet exists in
 * the tree it will be present in the table as well.
 *
 * The next node stored as upvalue before returning, must be the first node of
 * the next group.
 *
 * Given a single radix rn collect what can be combined safely: overlapping
 * prefixes or adjacent prefixes.
 * introducing new address space in the tree:
 * 1) overlapping space:
 *    - more specifics, inclusive of largest leaf in the dupedkeychain
 * 2) adjacent space
 *    a) combinable w/ previous (non-duped) leaf?
 *    b) combinable w/ next (non-duped) leaf?
 *
 * Algorithm:
 * - goto leaf's parent
 * - get largest-left, largest-right
 * - if adjacent -> combine, else take largest-left
 *   return all more specifics; next node is first-leaf of grandparent R-tree
 */

static int
iter_merge(lua_State *L)
{
    dbg_stack("inc(.) <--");                   // [t p]

    struct radix_node *rn = lua_touserdata(L, lua_upvalueindex(1));
    struct radix_node *ll=NULL, *lr=NULL;;

    if (rn == NULL) return 0;          /* all done, not an error */
    if (! isvalid(rn)) return 0;       /* error: cannot continue */
    if (! RDX_ISLEAF(rn)) return 0;    /* error: should've been a leaf */
    lua_pop(L, lua_gettop(L));         /* [] -- clear stack */

    while(rn) {
        while(RDX_ISLEAF(rn->rn_parent)) rn = rn->rn_parent; /* top of chain */
        // if (RDX_ISROOT(rn)) return 0; /* all done */
        ll = ipt_merge_largest(rn->rn_parent->rn_left);
        lr = ipt_merge_largest(rn->rn_parent->rn_right);
        _dumprn("lo ", rn);
        _dumprn("ll ", ll);
        _dumprn("lr ", lr);

        /* Case:
         * - ll + lr are adjacent ->  key_join'm & return msp
         * - ll includes lr       ->  key := ll  & return msp
         * - ll is not top of chain -> key := ll & return msp
         * - lr is not top of chain -> key := lr & return msp
         * move onto next subtree
         */

        if(key_isin(ll->rn_key, lr->rn_key, ll->rn_mask)) {
            fprintf(stderr, "ll contains lr -> msp(ll)\n");
        }

        /* if (key_merge(spfx, &mlen, ll, lr)) { */
        /*     /1* return spfx's more specifics, inclusive *1/ */
        /*     /1* rn = rdx_nextleaf(rn->rn_parent) *1/ */
        /* } else if (key_isin(ll, lr, ll->rn_mask)) { */
        /*     /1* return ll's more specifics, inclusive *1/ */
        /* } else if (RDX_ISLEAF(ll->rn_parent)) { */
        /*     /1* return lr's more specifics, inclusive *1/ */
        /* } else { */
        /*     /1* return *1/ */
        /* } */

        rn = rdx_nextleaf(lr);
        if (rn == NULL) return 0;
        if(RDX_ISROOT(rn)) return 0;

    }


    return 0;
}

/*
 * Iterate across more specific prefixes one at a time.
 *
 * - top points to subtree where possible matches are located
 * - rn is the current leaf under consideration
 */
static int
iter_more_org(lua_State *L)
{
    dbg_stack("inc(.) <--");
    lua_pop(L, lua_gettop(L));  // clear stack, not used

    char buf[MAX_STRKEY];
    struct radix_node *top = lua_touserdata(L, lua_upvalueindex(1));
    struct radix_node *rn = lua_touserdata(L, lua_upvalueindex(2));
    struct entry_t *e = NULL;
    int maxb = lua_tointeger(L, lua_upvalueindex(3));
    size_t dummy;
    uint8_t addr[MAX_BINKEY], mask[MAX_BINKEY];

    if (rn == NULL) return 0;     /* we're done */
    if (!isvalid(rn)) return 0;   /* TODO: error handling, rn was deleted */

    if(!check_binkey(L, lua_upvalueindex(4), addr, &dummy)) return 0;
    if(!check_binkey(L, lua_upvalueindex(5), mask, &dummy)) return 0;

    dbg_msg("search msp %s/%d", key_tostr(buf, addr), key_tolen(mask));
    dbg_msg("candidate  %s/%d", key_tostr(buf, rn->rn_key), key_tolen(rn->rn_mask));
    dbg_msg("        rn %p", (void*)rn);

    /* check LEAF and duplicates for more specific prefixes */
    int matched = 0, done = 0;
    while (! matched && ! done) {

        /* check for match (only a non-ROOT-LEAF may match) */

        if(RDX_ISLEAF(rn)
                && !RDX_ISROOT(rn)
                && rn->rn_bit <= maxb
                && key_isin(addr, rn->rn_key, mask)) {

            e = (entry_t *)rn;
            lua_pushfstring(L, "%s/%d",
                    key_tostr(buf, e->rn[0].rn_key),
                    key_tolen(e->rn[0].rn_mask));
            lua_rawgeti(L, LUA_REGISTRYINDEX, *(int *)e->value);
            matched = 1;
        } else if(RDX_ISLEAF(rn)
                && !RDX_ISROOT(rn)
                && rn->rn_bit <= maxb) {
            printf("%s/%d no match for ",
                key_tostr(buf, rn->rn_key), key_tolen(rn->rn_mask));
            printf("%s/%d\n",
                key_tostr(buf, addr), key_tolen(mask));


                }

        dbg_msg("top %p, maxb %d, rn %p, rn_bit %d, match %d",
          (void *)top, maxb, (void *)rn, rn->rn_bit, matched);

        /* setup next leaf node, in top's subtree,  to try later on */

        if (rn->rn_dupedkey) {
            rn = rn->rn_dupedkey;      /* more dups to try */
        } else {

            /* if rn is dupedkey-child of RE-marker, we're done */
            if (RDX_ISLEAF(rn->rn_parent)
                && RDX_ISROOT(rn->rn_parent)
                && (rn->rn_flags & RNF_NORMAL)){
              done = 1;
            }

            /* end of the dupedkey chain, go back to top of chain */
            while(RDX_ISLEAF(rn->rn_parent) && !RDX_ISROOT(rn->rn_parent)) {
                rn=rn->rn_parent;
            }

            /* go back up top's subtree, while we're a right child */
            while(RDX_ISRIGHT_CHILD(rn) && !RDX_ISROOT(rn)
                && rn->rn_parent != top) {
                rn = rn->rn_parent;
            }

            /* If rn is top's right child, we're done */
            if (rn == top->rn_right) done = 1;

            /* cross over to top's right subtree & goto its left-most leaf */
            for (rn = rn->rn_parent->rn_right; !RDX_ISLEAF(rn); )
                rn = rn->rn_left;

            /* if rn is RE-marker (also a leaf), we're done */
            if (RDX_ISROOT(rn->rn_parent)) done = 1;
        }

        if (done || matched) {
            /* exiting while-loop, so save rn to upvalue for next call */
            rn = done ? NULL : rn;
            lua_pushlightuserdata(L, rn);
            lua_replace(L, lua_upvalueindex(2));
        }
    }

    if (matched) {
        dbg_stack("out(2) ==>");
        return 2;
    }
    dbg_stack("out (0)");
    return 0;
}

static int
iter_more(lua_State *L)
{
    dbg_stack("inc(.) <--");
    lua_pop(L, lua_gettop(L));  // clear stack, not used

    char buf[MAX_STRKEY];
    struct entry_t *e = NULL;
    struct radix_node *rn = lua_touserdata(L, lua_upvalueindex(2));
    int inclusive = lua_tointeger(L, lua_upvalueindex(3));
    int mlen;
    size_t dummy;
    uint8_t addr[MAX_BINKEY], mask[MAX_BINKEY];

    /* fprintf(stderr, "iter-more\n"); */
    if (rn == NULL) return 0;     /* we're done */
    if (!isvalid(rn)) return 0;   /* TODO: error: rn was deleted */
    if(!check_binkey(L, lua_upvalueindex(4), addr, &dummy)) return 0;
    if(!check_binkey(L, lua_upvalueindex(5), mask, &dummy)) return 0;
    mlen = key_tolen(mask);
    mlen = inclusive ? mlen : mlen + 1;

    while (rn) {

        if(key_tolen(rn->rn_mask) >= mlen
                && key_isin(addr, rn->rn_key, mask)) {

            /* fprintf(stderr, " -> match!\n"); */
            e = (entry_t *)rn;
            lua_pushfstring(L, "%s/%d",
                    key_tostr(buf, e->rn[0].rn_key),
                    key_tolen(e->rn[0].rn_mask));
            lua_rawgeti(L, LUA_REGISTRYINDEX, *(int *)e->value);

            rn = rdx_nextleaf(rn);

            lua_pushlightuserdata(L, rn);
            lua_replace(L, lua_upvalueindex(2));

            return 2;

        }
        /* keys still within the inclusive range? */
        if(key_isin(addr, rn->rn_key, mask))
            rn = rdx_nextleaf(rn);
        else
            return 0; /* all done */
    }
    return 0; /* NOT REACHED */
}

/*
 * iter_radix()  <--  [ud k] ([nil nil] at first call)
 *
 * - return current node as a Lua table or nil to stop iteration
 * - save next (type, node) as upvalues (1) resp. (2)
 *
 */

static int
iter_radix(lua_State *L)
{
    dbg_stack("inc(.) <--");

    table_t *t = check_table(L, 1);
    void *node;
    int type;

    if (! rdx_nextnode(t, &type, &node)) return 0; // we're done

    dbg_msg(">> node %p, type %d", node, type);

    switch (type) {
        case TRDX_NODE_HEAD:
            return push_rdx_node_head(L, node);
        case TRDX_HEAD:
            return push_rdx_head(L, node);
        case TRDX_NODE:
            if (! isvalid(node)) return 0;         // rn got deleted
            return push_rdx_node(L, node);
        case TRDX_MASK_HEAD:
            return push_rdx_mask_head(L, node);
        case TRDX_MASK:
            return push_rdx_mask(L, node);
    }

    dbg_msg(" `-> unhandled node type %d!", type);

    return 0;
}

// iter_radix helpers

static void
iptL_push_fstr(lua_State *L, const char *k, const char *fmt, const void *v)
{
    if (! lua_istable(L, -1)) {
        dbg_msg("need stack top to be a %s", "table");
        dbg_stack("not a table? ->");
        return;
    }
    lua_pushstring(L, k);
    lua_pushfstring(L, fmt, v);
    lua_settable(L, -3);
}

static void
iptL_push_int(lua_State *L, const char *k, int v)
{
    if (! lua_istable(L, -1)) {
        dbg_msg("need stack top to be a %s", "table");
        dbg_stack("not a table ? ->");
        return;
    }
    lua_pushstring(L, k);
    lua_pushinteger(L, v);
    lua_settable(L, -3);
}


static int
push_rdx_node_head(lua_State *L, struct radix_node_head *rnh)
{
    // create table and populate its fields for rnh
    dbg_stack("inc(.) <--");

    lua_newtable(L);
    iptL_push_fstr(L, "_MEM_", "%p", rnh);
    iptL_push_int(L, "_TYPE_", TRDX_NODE_HEAD);
    iptL_push_fstr(L, "_NAME_", "%s", "RADIX_NODE_HEAD");

    // rh goes into a subtable
    lua_pushliteral(L, "rh");
    push_rdx_head(L, &rnh->rh);
    lua_settable(L, -3);

    // rnh_nodes -> {_MEM_,..{{RDX[0]}, {RDX[1]}, {RDX[2]}}}
    lua_pushliteral(L, "rnh_nodes");

    // new subtable: array of 3 RDX nodes; table has MEM/NAME but no type
    lua_newtable(L);
    iptL_push_fstr(L, "_MEM_", "%p", rnh->rnh_nodes);
    iptL_push_fstr(L, "_NAME_", "%s", "RNH_NODES[3]");
    lua_pushinteger(L, 1);
    push_rdx_node(L, &rnh->rnh_nodes[0]);
    lua_settable(L, -3);
    lua_pushinteger(L, 2);
    push_rdx_node(L, &rnh->rnh_nodes[1]);
    lua_settable(L, -3);
    lua_pushinteger(L, 3);
    push_rdx_node(L, &rnh->rnh_nodes[2]);
    lua_settable(L, -3);  // last entry is subtable

    lua_settable(L, -3);


    dbg_stack("out(1) ==>");
    return 1;
}

static int
push_rdx_node(lua_State *L, struct radix_node *rn)
{
    // create table and populate its fields for rn
    // - uses the convenience rn->field_names
    char key[MAX_STRKEY];
    dbg_stack("inc(.) <--");

    lua_newtable(L);

    iptL_push_fstr(L, "_MEM_", "%p", rn);
    iptL_push_int(L, "_TYPE_", TRDX_NODE);
    iptL_push_fstr(L, "_NAME_", "%s", "RADIX_NODE");

    iptL_push_fstr(L, "rn_mklist", "%p", rn->rn_mklist);
    iptL_push_fstr(L, "rn_parent", "%p", rn->rn_parent);
    iptL_push_int(L, "rn_bit", rn->rn_bit);
    // its a char, pushed as int => print("%02x", 0xff & int_val)
    iptL_push_int(L, "rn_bmask", rn->rn_bmask);
    iptL_push_int(L, "rn_flags", rn->rn_flags);

    // set _RNF_FLAGs_
    if (rn->rn_flags & RNF_NORMAL)
        iptL_push_int(L, "_NORMAL_", 1);
    if (rn->rn_flags & RNF_ROOT)
        iptL_push_int(L, "_ROOT_", 1);
    if (rn->rn_flags & RNF_ACTIVE)
        iptL_push_int(L, "_ACTIVE_", 1);

    if(RDX_ISLEAF(rn)) {
      iptL_push_int(L, "_LEAF_", 1);
      iptL_push_fstr(L, "rn_key", "%s", key_tostr(key, rn->rn_key));
      iptL_push_fstr(L, "rn_mask", "%s", key_tostr(key, rn->rn_mask));
      iptL_push_fstr(L, "rn_dupedkey", "%p", rn->rn_dupedkey);

      /* additional diagnostics */
      if (rn->rn_key)
        iptL_push_int(L, "_rn_key_LEN", 0xff & IPT_KEYLEN(rn->rn_key));
      else
        iptL_push_int(L, "_rn_key_LEN", -1);

      if (rn->rn_mask) {
        iptL_push_int(L, "_rn_mask_LEN", IPT_KEYLEN(rn->rn_mask));
        iptL_push_int(L, "_rn_mlen", key_tolen(rn->rn_mask));
      } else {
        iptL_push_int(L, "_rn_mask_LEN", -1); /* may happen in mask tree */
        iptL_push_int(L, "_rn_mlen", key_tolen(rn->rn_key));
      }


    } else {
      iptL_push_int(L, "_INTERNAL_", 1);
      iptL_push_int(L, "rn_offset", rn->rn_offset);
      iptL_push_fstr(L, "rn_left", "%p", rn->rn_left);
      iptL_push_fstr(L, "rn_right", "%p", rn->rn_right);
    }

    dbg_stack("out(1) ==>");

    return 1;
}

static int
push_rdx_head(lua_State *L, struct radix_head *rh)
{
    // create table and populate its fields for rn
    dbg_stack("inc(.) <--");

    lua_newtable(L);
    iptL_push_fstr(L, "_MEM_", "%p", rh);
    iptL_push_int(L, "_TYPE_", TRDX_HEAD);
    iptL_push_fstr(L, "_NAME_", "%s", "RADIX_HEAD");

    iptL_push_fstr(L, "rnh_treetop", "%p", rh->rnh_treetop);
    iptL_push_fstr(L, "rnh_masks", "%p", rh->rnh_masks);

    dbg_stack("out(1) ==>");

    return 1;
}

static int
push_rdx_mask_head(lua_State *L, struct radix_mask_head *rmh)
{
    // create table and populate its fields for rn
    dbg_stack("inc(.) <--");

    lua_newtable(L);
    iptL_push_fstr(L, "_MEM_", "%p", rmh);
    iptL_push_int(L, "_TYPE_", TRDX_MASK_HEAD);
    iptL_push_fstr(L, "_NAME_", "%s", "RADIX_MASK_HEAD");

    lua_pushliteral(L, "head");
    push_rdx_head(L, &rmh->head);
    lua_settable(L, -3);

    lua_pushliteral(L, "mask_nodes");

    // new subtable: an array of 3 radix_node's
    lua_newtable(L);
    iptL_push_fstr(L, "_MEM_", "%p", rmh->mask_nodes);
    iptL_push_fstr(L, "_NAME_", "%s", "MASK_NODES[3]");
    lua_pushinteger(L, 1);
    push_rdx_node(L, &rmh->mask_nodes[0]);
    lua_settable(L, -3);
    lua_pushinteger(L, 2);
    push_rdx_node(L, &rmh->mask_nodes[1]);
    lua_settable(L, -3);
    lua_pushinteger(L, 3);
    push_rdx_node(L, &rmh->mask_nodes[2]);
    lua_settable(L, -3);

    lua_settable(L, -3);  // mask_nodes -> subtable/array

    dbg_stack("out(1) ==>");

    return 1;
}

static int
push_rdx_mask(lua_State *L, struct radix_mask *rm)
{
    // create table and populate its fields for rn
    dbg_stack("inc(.) <--");

    char key[MAX_STRKEY];

    lua_newtable(L);
    iptL_push_fstr(L, "_MEM_", "%p", rm);
    iptL_push_int(L, "_TYPE_", TRDX_MASK);
    iptL_push_fstr(L, "_NAME_", "%s", "RADIX_MASK");

    iptL_push_int(L, "rm_bit", rm->rm_bit);
    iptL_push_int(L, "rm_unused", rm->rm_unused);
    iptL_push_int(L, "rm_flags", rm->rm_flags);

    // set _RNF_FLAGs_
    if (rm->rm_flags & RNF_NORMAL) iptL_push_int(L, "_NORMAL_", 1);
    if (rm->rm_flags & RNF_ROOT)   iptL_push_int(L, "_ROOT_", 1);
    if (rm->rm_flags & RNF_ACTIVE) iptL_push_int(L, "_ACTIVE_", 1);

    iptL_push_fstr(L, "rm_mklist", "%p", rm->rm_mklist);
    iptL_push_int(L, "rm_refs", rm->rm_refs);

    if (rm->rm_flags & RNF_NORMAL) {
      // NOTE: if its a NORMAL 'radix_mask' then union -> rm_leaf else rm_mask
      // - see radix.c:377 and and radix.c:773
      iptL_push_int(L, "_LEAF_", 1);
      iptL_push_fstr(L, "rm_leaf", "%p", rm->rm_leaf);

    } else {
      iptL_push_int(L, "_INTERNAL_", 1);
      iptL_push_fstr(L, "rm_mask", "%s", key_tostr(key, rm->rm_mask));
    }

    dbg_stack("out(1) ==>");

    return 1;
}


// iptable module functions

/*
 * .new()  <--  []
 *
 * Create and return a new iptable instance.
 *
 * - void** t -> so tbl_destroy(&t) sets t=NULL when done clearing it
 * - Return a new iptable instance.  Bail on memory errors.
 *
 */

static int
ipt_new(lua_State *L)
{
    dbg_stack("inc(.) <--");

    void **t = lua_newuserdata(L, sizeof(void **));
    *t = tbl_create(refp_delete);             // usr_delete func to free values

    if (*t == NULL) {
        lua_pushliteral(L, "error creating iptable");
        lua_error(L);
    }

    luaL_getmetatable(L, LUA_IPTABLE_ID); // [ud M]
    lua_setmetatable(L, 1);

    dbg_stack("out(1) ==>");

    return 1;
}

/*
 * .tobin()  <--  [str]
 *
 * Return byte array for binary key, masklength & AF for a given prefix, nil on
 * errors.  Note: byte array is [LEN-byte | key-bytes].
 *
 */

static int
ipt_tobin(lua_State *L)
{
    dbg_stack("inc(.) <--");

    int af, mlen;
    uint8_t addr[MAX_BINKEY];
    size_t len = 0;
    const char *pfx = check_pfxstr(L, 1, &len);

    if (! key_bystr(addr, &mlen, &af, pfx)) return 0;

    lua_pushlstring(L, (const char *)addr, IPT_KEYLEN(addr));
    lua_pushinteger(L, mlen);
    lua_pushinteger(L, af);

    dbg_stack("out(3) ==>");

    return 3;
}

/*
 * tostr()  <--  [binkey]
 *
 * Return string representation for a binary key, nil on errors
 *
 */

static int
ipt_tostr(lua_State *L)
{
    dbg_stack("inc(.) <--");

    uint8_t key[MAX_BINKEY];
    char str[MAX_STRKEY];
    size_t len = 0;

    if (!check_binkey(L, 1, key, &len)) return 0;
    if (len != (size_t)IPT_KEYLEN(key)) return 0; // illegal binary
    if (key_tostr(str, key) == NULL) return 0;

    lua_pushstring(L, str);

    dbg_stack("out(1) ==>");

    return 1;
}

/*
 * .tolen()  <--  [key]
 *
 * Return the number of consecutive msb 1-bits, nil on errors.
 * - stops at the first zero bit.
 *
 */

static int
ipt_tolen(lua_State *L)
{
    dbg_stack("inc(.) <--");

    uint8_t buf[MAX_BINKEY];
    size_t len = 0;
    int mlen = -1;

    if (!check_binkey(L, 1, buf, &len)) return 0;

    mlen = key_tolen(buf);
    lua_pushinteger(L, mlen);

    dbg_stack("out(1) ==>");

    return 1;
}

/*
 * .size()  <--  [pfx]
 *
 * Returns the number of hosts in a given prefix, nil on errors
 * - uses Lua's arithmatic (2^hostbits), since ipv6 can get large.
 *
 */

static int
ipt_size(lua_State *L)
{
    dbg_stack("inc(.) <--");

    uint8_t addr[MAX_BINKEY];
    size_t len = 0;
    int af = AF_UNSPEC, mlen = -1, hlen = -1;
    const char *pfx = NULL;

    pfx = check_pfxstr(L, 1, &len);
    if (! key_bystr(addr, &mlen, &af, pfx)) return 0;
    if (AF_UNKNOWN(af)) return 0;

    hlen = af == AF_INET ? IP4_MAXMASK : IP6_MAXMASK;
    hlen = mlen < 0 ? 0 : hlen - mlen;              // mlen<0 means host addr
    lua_pushinteger(L, 2);
    lua_pushinteger(L, hlen);
    lua_arith(L, LUA_OPPOW);
    dbg_stack("out(1) ==>");

    return 1;
}

/*
 * .address()  <--  [str]
 *
 * Return host address, masklen and af_family for pfx; nil on errors.
 *
 */

static int
ipt_address(lua_State *L)
{
    dbg_stack("inc(.) <--");

    char buf[MAX_STRKEY];
    uint8_t addr[MAX_BINKEY], mask[MAX_BINKEY];
    size_t len = 0;
    int af = AF_UNSPEC, mlen = -1;
    const char *pfx = NULL;

    pfx = check_pfxstr(L, 1, &len);
    if (! key_bystr(addr, &mlen, &af, pfx)) return 0;
    if (! key_bylen(mask, mlen, af)) return 0;
    if (! key_tostr(buf, addr)) return 0;

    lua_pushstring(L, buf);
    lua_pushinteger(L, mlen);
    lua_pushinteger(L, af);

    dbg_stack("out(3) ==>");

    return 3;
}

/*
 * .network()  <--  [pfx]
 *
 * Return network address, masklen and af_family for pfx; nil on errors.
 *
 */

static int
ipt_network(lua_State *L)
{
    dbg_stack("inc(.) <--");

    char buf[MAX_STRKEY];
    uint8_t addr[MAX_BINKEY], mask[MAX_BINKEY];
    size_t len = 0;
    int af = AF_UNSPEC, mlen = -1;
    const char *pfx = NULL;

    pfx = check_pfxstr(L, 1, &len);
    if (! key_bystr(addr, &mlen, &af, pfx)) return 0;
    if (! key_bylen(mask, mlen, af)) return 0;
    if (! key_network(addr, mask)) return 0;
    if (! key_tostr(buf, addr)) return 0;

    lua_pushstring(L, buf);
    lua_pushinteger(L, mlen);
    lua_pushinteger(L, af);

    dbg_stack("out(3) ==>");

    return 3;
}

/*
 * .neighbor()  <--  [str]
 *
 * Given a prefix, return the neighbor prefix, masklen and af_family, such that
 * both can be combined into a supernet with masklen -1; nil on errors.
 *
 */

static int
ipt_neighbor(lua_State *L)
{
    dbg_stack("inc(.) <--");

    char buf[MAX_STRKEY];
    uint8_t addr[MAX_BINKEY], mask[MAX_BINKEY], nbor[MAX_BINKEY];
    size_t len = 0;
    int af = AF_UNSPEC, mlen = -1;
    const char *pfx = NULL;

    pfx = check_pfxstr(L, 1, &len);
    if (! key_bystr(addr, &mlen, &af, pfx)) return 0;
    if (mlen == 0) return 0;                        /* 0/0 has no neighbor */
    if (! key_bylen(mask, mlen, af)) return 0;
    if (! key_bypair(nbor, addr, mask)) return 0;
    if (! key_tostr(buf, nbor)) return 0;

    lua_pushstring(L, buf);
    lua_pushinteger(L, mlen);
    lua_pushinteger(L, af);

    dbg_stack("out(3) ==>");

    return 3;
}

/* .broadcast()  <--  [pfx]
 *
 * Return broadcast address, masklen and af_family for pfx; nil on errors.
 *
 */

static int
ipt_broadcast(lua_State *L)
{
    dbg_stack("inc(.) <--");

    int af = AF_UNSPEC, mlen = -1;
    size_t len = 0;
    char buf[MAX_STRKEY];
    uint8_t addr[MAX_BINKEY], mask[MAX_BINKEY];
    const char *pfx = NULL;

    pfx = check_pfxstr(L, 1, &len);
    if (! key_bystr(addr, &mlen, &af, pfx)) return 0;
    if (! key_bylen(mask, mlen, af)) return 0;
    if (! key_broadcast(addr, mask)) return 0;
    if (! key_tostr(buf, addr)) return 0;

    lua_pushstring(L, buf);
    lua_pushinteger(L, mlen);
    lua_pushinteger(L, af);

    dbg_stack("out(3) ==>");

    return 3;
}

/*
 * iptable.mask()  <--  [num]
 *
 * Returns mask (as string) for mlen bits given, Nil on errors
 * - mlen < 0 means inverse mask of mlen, so mlen = -8 -> 0.255.255.255
 *
 * TODO: normally mlen==-1 means 'no mask present so default to MAXMASK', but
 * here we deviate.  Better to create imask(af, mlen) and maintain the notion
 * of mlen==-1 and return an inverse mask of max mask.
 *
 */

static int
ipt_mask(lua_State *L)
{
    dbg_stack("inc(.) <--");

    int af = AF_UNSPEC, mlen = -1, isnum = 0;
    char buf[MAX_STRKEY];
    uint8_t mask[MAX_BINKEY];

    af = lua_tointegerx(L, 1, &isnum);
    if (! isnum) return 0;
    if (AF_UNKNOWN(af)) return 0;

    mlen = lua_tointegerx(L, 2, &isnum);
    if (! isnum) return 0;
    if (! key_bylen(mask, mlen < 0 ? -mlen : mlen, af)) return 0;
    if (mlen < 0 && ! key_invert(mask)) return 0;
    if (! key_tostr(buf, mask)) return 0;

    lua_pushstring(L, buf);

    dbg_stack("out(1) ==>");

    return 1;
}


/*
 * .hosts()  <--  [pfx incl], incl is optional.
 *
 * Iterate across host adresses in prefix pfx, if incl is true, the network
 * and broadcast addresses are included as well.
 *
 */

static int
ipt_hosts(lua_State *L)
{
    dbg_stack("inc(.) <--");

    size_t len = 0;
    int af = AF_UNSPEC, mlen = -1, inclusive = 0;
    int fail = 0;  // even on failure, gotta push iterfunc with 2 upvalues
    uint8_t addr[MAX_BINKEY], mask[MAX_BINKEY], stop[MAX_BINKEY];
    const char *pfx = NULL;

    if (lua_gettop(L) == 2 && lua_isboolean(L, 2))
        inclusive = lua_toboolean(L, 2);  // include netw/bcast (or not)

    pfx = check_pfxstr(L, 1, &len);
    if (! key_bystr(addr, &mlen, &af, pfx)) fail = 1;
    if (! key_bystr(stop, &mlen, &af, pfx)) fail = 1;
    if (! key_bylen(mask, mlen, af)) fail = 1;
    if (! key_network(addr, mask)) fail = 1;           // start = network
    if (! key_broadcast(stop, mask)) fail = 1;         // stop = bcast

    if (inclusive)                                     // incl network/bcast?
        key_incr(stop);
    else if (key_cmp(addr, stop) < 0)
        key_incr(addr);  // not inclusive, so donot 'iterate' a host ip addr.

    if (fail) {
        lua_pushnil(L);
        lua_pushnil(L);
        dbg_stack("fail! 2+");
    } else {
        lua_pushlstring(L, (const char *)addr, IPT_KEYLEN(addr));
        lua_pushlstring(L, (const char *)stop, IPT_KEYLEN(stop));
        dbg_stack("suc6! 2+");
    }
    lua_pushcclosure(L, iter_hosts, 2);  // [.., func]

    dbg_stack("out(1) ==>");

    return 1;
}

// iptable instance methods

/*
 * _gc()  <--  [t]
 *
 * Garbage collect the table: free all resources
 *
 */

static int
_gc(lua_State *L) {
    dbg_stack("inc(.) <--");

    table_t *t = check_table(L, 1);
    tbl_destroy(&t, L);

    dbg_stack("out(0) ==>");

    return 0;
}

/*
 * _newindex()  <-- [t k v]
 *
 * Implements t[k] = v
 *
 * If v is nil, t[k] is deleted.  Otherwise, v is stored in the lua_registry
 * and its ref-value is stored in the radix tree. If k is not a valid ipv4/6
 * prefix, cleanup and ignore the request.
 *
 */

static int
_newindex(lua_State *L)
{
    dbg_stack("inc(.) <--");

    const char *pfx = NULL;
    size_t len = 0;
    table_t *t = check_table(L, 1);
    int *refp = NULL;

    pfx = check_pfxstr(L, 2, &len);
    dbg_msg("got pfx %s", pfx);

    if (lua_isnil(L, -1)) {
        dbg_msg("tbl_del on %s", pfx);
        tbl_del(t, pfx, L);
    }
    else {
        if ((refp = refp_create(L)))
            if (! tbl_set(t, pfx, refp, L))
                refp_delete(L, (void**)&refp);
    }

    dbg_stack("out(0) ==>");

    return 0;
}

/*
 * __index()  <--  [t k]
 *
 * Given index k:
 *  - do longest prefix search if k is a prefix without mask,
 *  - do an exact match if k is a prefix with a mask
 *  - otherwise, do metatable lookup for property named by k.
 *
 */

static int
_index(lua_State *L)
{
    dbg_stack("inc(.) <--");

    entry_t *entry = NULL;
    size_t len = 0;
    const char *pfx = NULL;

    table_t *t = check_table(L, 1);
    pfx = check_pfxstr(L, 2, &len);

    if(pfx)
        entry = strchr(pfx, '/') ? tbl_get(t, pfx) : tbl_lpm(t, pfx);

    if(entry)
        lua_rawgeti(L, LUA_REGISTRYINDEX, *(int *)entry->value); // [tbl k v]
    else {
        if (luaL_getmetafield(L, 1, pfx) == LUA_TNIL)
            return 0;
    }

    dbg_stack("out(1) ==>");

    return 1;
}

/*
 * _len()  <--  [t]
 *
 * Return the sum of the number of entries in the ipv4 and ipv6 radix trees as
 * the 'length' of the table.
 *
 */

static int
_len(lua_State *L)
{
    dbg_stack("inc(.) <--");

    table_t *t = check_table(L, 1);
    lua_pushinteger(L, t->count4 + t->count6);

    dbg_stack("out(1) ==>");

    return 1;
}

/*
 * _tostring()  <--  [t]
 *
 * Return a string representation of the iptable instance (with counts).
 *
 */

static int
_tostring(lua_State *L)
{
    dbg_stack("inc(.) <--");

    table_t *t = check_table(L, 1);
    lua_pushfstring(L, "iptable{#ipv4=%d, #ipv6=%d}", t->count4, t->count6);

    dbg_stack("out(1) ==>");

    return 1;
}

/*
 * :counts()  <--  [t]
 *
 * Return both ipv4 and ipv6 counts as two numbers.
 *
 */

static int
counts(lua_State *L)
{
    dbg_stack("inc(.) <--");

    table_t *t = check_table(L, 1);
    lua_pushinteger(L, t->count4);         // [t count4]
    lua_pushinteger(L, t->count6);         // [t count4 count6]

    dbg_stack("out(2) ==>");

    return 2;                              // [.., count4, count6]
}

/*
 * _pairs()  <--  [t]
 *
 * Setup iteration across key,value-pairs in the table.  The first ipv4 or ipv6
 * leaf node is pushed.  The iter_pairs iterator uses nextleaf to go through
 * all leafs of the tree.  It will traverse ipv6 as well if we started with the
 * ipv4 tree first.
 *
 */

static int
_pairs(lua_State *L)
{
    dbg_stack("inc(.) <--");

    table_t *t = check_table(L, 1);
    struct radix_node *rn = rdx_firstleaf(&t->head4->rh);
    if (rn == NULL)
        rn = rdx_firstleaf(&t->head6->rh);

    if (rn == NULL) return iter_bail(L);

    lua_pushlightuserdata(L, rn);        // [t rn], rn is 1st node
    lua_pushcclosure(L, iter_kv, 1);     // [t f], rn as upvalue(1)
    lua_rotate(L, 1, 1);                 // [f t]
    lua_pushnil(L);                      // [f t nil]

    dbg_stack("out(3) ==>");

    return 3;                            // [iter_f invariant ctl_var]
}

/*
 * subtree_fail()
 *
 * Checks correct subtree after descending down a tree.
 *
 */

static inline int
subtree_fail(struct radix_node *rn, int mlen) {
  return RDX_ISROOT(rn)
      && RDX_ISLEAF(rn)
      && mlen !=0
      && !(rn->rn_dupedkey);
}

/*
 * :more()  <--  [t pfx bool], bool is optional
 *
 * Iterate across more specific prefixes. AF_family is deduced from the
 * prefix given.  Note this traverses the entire tree if pfx has a /0 mask.
 *
 */
static int
more_org(lua_State *L)
{
    dbg_stack("inc(.) <--");

    size_t len = 0;
    int af = AF_UNSPEC, mlen = -1, maxb = -1;
    uint8_t addr[MAX_BINKEY], mask[MAX_BINKEY];
    struct radix_node_head *head = NULL;
    struct radix_node *rn = NULL, *top = NULL;

    table_t *t = check_table(L, 1);
    const char *pfx = check_pfxstr(L, 2, &len);

    if (! key_bystr(addr, &mlen, &af, pfx)) {
        /* TODO: err hdlr - set errno & bail: iter_bail(L, errno) */
        lua_pushfstring(L, "more(): invalid prefix %s", lua_tostring(L, 2));
        lua_error(L);
    }
    if (lua_gettop(L) == 3 && lua_isboolean(L, 3))
        maxb = 0;

    lua_pop(L, lua_gettop(L) - 1);  // [t]

    if (af == AF_INET) {
      head = t->head4;
      mlen = mlen < 0 ? IP4_MAXMASK : mlen;
    } else if (af == AF_INET6) {
      head = t->head6;
      mlen = mlen < 0 ? IP6_MAXMASK : mlen;
    } else return iter_bail(L);

    if (! key_bylen(mask, mlen, af) || ! key_network(addr, mask)) {
        /* TODO: err hdlr - set errno & bail: iter_bail(L, errno) */
        lua_pushliteral(L, "more(): error converting prefix");
        lua_error(L);
    }

    /*
     * rn_bit >= maxb, and in case mlen==0 and 0/0 is present in the tree,
     * it's rn_bit is -1 and not -1-IPT_KEYOFFSET-mlen like for all other
     * leafs
     *
     */

    maxb = (mlen == 0) ? maxb - 1 : maxb - 1 - IPT_KEYOFFSET - mlen;

    /* descend the tree towards a possible matching leaf */
    for(rn = head->rh.rnh_treetop; !RDX_ISLEAF(rn);)
        if (addr[rn->rn_offset] & rn->rn_bmask)
            rn = rn->rn_right;
        else
            rn = rn->rn_left;

    /* go up to INTERNAL node governing the tree of this leaf */
    for(top=rn->rn_parent; top->rn_bit>mlen+IPT_KEYOFFSET; top=top->rn_parent)
        if (RDX_ISROOT(top)) break;

    /* goto LEFT subtree, first LEAF */
    for (rn = top; !RDX_ISLEAF(rn); rn=rn->rn_left)
        ;

    /*
     * If the search ends up on the default ROOT 0/0 node, it has failed if
     * mlen != 0 and no matches are possible.  Note: ROOT's 0.0.0.0 rn_key has
     * a keylength of 0 bytes(!) and thus will always match any other key when
     * using key_isin to check for a match.  Hence the first check is for a
     * subtree failure and then a key_isin check is done.
     *
     * If the search ends up on some 'real' LEAF node, key_isin can be used to
     * check the leaf actually matches.  Required since the trie is path
     * compressed.
     *
     */

    if (subtree_fail(rn, mlen) || !key_isin(addr, rn->rn_key, mask)) {
        /* switch to RIGHT subtree */
        for (rn = top->rn_right; !RDX_ISLEAF(rn); rn=rn->rn_left)
            ;
        if (subtree_fail(rn, mlen) || !key_isin(addr, rn->rn_key, mask))
          rn = NULL;
    }

    /* the upvalues for the iterator: subtreetop, current node & maxbit */
    if (rn && RDX_ISLEAF(rn)) {
        char buf[MAX_STRKEY];
        printf("more start found %s/%d, top's rn_bit %d\n",
            key_tostr(buf, rn->rn_key), key_tolen(rn->rn_mask),
            top->rn_bit);
    }
    lua_pushlightuserdata(L, top);
    lua_pushlightuserdata(L, rn);
    lua_pushinteger(L, maxb);
    lua_pushlstring(L, (const char *)addr, (size_t)IPT_KEYLEN(addr));
    lua_pushlstring(L, (const char *)mask, (size_t)IPT_KEYLEN(mask));

                                                   // [t top rn max addr mask]
    lua_pushcclosure(L, iter_more_org, 5);         // [t f]
    lua_rotate(L, 1, 1);                           // [f t]
    lua_pushnil(L);                                // [f t nil]

    dbg_stack("out(1) ==>");  // [iter_f invariant ctl_var]

    return 3;
}

static int
more(lua_State *L)
{
    dbg_stack("inc(.) <--");

    size_t len = 0;
    int af = AF_UNSPEC, mlen = -1, maxb = -1;
    uint8_t addr[MAX_BINKEY], mask[MAX_BINKEY];
    struct radix_node_head *head = NULL;
    struct radix_node *rn = NULL, *top = NULL;
    int inclusive = 0;

    table_t *t = check_table(L, 1);
    const char *pfx = check_pfxstr(L, 2, &len);

    /* fprintf(stderr, "-1-\n"); */
    if (! key_bystr(addr, &mlen, &af, pfx)) {
        /* TODO: err hdlr - set errno & bail: iter_bail(L, errno) */
        lua_pushfstring(L, "more(): invalid prefix %s", lua_tostring(L, 2));
        lua_error(L);
    }
    if (lua_gettop(L) == 3 && lua_isboolean(L, 3))
        inclusive = 1;
    if (af == AF_INET) {
      head = t->head4;
      mlen = mlen < 0 ? IP4_MAXMASK : mlen;
    } else if (af == AF_INET6) {
      head = t->head6;
      mlen = mlen < 0 ? IP6_MAXMASK : mlen;
    } else return iter_bail(L);
    if (! key_bylen(mask, mlen, af) || ! key_network(addr, mask)) {
        /* TODO: err hdlr - set errno & bail: iter_bail(L, errno) */
        lua_pushliteral(L, "more(): error converting prefix");
        lua_error(L);
    }
    lua_pop(L, lua_gettop(L) - 1);  // [t]

    maxb = (mlen > 0) ? -1 - IPT_KEYOFFSET - mlen : -2;
    for(top = head->rh.rnh_treetop; !RDX_ISLEAF(top) && top->rn_bit >= maxb;)
        if (addr[top->rn_offset] & top->rn_bmask)
            top = top->rn_right;
        else
            top = top->rn_left;

    for (rn = top->rn_parent; !RDX_ISLEAF(rn);)  /* first, left-most, leaf */
        rn = rn->rn_left;

    /* iterator upvalues: sub-treetop, fst-leaf, inclusive, addr, mask */
    lua_pushlightuserdata(L, top);  // stay below this node
    lua_pushlightuserdata(L, rn);   // first possible match in subtree
    lua_pushinteger(L, inclusive);
    lua_pushlstring(L, (const char *)addr, (size_t)IPT_KEYLEN(addr));
    lua_pushlstring(L, (const char *)mask, (size_t)IPT_KEYLEN(mask));
    lua_pushcclosure(L, iter_more, 5);            // [t f]
    lua_rotate(L, 1, 1);                          // [f t]

    dbg_stack("out(1) ==>");

    return 2;                                     // [iter_f invariant]
}

/*
 * :less()  <--  [t pfx incl]
 *
 * Iterate across prefixes in the tree that are less specific than pfx.
 * - search may include pfx itself in the results, if incl is true.
 * - iter_less takes (pfx, mlen, af)
 *
 */

static int
less(lua_State *L)
{
    dbg_stack("inc(.) <--");

    size_t len = 0;
    int mlen = 0, inclusive = 0, af = AF_UNSPEC;
    uint8_t addr[MAX_BINKEY];
    const char *pfx;
    char buf[MAX_STRKEY];

    pfx = check_pfxstr(L, 2, &len);
    if (pfx == NULL || len < 1) return iter_bail(L);

    if (lua_gettop(L) > 2 && lua_isboolean(L, 3))
      inclusive = lua_toboolean(L, 3);

    lua_pop(L, lua_gettop(L) - 1);                        // [t]

    if (! key_bystr(addr, &mlen, &af, pfx)) return iter_bail(L);
    if (! key_tostr(buf, addr)) return iter_bail(L);

    if (af == AF_INET)
      mlen = mlen < 0 ? IP4_MAXMASK : mlen;
    else if (af == AF_INET6)
      mlen = mlen < 0 ? IP6_MAXMASK : mlen;
    else return iter_bail(L);                // unknown AF
    mlen = inclusive ? mlen : mlen -1;
    if (mlen < 0) return iter_bail(L);       // non-inclusive less than /0

    lua_pushstring(L, buf);                              // [t pfx]
    lua_pushinteger(L, mlen);                            // [t pfx mlen]
    lua_pushcclosure(L, iter_less, 2);                   // [t f]
    lua_rotate(L, 1, 1);                                 // [f t]

    dbg_stack("out(2) ==>");

    return 2;     // [iter_f invariant] (ctl_var not needed)
}

/*
 * :masks(af)  <--  [t af]
 *
 * Iterate across all masks used in AF_family's radix tree.
 * Notes:
 * - a mask tree stores masks in rn_key fields.
 * - a mask's KEYLEN == nr of non-zero mask bytes, rather LEN of byte array.
 * - a /0 (zeromask) is never stored in the radix mask tree (!).
 * - a /0 (zeromask) is stored in ROOT(0.0.0.0)'s *last* dupedkey-chain leaf.
 * - the AF_family cannot be deduced from the mask in rn_key.
 *
 * So, the iter_f needs the AF to properly format masks for the given family
 * (an ipv6/24 mask would otherwise come out as 255.255.255.0) and an explicit
 * flag needs to be passed to iter_f that a zeromask entry is present.
 *
 */

static
int masks(lua_State *L) { 

    dbg_stack("inc(.) <--");                         // [t af]

    uint8_t binmask[MAX_BINKEY];
    char strmask[MAX_STRKEY];

    struct radix_node_head *rnh;
    struct radix_node *rn;
    int isnum = 0, af = AF_UNSPEC;
    table_t *t = check_table(L, 1);

    if (lua_gettop(L) != 2)
        return iter_bail(L);                         // no AF_family

    af = lua_tointegerx(L, 2, &isnum);
    if (!isnum || AF_UNKNOWN(af))
        return iter_bail(L);                         // bad AF_family
    lua_pop(L, 1);                                   // [t]

    rnh = (af == AF_INET) ? t->head4 : t->head6;

    /*
     * Do an explicit check for a /0 mask in af_family's key-radix tree
     *
     * The mask_tree stores all the masks used in the radix tree (for actual
     * keys), except for the /0 mask itself. Its use is only visible as the
     * last dupedkey key child of the left-end marker having rn_bit == -1.
     * (i.e. -1 - networkindex (of 0) == -1).
     *
     */

    rn = &rnh->rnh_nodes[0];
    while (rn->rn_dupedkey)
        rn = rn->rn_dupedkey;
    if (!RDX_ISROOT(rn) && rn->rn_bit == -1) {
        key_bylen(binmask, 0, af);
        key_tostr(strmask, binmask);
    } else {
        strmask[0] = '\0';
    }

    /*
     * find first leaf in mask tree, maybe NULL if all that is stored in the
     * tree is a single, explicit 0/0 entry in which case only the zero-mask
     * needs to be returned by iter_masks
     *
     */

    rn = rdx_firstleaf(&rnh->rh.rnh_masks->head);
    lua_pushlightuserdata(L, rn);                    // [t rn]
    lua_pushinteger(L, af);                          // [t rn af]
    lua_pushstring(L, strmask);                      // [t rn af zm]
    lua_pushcclosure(L, iter_masks, 3);              // [t f]
    lua_rotate(L, 1, 1);                             // [f t]

    dbg_stack("out(2) ==>");

    return 2;                                        // [iter_f invariant]
}

/*
 * :merge(af)  <--  [t, af]
 *
 * Iterate across groups of pfx's that may be combined
 */

static int
merge(lua_State *L)
{
    dbg_stack("inc(.) <--");

    struct radix_node *rn;
    table_t *t = check_table(L, 1);
    int af = lua_tointeger(L, 2);

    if (af == AF_INET)
        rn = rdx_firstleaf(&t->head4->rh);
    else if (af == AF_INET6)
        rn = rdx_firstleaf(&t->head6->rh);
    else return iter_bail(L);

    lua_pop(L, 1);                            // [t]
    lua_pushlightuserdata(L, rn);             // [t rn]
    lua_pushcclosure(L, iter_merge, 1);       // [t f]
    lua_rotate(L, 1, -1);                     // [f t]

    dbg_stack("out(2) ==>");

    return 2;                                 // [iter_f invariant]
}

/*
 * :radix(af)  <--  [t af]
 *
 * Iterate across all nodes of all types in a radix tree.
 * - returns the C-structs as Lua tables.
 * TODO: :radix(af, maskp)  <-- change this:
 *  - take a single AF_family as iteration target, and
 *  - a boolean that says to include the mask tree or not.
 */

static int
radixes(lua_State *L)
{
    dbg_stack("inc(.) <--");

    int isnum = 0, af = AF_UNSPEC, afs = IPT_UNSPEC;
    table_t *t = check_table(L, 1);

    if (lua_gettop(L) < 2) {
        lua_pushfstring(L, "ipt:radixes(): need AF_INET, AF_INET6 or both");
        lua_error(L);
    }

    /* get all af families given */
    while(lua_gettop(L) > 1) {
      af = lua_tointegerx(L, lua_gettop(L), &isnum);
      lua_pop(L, 1);
      if (!isnum || AF_UNKNOWN(af)) {
        lua_pushfstring(L, "ipt:radixes(): unknown AF_family %d", af);
        lua_error(L);
      }
      /* translate AF_fam to IPT_fam, which are powers of two */
      switch (af) {
        case AF_INET:
          afs |= IPT_INET;
          break;
        case AF_INET6:
          afs |= IPT_INET6;
          break;
        default:
          dbg_msg("unknown AF_family (%d)", af);
          lua_pushfstring(L, "Address family (%d) not supported", af);
          lua_error(L);
      }
    }

    if (! rdx_firstnode(t, afs)) return iter_bail(L);

    dbg_stack("upvalues(0)");

    lua_pushcclosure(L, iter_radix, 0);             // [t_ud iter_f]
    lua_rotate(L, 1, 1);                            // [iter_f t_ud]

    dbg_stack("out(2) ==>");

    return 2;                                       // [iter_f invariant]
}
