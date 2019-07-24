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
#define LUA_IPT_ITR_GC "itr_gc"

/* iterator for-loop break protection
 *
 * Iterators traverse the tree by hopping from leaf to leaf and keep a pointer
 * to the next hop in order to be able to continue.  During iteration, the tree
 * is locked against actual radix node removal and nodes, when deleted, are
 * simply flagged for deferred deletion when no iterators are active.
 *
 * The ipt_iter_gc() function implements this deferred deletion.
 */

typedef struct itr_gc_t {
  table_t *t;
} itr_gc_t;

/* lua functions */

int luaopen_iptable(lua_State *);

/* helper funtions */

table_t *iptL_get_table(lua_State *, int);
static int iptL_get_binkey(lua_State *, int, uint8_t *, size_t *);
const char *iptL_get_pfxstr(lua_State *, int, size_t *);
static int ipt_itr_gc(lua_State *);
static int *iptL_refp_create(lua_State *);
static void iptL_refp_delete(void *, void **);
static int iter_bail(lua_State *);
static int iter_fail_f(lua_State *);

/* iter_xxx() helpers */

static void iptL_push_itr_gc(lua_State *, table_t *);
static void iptT_set_fstr(lua_State *, const char *, const char *, const void *);
static void iptT_set_int(lua_State *, const char *, int);
static void iptT_set_kv(lua_State *, struct radix_node *);
static int iptL_push_rnh(lua_State *, struct radix_node_head *);
static int iptL_push_rn(lua_State *, struct radix_node *);
static int iptL_push_rh(lua_State *, struct radix_head *);
static int iptL_push_rmh(lua_State *, struct radix_mask_head *);
static int iptL_push_rm(lua_State *, struct radix_mask *);


/* iterators */

static int iter_hosts_f(lua_State *);
static int iter_kv_f(lua_State *);
static int iter_less_f(lua_State *);
static int iter_masks_f(lua_State *);
static int iter_merge_f(lua_State *);
static int iter_more_f(lua_State *);
static int iter_radix(lua_State *);

/* iptable module functions */

static int ipt_address(lua_State *);
static int ipt_broadcast(lua_State *);
static int iter_hosts(lua_State *);
static int ipt_mask(lua_State *);
static int ipt_neighbor(lua_State *L);
static int ipt_network(lua_State *);
static int ipt_new(lua_State *);
static int ipt_size(lua_State *);
static int ipt_tobin(lua_State *);
static int ipt_tolen(lua_State *);
static int ipt_tostr(lua_State *);

/* iptable instance methods */

static int iptm_gc(lua_State *);
static int iptm_index(lua_State *);
static int iptm_newindex(lua_State *);
static int iptm_len(lua_State *);
static int iptm_tostring(lua_State *);
static int iptm_counts(lua_State *);
static int iter_kv(lua_State *);
static int iter_less(lua_State *);
static int iter_masks(lua_State *);
static int iter_merge(lua_State *);
static int iter_more(lua_State *);
static int iter_radixes(lua_State *);

/* iptable module function array */

static const struct luaL_Reg funcs [] = {
    {"address", ipt_address},
    {"broadcast", ipt_broadcast},
    {"hosts", iter_hosts},
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
    {"__gc", iptm_gc},
    {"__index", iptm_index},
    {"__newindex", iptm_newindex},
    {"__len", iptm_len},
    {"__tostring", iptm_tostring},
    {"__pairs", iter_kv},
    {"counts", iptm_counts},
    {"masks", iter_masks},
    {"merge", iter_merge},
    {"more", iter_more},
    {"less", iter_less},
    {"radixes", iter_radixes},
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

    /* LUA_IPT_ITR_GC metatable */
    luaL_newmetatable(L, LUA_IPT_ITR_GC);
    lua_pushstring(L, "__gc");
    lua_pushcfunction(L, ipt_itr_gc);
    lua_settable(L, -3);

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
 * check out an iptable at given index or fail  <--  [ .. t ..]
 *
 * Fails if index does not hold userdata with the correct metatable.
 */

table_t *
iptL_get_table(lua_State *L, int index)
{
    void **t = luaL_checkudata(L, index, LUA_IPTABLE_ID);
    luaL_argcheck(L, t != NULL, index, "`iptable' expected");
    return (table_t *)*t;
}

int iptL_get_int(lua_State *L, int, const char *);
int
iptL_get_int(lua_State *L, int idx, const char *msg)
{
    if (! lua_isinteger(L, idx)) {
        lua_pushstring(L, msg);
        lua_error(L);
    }
    return lua_tointeger(L, idx);

}

/*
 * check out an AF_family or default to 'af_default' given.
 * If af_default is NULL, this will raise an error if no known AF_family is
 * given.
 */

int iptL_get_af(lua_State *L, int, const char*);
int
iptL_get_af(lua_State *L, int idx, const char *af_default)
{
    static const char *const af_fam[] = {"AF_UNSPEC", "AF_INET", "AF_INET6",
        NULL };
    static const int af_num[] = {AF_UNSPEC, AF_INET, AF_INET6};

    int af = luaL_checkoption(L, idx, af_default, af_fam);

    return af_num[af];
}

/*
 * iptL_get_binkey()  <--  [ .. k ..]
 *
 * Copy a binary key, either an address or a mask, at given 'idx' into given
 * 'buf'.  'buf' size is assumed to be MAX_BINKEY.  A binary key is a byte
 * array [LEN | key bytes] and LEN is total length.  However, radix masks may
 * have set their LEN-byte equal to the nr of non-zero bytes in the array
 * instead.
 *
 */

static int
iptL_get_binkey(lua_State *L, int idx, uint8_t *buf, size_t *len)
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
 * iptL_get_pfxstr()  <--  [.. s ..]
 *
 * Checks if given index is a string and yields a const char ptr to it or NULL.
 * Sets len to the string length reported by Lua's stack manager.  Lua owns the
 * memory pointed to by the return value (no free by caller needed).
 *
 */

const char *
iptL_get_pfxstr(lua_State *L, int idx, size_t *len)
{
    /* return const char to a (prefix) string.  NULL on failure. */
    const char *pfx = NULL;
    if (! lua_isstring(L, idx)) return NULL;
    pfx = lua_tolstring(L, idx, len);  // donot use luaL_tolstring!

    return pfx;
}

/*
 * iptL_refp_create()  <--  [..]
 *
 * Create a reference id for the lua_State given.
 * This allocates an int pointer, gets a new ref_id, stores it in the allocated
 * space and returns a pointer to it.
 */

static int *
iptL_refp_create(lua_State *L)
{
    int *refp = calloc(1, sizeof(int));
    *refp = luaL_ref(L, LUA_REGISTRYINDEX);
    return refp;
}

/*
 * iptL_refp_delete()
 *
 * Delete a value from LUA_REGISTRYINDEX indexed by **r (which is treated as an
 * **int).  This function acts as the purge_f_t (see iptable.h) for the table.
 *
 */

static void iptL_refp_delete(void *L, void **r)
{
    lua_State *LL = L;
    int **refp = (int **)r;

    if(refp == NULL || *refp == NULL) return;
    luaL_unref(LL, LUA_REGISTRYINDEX, **refp);
    free(*refp);
    *refp = NULL;
}

/*
* iter_bail(L)  <--  [..]
*
* Helper function to bail out of an iteration factory function.
*
* An iteration factory function MUST return a valid [iter_f] and optionally
* an invariant and ctl_var. By returning iter_fail_f as [iter_f] we ensure
* the iteration in question will yield no results in Lua.
*
*/
static int
iter_bail(lua_State *L)
{
    dbg_stack("inc(.) ->");

    lua_settop(L, 0);                        /* clear the stack */
    // lua_pop(L, lua_gettop(L));               /* clear the stack */
    lua_pushcclosure(L, iter_fail_f, 0);       /* the iteration blocker */

    dbg_stack("out(1) ==>");

    return 1;
}

/*
* iter_fail_f  <--  [..], stack is ignored
*
* An iteration func that terminates any iteration.
*
*/

static int
iter_fail_f(lua_State *L)
{
    dbg_stack("ignored ->");

    lua_pop(L, lua_gettop(L));
    return 0;
}



// iptable module functions

/*
 * iptable.new()  <--  []
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
    *t = tbl_create(iptL_refp_delete);             // usr_delete func to free values

    if (*t == NULL) {
        lua_pushliteral(L, "error creating iptable");
        lua_error(L);
    }

    luaL_getmetatable(L, LUA_IPTABLE_ID); // [t M]
    lua_setmetatable(L, 1);               // [t]

    dbg_stack("out(1) ==>");

    return 1;
}

/*
 * iptable.tobin()  <--  [str]
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
    const char *pfx = iptL_get_pfxstr(L, 1, &len);

    if (! key_bystr(addr, &mlen, &af, pfx)) return 0;

    lua_pushlstring(L, (const char *)addr, IPT_KEYLEN(addr));
    lua_pushinteger(L, mlen);
    lua_pushinteger(L, af);

    dbg_stack("out(3) ==>");

    return 3;
}

/*
 * iptable.tostr()  <--  [binkey]
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

    if (!iptL_get_binkey(L, 1, key, &len)) return 0;
    if (len != (size_t)IPT_KEYLEN(key)) return 0; // illegal binary
    if (key_tostr(str, key) == NULL) return 0;

    lua_pushstring(L, str);

    dbg_stack("out(1) ==>");

    return 1;
}

/*
 * iptable.tolen()  <--  [key]
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

    if (!iptL_get_binkey(L, 1, buf, &len)) return 0;

    mlen = key_tolen(buf);
    lua_pushinteger(L, mlen);

    dbg_stack("out(1) ==>");

    return 1;
}

/*
 * iptable.size()  <--  [pfx]
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

    pfx = iptL_get_pfxstr(L, 1, &len);
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
 * iptable.address()  <--  [str]
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

    pfx = iptL_get_pfxstr(L, 1, &len);
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
 * iptable.network()  <--  [pfx]
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

    pfx = iptL_get_pfxstr(L, 1, &len);
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
 * iptable.neighbor(pfx)  <--  [str]
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

    pfx = iptL_get_pfxstr(L, 1, &len);
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

/* iptable.broadcast()  <--  [pfx]
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

    pfx = iptL_get_pfxstr(L, 1, &len);
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
 * iptable.mask(af, masklengh, [invert])  <--  [af, num, bool]
 *
 * Returns mask (as string) for mlen bits given, Nil on errors
 * - mlen < 0 means host/full mask
 * - inverted means to invert the mask (default is false).
 *
 * TODO:
 * o add bool parameter instead of using -mlen to convey desire for inversion
 * o restore mlen<0 to mean IPx_MAXMASK
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
 * iptable.hosts(pfx [, incl])  <--  [pfx [incl]]
 *
 * Iterate across host adresses in prefix pfx.
 *
 * The optional incl argument defaults to false, when given & true, the network
 * and broadcast address will be included in the iteration results.  If pfx has
 * no mask, the af's max mask is used.
 *
 */

static int
iter_hosts(lua_State *L)
{
    dbg_stack("inc(.) <--");

    size_t len = 0;
    int af = AF_UNSPEC, mlen = -1, inclusive = 0;
    int fail = 0;  // even on failure, gotta push iterfunc with 2 upvalues
    uint8_t addr[MAX_BINKEY], mask[MAX_BINKEY], stop[MAX_BINKEY];
    const char *pfx = NULL;

    if (lua_gettop(L) == 2 && lua_isboolean(L, 2))
        inclusive = lua_toboolean(L, 2);  // include netw/bcast (or not)

    pfx = iptL_get_pfxstr(L, 1, &len);
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
    lua_pushcclosure(L, iter_hosts_f, 2);  // [.., func]

    dbg_stack("out(1) ==>");

    return 1;
}

/*
 * iter_hosts_f()  <--  [h], h is nil on first call.
 *
 * The iter_f for iptable.hosts(pfx), yields the next host ip until stop value
 * is reached.  Ignores the stack: it uses upvalues for next, stop
 *
 */

static int
iter_hosts_f(lua_State *L)
{
    dbg_stack("inc(.) <--");

    size_t nlen = 0, slen = 0;
    uint8_t next[MAX_BINKEY], stop[MAX_BINKEY];
    char buf[MAX_STRKEY];

    if (!iptL_get_binkey(L, lua_upvalueindex(1), next, &nlen)) return 0;
    if (!iptL_get_binkey(L, lua_upvalueindex(2), stop, &slen)) return 0;
    if (key_cmp(next, stop) == 0) return 0;

    key_tostr(buf, next);                               /* return cur val */
    lua_pushstring(L, buf);

    key_incr(next);                                     /* setup next val */
    lua_pushlstring(L, (const char *)next, (size_t)IPT_KEYLEN(next));
    lua_replace(L, lua_upvalueindex(1));

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
iptm_gc(lua_State *L) {
    dbg_stack("inc(.) <--");

    table_t *t = iptL_get_table(L, 1);
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
iptm_newindex(lua_State *L)
{
    dbg_stack("inc(.) <--");

    const char *pfx = NULL;
    size_t len = 0;
    table_t *t = iptL_get_table(L, 1);
    int *refp = NULL;

    pfx = iptL_get_pfxstr(L, 2, &len);

    if (lua_isnil(L, -1)) {
        tbl_del(t, pfx, L);
        dbg_msg("tbl_del on %s", pfx);
    }
    else {
        if ((refp = iptL_refp_create(L)))
            if (! tbl_set(t, pfx, refp, L))
                iptL_refp_delete(L, (void**)&refp);
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
iptm_index(lua_State *L)
{
    dbg_stack("inc(.) <--");

    entry_t *entry = NULL;
    size_t len = 0;
    const char *pfx = NULL;

    table_t *t = iptL_get_table(L, 1);
    pfx = iptL_get_pfxstr(L, 2, &len);

    if(pfx)
        entry = strchr(pfx, '/') ? tbl_get(t, pfx) : tbl_lpm(t, pfx);

    if(entry)
        lua_rawgeti(L, LUA_REGISTRYINDEX, *(int *)entry->value); // [t k v]
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
iptm_len(lua_State *L)
{
    dbg_stack("inc(.) <--");

    table_t *t = iptL_get_table(L, 1);
    lua_pushinteger(L, t->count4 + t->count6);

    dbg_stack("out(1) ==>");

    return 1;
}

/*
 * _tostring()  <--  [t]
 *
 * Return a string representation of the iptable instance (with iptm_counts).
 *
 */

static int
iptm_tostring(lua_State *L)
{
    dbg_stack("inc(.) <--");

    table_t *t = iptL_get_table(L, 1);
    lua_pushfstring(L, "iptable{#ipv4=%d, #ipv6=%d}", t->count4, t->count6);

    dbg_stack("out(1) ==>");

    return 1;
}

/*
 * t:iptm_counts()  <--  [t]
 *
 * Return both ipv4 and ipv6 iptm_counts as two numbers.
 *
 */

static int
iptm_counts(lua_State *L)
{
    dbg_stack("inc(.) <--");

    table_t *t = iptL_get_table(L, 1);
    lua_pushinteger(L, t->count4);         // [t count4]
    lua_pushinteger(L, t->count6);         // [t count4 count6]

    dbg_stack("out(2) ==>");

    return 2;                              // [.., count4, count6]
}

/*
 * iter_kv  <--  [t]  --> for pairs(t)
 *
 * Setup iteration across key,value-pairs in the table.  The first ipv4 or ipv6
 * leaf node is pushed.  The iter_pairs iterator uses nextleaf to go through
 * all leafs of the tree.  It will traverse ipv6 as well if we started with the
 * ipv4 tree first.
 *
 */

static int
iter_kv(lua_State *L)
{
    dbg_stack("inc(.) <--");

    table_t *t = iptL_get_table(L, 1);
    struct radix_node *rn = rdx_firstleaf(&t->head4->rh);

    /* cannot start with a deleted key */
    while(rn && (rn->rn_flags & IPTF_DELETE))
        rn = rdx_nextleaf(rn);

    /* switch to ipv6 if ipv4 is empty tree */
    if (rn == NULL)
        rn = rdx_firstleaf(&t->head6->rh);

    /* cannot start with a deleted key */
    while(rn && (rn->rn_flags & IPTF_DELETE))
        rn = rdx_nextleaf(rn);

    if (rn == NULL) return iter_bail(L);

    lua_pushlightuserdata(L, rn);        // [t rn], rn is 1st node
    iptL_push_itr_gc(L, t);              // [t rn gc], itr garbage collector
    lua_pushcclosure(L, iter_kv_f, 2);   // [t f]
    lua_rotate(L, 1, 1);                 // [f t]
    lua_pushnil(L);                      // [f t nil]

    dbg_stack("out(3) ==>");

    return 3;                            // [iter_f invariant ctl_var]
}

/*
 * iter_kv_f()  <--  [t k]
 *
 * The iter_f for __iter_kv(), yields all k,v pairs in the tree(s).
 * - upvalue(1) is the leaf to process.
 *
 */

static int
iter_kv_f(lua_State *L)
{
    dbg_stack("inc(.) <--");

    char saddr[MAX_STRKEY];

    table_t *t = iptL_get_table(L, 1);
    struct radix_node *rn = lua_touserdata(L, lua_upvalueindex(1));
    entry_t *e = (entry_t *)rn;

    if (rn == NULL || RDX_ISROOT(rn)) return 0; // we're done

    /* push the next key, value onto stack */
    key_tostr(saddr, rn->rn_key);
    lua_pushfstring(L, "%s/%d", saddr, key_tolen(rn->rn_mask)); // [t k k']
    lua_rawgeti(L, LUA_REGISTRYINDEX, *(int *)e->value);        // [t k k' v']

    /* get next, non-deleted leaf node */
    rn = rdx_nextleaf(rn);
    while(rn && (rn->rn_flags & IPTF_DELETE))
        rn = rdx_nextleaf(rn);

    /* switch to ipv6 tree when ipv4 tree is exhausted */
    if (rn == NULL && KEY_IS_IP4(e->rn->rn_key))
        rn = rdx_firstleaf(&t->head6->rh);

    lua_pushlightuserdata(L, rn);                            // [t k k' v' rn]
    lua_replace(L, lua_upvalueindex(1));                     // [t_ud k k' v']

    dbg_stack("out(2) ==>");

    return 2;                                                // [.., k', v']
}

/*
 * :more()  <--  [t pfx bool], bool is optional
 *
 * Iterate across more specific prefixes. AF_family is deduced from the
 * prefix given.  Note this traverses the entire tree if pfx has a /0 mask.
 *
 */

static int
iter_more(lua_State *L)
{
    dbg_stack("inc(.) <--");

    size_t len = 0;
    int af = AF_UNSPEC, mlen = -1, maxb = -1;
    uint8_t addr[MAX_BINKEY], mask[MAX_BINKEY];
    struct radix_node_head *head = NULL;
    struct radix_node *rn = NULL, *top = NULL;
    int inclusive = 0;

    table_t *t = iptL_get_table(L, 1);
    const char *pfx = iptL_get_pfxstr(L, 2, &len);

    if (! key_bystr(addr, &mlen, &af, pfx)) {
        lua_pushfstring(L, "more(): invalid prefix %s", lua_tostring(L, 2));
        lua_error(L);
    }
    if (lua_gettop(L) == 3 && lua_isboolean(L, 3))
      inclusive = lua_toboolean(L, 3);
    if (af == AF_INET) {
      head = t->head4;
      mlen = mlen < 0 ? IP4_MAXMASK : mlen;
    } else if (af == AF_INET6) {
      head = t->head6;
      mlen = mlen < 0 ? IP6_MAXMASK : mlen;
    } else return iter_bail(L);
    if (! key_bylen(mask, mlen, af) || ! key_network(addr, mask)) {
      lua_pushliteral(L, "more(): error converting prefix");
      lua_error(L);
    }
    lua_pop(L, lua_gettop(L) - 1);                // [t]

    maxb = (mlen > 0) ? -1 - IPT_KEYOFFSET - mlen : -2;
    for(top = head->rh.rnh_treetop; !RDX_ISLEAF(top) && top->rn_bit >= maxb;)
        if (addr[top->rn_offset] & top->rn_bmask)
            top = top->rn_right;
        else
            top = top->rn_left;

    /* iter_more_f deals with IPTF_DELETE'd nodes */
    for (rn = top->rn_parent; !RDX_ISLEAF(rn);)   /* first, left-most, leaf */
        rn = rn->rn_left;

    /* iterator upvalues: sub-treetop, fst-leaf, inclusive, addr, mask */
    lua_pushlightuserdata(L, top);  // stay below this node
    lua_pushlightuserdata(L, rn);   // first possible match in subtree
    lua_pushinteger(L, inclusive);
    lua_pushlstring(L, (const char *)addr, (size_t)IPT_KEYLEN(addr));
    lua_pushlstring(L, (const char *)mask, (size_t)IPT_KEYLEN(mask));
    iptL_push_itr_gc(L, t);
    lua_pushcclosure(L, iter_more_f, 6);            // [t f]
    lua_rotate(L, 1, 1);                          // [f t]

    dbg_stack("out(1) ==>");

    return 2;                                     // [iter_f invariant]
}

/*
 * Iterate across more specific prefixes one at a time.
 *
 * - top points to subtree where possible matches are located
 * - rn is the current leaf under consideration
 */

static int
iter_more_f(lua_State *L)
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

    if (rn == NULL) return 0;     /* we're done */
    if(!iptL_get_binkey(L, lua_upvalueindex(4), addr, &dummy)) return 0;
    if(!iptL_get_binkey(L, lua_upvalueindex(5), mask, &dummy)) return 0;
    mlen = key_tolen(mask);
    mlen = inclusive ? mlen : mlen + 1;

    while (rn) {

        /* costly key_isin check is last */
        if(key_tolen(rn->rn_mask) >= mlen
                && !(rn->rn_flags & IPTF_DELETE)
                && key_isin(addr, rn->rn_key, mask)) {

            e = (entry_t *)rn;
            lua_pushfstring(L, "%s/%d",
                    key_tostr(buf, e->rn->rn_key),
                    key_tolen(e->rn->rn_mask));
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
 * :less()  <--  [t pfx incl]
 *
 * Iterate across prefixes in the tree that are less specific than pfx.
 * - search may include pfx itself in the results, if incl is true.
 * - iter_less_f takes (pfx, mlen, af)
 *
 */

static int
iter_less(lua_State *L)
{
    dbg_stack("inc(.) <--");

    table_t *t = iptL_get_table(L, 1);
    size_t len = 0;
    int mlen = 0, inclusive = 0, af = AF_UNSPEC;
    uint8_t addr[MAX_BINKEY];
    const char *pfx;
    char buf[MAX_STRKEY];

    pfx = iptL_get_pfxstr(L, 2, &len);
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
    iptL_push_itr_gc(L, t);                              // [t pfx mlen gc]
    lua_pushcclosure(L, iter_less_f, 3);                 // [t f]
    lua_rotate(L, 1, 1);                                 // [f t]

    dbg_stack("out(2) ==>");

    return 2;     // [iter_f invariant] (ctl_var not needed)
}

/*
 * iter_less_f()  <--  [t k], k is ignored
 *
 * Iterate across less specific prefixes relative to a given prefix.
 *
 */

static int
iter_less_f(lua_State *L)
{
    char buf[MAX_STRKEY];
    table_t *t = iptL_get_table(L, 1);
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
                    key_tostr(buf, e->rn->rn_key),
                    key_tolen(e->rn->rn_mask));
            lua_rawgeti(L, LUA_REGISTRYINDEX, *(int *)e->value);
            lua_pushinteger(L, mlen-1);
            lua_replace(L, lua_upvalueindex(2));
            return 2;
        }
    }
    return 0;  // all done
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
int iter_masks(lua_State *L) { 

    dbg_stack("inc(.) <--");                         // [t af]

    uint8_t binmask[MAX_BINKEY];
    char strmask[MAX_STRKEY];

    struct radix_node_head *rnh;
    struct radix_node *rn;
    int isnum = 0, af = AF_UNSPEC;
    table_t *t = iptL_get_table(L, 1);

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
     * needs to be returned by iter_masks_f
     *
     */

    rn = rdx_firstleaf(&rnh->rh.rnh_masks->head);
    lua_pushlightuserdata(L, rn);                    // [t rn]
    lua_pushinteger(L, af);                          // [t rn af]
    lua_pushstring(L, strmask);                      // [t rn af zm]
    lua_pushcclosure(L, iter_masks_f, 3);              // [t f]
    lua_rotate(L, 1, 1);                             // [f t]

    dbg_stack("out(2) ==>");

    return 2;                                        // [iter_f invariant]
}

/*
 * iter_masks_f(lua_State *);
 *
 * iter_f for :masks(af), yields all masks used in af's radix mask tree.
 * Masks are read-only: we donot interact directly with a radix mask tree.
 *
 */

static int
iter_masks_f(lua_State *L)
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

    if (rn == NULL || RDX_ISROOT(rn))
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
 * :merge(af)  <--  [t, af]
 *
 * Iterate across groups of pfx's that may be combined, to setup just return
 * the first leaf of the correct AF_family's tree.
 */

static int
iter_merge(lua_State *L)
{
    dbg_stack("inc(.) <--");                  // [t af]

    struct radix_node *rn;
    table_t *t = iptL_get_table(L, 1);
    int af = iptL_get_int(L, 2, "expected an AF_family number");

    lua_pop(L, 1);                            // [t]
    if (af == AF_INET)
        rn = rdx_firstleaf(&t->head4->rh);
    else if (af == AF_INET6)
        rn = rdx_firstleaf(&t->head6->rh);
    else return iter_bail(L);

    lua_pushlightuserdata(L, rn);             // [t af rn]
    lua_pushlightuserdata(L, NULL);           // [t af rn NULL]
    iptL_push_itr_gc(L, t);                   // [t af rn NULL gc]
    lua_pushcclosure(L, iter_merge_f, 3);       // [t f]
    lua_rotate(L, 1, -1);                     // [f t]

    dbg_stack("out(2) ==>");

    return 2;                                 // [iter_f invariant]
}

/*
 * Iterate across prefixes that may be combined.
 *
 * Returns the supernet and a regular table with 2 or 3 pfx,value entries.
 *
 * Caller may decide to keep only the supernet or parts of the group.  If the
 * supernet exists in the tree it will be present in the table as well as a
 * third entry.
 *
 * The next node stored as upvalue before returning, must be the first node of
 * the next group.
 */

static int
iter_merge_f(lua_State *L)
{
    dbg_stack("inc(.) <--");                   // [t p], upvalues(nxt, alt)

    struct radix_node *rn = lua_touserdata(L, lua_upvalueindex(1));
    struct radix_node *pair=NULL, *nxt = NULL, *super = NULL;
    char buf[MAX_STRKEY];

    if (rn == NULL) return 0;                  /* all done, not an error */
    if (! RDX_ISLEAF(rn)) return 0;            /* error: not a leaf */

    /* skip leafs without a pairing key */
    while(rn && (pair = rdx_pairleaf(rn)) == NULL)
        rn = rdx_nextleaf(rn);

    if (rn == NULL) return 0;
    if(RDX_ISROOT(rn)) return 0;

    /* search for supernet node on dupedkey chain of lowest key */
    super = key_cmp(rn->rn_key, pair->rn_key) > 0 ? pair : rn;
    key_tostr(buf, super->rn_key);  /* to push supernet prefix as string */
    while(super && super->rn_bit != rn->rn_bit + 1)
        super = super->rn_dupedkey;

    /* Caller may delete upper-half or even the supernet, which may be next if
     * the current leaf is the lower-half.  So ensure nxt-node is neither. This
     * means that super-/pair-node may be skipped during a single iteration but
     * its the only way to prevent undefined behaviour.
     */

    /* save next leaf for next iteration (NULL stops next iteration) */
    nxt = rdx_nextleaf(rn);
    if (nxt == super) nxt = rdx_nextleaf(nxt);
    if (nxt == pair) nxt = rdx_nextleaf(nxt);
    lua_pushlightuserdata(L, nxt);
    lua_replace(L, lua_upvalueindex(1));

    /* clear stack, push supernet prefix string & table with k,v-pairs */
    lua_pop(L, lua_gettop(L));                                    // []
    lua_pushfstring(L, "%s/%d", buf, key_tolen(rn->rn_mask)-1);   // [s]

    /* new table and add key,value pairs */
    lua_newtable(L);                                              // [s {}]
    iptT_set_kv(L, rn);
    iptT_set_kv(L, pair);
    if (super) iptT_set_kv(L, super);

    dbg_stack("out(2) ==>");

    return 2;
}


/*
 * During iteration(s), delete operations only flag radix nodes (leafs holding
 * a prefix) for deletion so they are not actively removed, only flagged for
 * deletion.  This way, the 'next leaf' node, stored as an upvalue by the
 * iter_xxx functions, is guaranteed to still exist on the next iteration.
 *
 * Such 'inactive' leafs are still part of the tree, but are seen as absent by
 * regular tree operations.
 *
 * The iterator garbage collector only actually removes those flagged for
 * deletion when there are no more iterators active (ie. itr_count reaches
 * zero).
 */

static void
iptL_push_itr_gc(lua_State *L, table_t *t)
{
  dbg_stack("inc(.) <--");

  itr_gc_t *g = (itr_gc_t *)lua_newuserdata(L, sizeof(itr_gc_t *));

  if (g == NULL) {
    lua_pushliteral(L, "error creating iterator _gc guard");
    lua_error(L);
  }

  g->t = t;
  t->itr_lock++;  /* registers presence of an active iterator */

  luaL_newmetatable(L, LUA_IPT_ITR_GC);   // [... g M]
  lua_setmetatable(L, -2);                // [... g]

  dbg_stack("out(.) ==>");
}

static int
ipt_itr_gc(lua_State *L)
{
  dbg_stack("inc(.) <--");
  struct radix_node *rn, *nxt;
  purge_t args;

  itr_gc_t *gc = luaL_checkudata(L, 1, LUA_IPT_ITR_GC);

  dbg_msg("gc->t is %p", (void *)gc->t);
  gc->t->itr_lock--;
  if (gc->t->itr_lock) return 0;

  /* iterator activity has ceased, so run the deferred deletions */
  args.purge = gc->t->purge;
  args.args = L;
  args.head = NULL; /* set per rn type (ipv4 vs ipv6) */

  rn = rdx_firstleaf(&gc->t->head4->rh);

  while(rn) {
    nxt = rdx_nextleaf(rn);
    if (rn->rn_flags & IPTF_DELETE) {
        args.head = KEY_IS_IP4(rn->rn_key) ? gc->t->head4 : gc->t->head6;
        rdx_flush(rn, &args);
    }
    rn = nxt;
  }

  dbg_stack("out(.) ==>");

  return 0;
}

/*
 * :radix(af)  <--  [t af maskp]
 *
 * Iterate across all nodes of all types in af's radix trees.
 *
 * Only includes the radix_mask tree if the optional maskp argument is true;
 * The iterator will return the C-structs as Lua tables.
 */

static int
iter_radixes(lua_State *L)
{
    dbg_stack("inc(.) <--");                        // [t af maskp]

    table_t *t = iptL_get_table(L, 1);
    int af_fam = iptL_get_af(L, 2, "AF_INET");
    int maskp = lua_toboolean(L, 3);

    /* pushes af_fam's radix_node_head onto t's stack */
    if (! rdx_firstnode(t, af_fam)) return iter_bail(L);

    /* maskp & itr_gc as upvalues for iterator */
    lua_settop(L, 1);                                // [t]
    lua_pushinteger(L, maskp);                       // [t maskp]
    iptL_push_itr_gc(L, t);                          // [t maskp {}]
    lua_pushcclosure(L, iter_radix, 2);              // [t f]
    lua_rotate(L, 1, 1);                             // [f t]

    dbg_stack("out(2) ==>");

    return 2;                                       // [iter_f invariant]
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

    table_t *t = iptL_get_table(L, 1);
    void *node;
    int type;

    if (! rdx_nextnode(t, &type, &node)) return 0; // we're done

    dbg_msg(">> node %p, type %d", node, type);

    switch (type) {
        case TRDX_NODE_HEAD:
            return iptL_push_rnh(L, node);
        case TRDX_HEAD:
            return iptL_push_rh(L, node);
        case TRDX_NODE:
            return iptL_push_rn(L, node);
        case TRDX_MASK_HEAD:
            if (! lua_tointeger(L, lua_upvalueindex(1))) return 0;
            return iptL_push_rmh(L, node);
        case TRDX_MASK:
            return iptL_push_rm(L, node);
    }

    dbg_msg(" `-> unhandled node type %d!", type);

    return 0;
}

// k,v-setters for Table on top of L (iter_radix/iter_merge_f) helpers

static void
iptT_set_fstr(lua_State *L, const char *k, const char *fmt, const void *v)
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
iptT_set_int(lua_State *L, const char *k, int v)
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

/* iptT_set_kv(L, rn)
 *
 * set (rn->rn_key, v) on Table on top of L, based on pfx provided and its
 * value stored (indirectly) in the corresponding radix tree.
 */

static void
iptT_set_kv(lua_State *L, struct radix_node *rn)
{
    char buf[MAX_STRKEY];
    entry_t *e;
    if (rn == NULL || ! lua_istable(L, -1)) {
        dbg_msg("need stack top to be a %s", "table");
        dbg_stack("not a table? ->");
        return;
    }
    if (RDX_ISROOT(rn)) {
        dbg_msg("cannot push k,v pair for %s node!", "ROOT");
    }
    if (!RDX_ISLEAF(rn)) {
        dbg_msg("cannot push k,v pair for %s node!", "an INTERNAL");
    }

    e = (entry_t *)rn;
    lua_pushfstring(L, "%s/%d",
            key_tostr(buf, rn->rn_key),                   // [.. {} p]
            key_tolen(rn->rn_mask));
    lua_rawgeti(L, LUA_REGISTRYINDEX, *(int *)e->value);  // [.. {} p v]
    lua_settable(L, -3);                                  // [.. {}]
}

/*
 * push_rdx_<node-type>'s each translating a struct to a lua table.
 * Will translate and push IPTF_DELETE'd nodes for completeness sake.
 * The lua caller may decide herself what to do with those.
 */

static int
iptL_push_rnh(lua_State *L, struct radix_node_head *rnh)
{
    // create table and populate its fields for rnh
    dbg_stack("inc(.) <--");

    lua_newtable(L);
    iptT_set_fstr(L, "_MEM_", "%p", rnh);
    iptT_set_int(L, "_TYPE_", TRDX_NODE_HEAD);
    iptT_set_fstr(L, "_NAME_", "%s", "RADIX_NODE_HEAD");

    // rh goes into a subtable
    lua_pushliteral(L, "rh");
    iptL_push_rh(L, &rnh->rh);
    lua_settable(L, -3);

    // rnh_nodes -> {_MEM_,..{{RDX[0]}, {RDX[1]}, {RDX[2]}}}
    lua_pushliteral(L, "rnh_nodes");

    // new subtable: array of 3 RDX nodes; table has MEM/NAME but no type
    lua_newtable(L);
    iptT_set_fstr(L, "_MEM_", "%p", rnh->rnh_nodes);
    iptT_set_fstr(L, "_NAME_", "%s", "RNH_NODES[3]");
    lua_pushinteger(L, 1);
    iptL_push_rn(L, &rnh->rnh_nodes[0]);
    lua_settable(L, -3);
    lua_pushinteger(L, 2);
    iptL_push_rn(L, &rnh->rnh_nodes[1]);
    lua_settable(L, -3);
    lua_pushinteger(L, 3);
    iptL_push_rn(L, &rnh->rnh_nodes[2]);
    lua_settable(L, -3);  // last entry is subtable

    lua_settable(L, -3);


    dbg_stack("out(1) ==>");
    return 1;
}

static int
iptL_push_rn(lua_State *L, struct radix_node *rn)
{
    // create table and populate its fields for rn
    // - uses the convenience rn->field_names
    char key[MAX_STRKEY];
    dbg_stack("inc(.) <--");

    lua_newtable(L);

    iptT_set_fstr(L, "_MEM_", "%p", rn);
    iptT_set_int(L, "_TYPE_", TRDX_NODE);
    iptT_set_fstr(L, "_NAME_", "%s", "RADIX_NODE");

    iptT_set_fstr(L, "rn_mklist", "%p", rn->rn_mklist);
    iptT_set_fstr(L, "rn_parent", "%p", rn->rn_parent);
    iptT_set_int(L, "rn_bit", rn->rn_bit);
    // its a char, pushed as int => print("%02x", 0xff & int_val)
    iptT_set_int(L, "rn_bmask", rn->rn_bmask);
    iptT_set_int(L, "rn_flags", rn->rn_flags);

    // set _RNF_FLAGs_
    if (rn->rn_flags & RNF_NORMAL)
        iptT_set_int(L, "_NORMAL_", 1);
    if (rn->rn_flags & RNF_ROOT)
        iptT_set_int(L, "_ROOT_", 1);
    if (rn->rn_flags & RNF_ACTIVE)
        iptT_set_int(L, "_ACTIVE_", 1);
    if (rn->rn_flags & IPTF_DELETE)
        iptT_set_int(L, "_DELETE_", 1);

    if(RDX_ISLEAF(rn)) {
      iptT_set_int(L, "_LEAF_", 1);
      iptT_set_fstr(L, "rn_key", "%s", key_tostr(key, rn->rn_key));
      iptT_set_fstr(L, "rn_mask", "%s", key_tostr(key, rn->rn_mask));
      iptT_set_fstr(L, "rn_dupedkey", "%p", rn->rn_dupedkey);

      /* additional diagnostics */
      if (rn->rn_key)
        iptT_set_int(L, "_rn_key_LEN", 0xff & IPT_KEYLEN(rn->rn_key));
      else
        iptT_set_int(L, "_rn_key_LEN", -1);

      if (rn->rn_mask) {
        iptT_set_int(L, "_rn_mask_LEN", IPT_KEYLEN(rn->rn_mask));
        iptT_set_int(L, "_rn_mlen", key_tolen(rn->rn_mask));
      } else {
        iptT_set_int(L, "_rn_mask_LEN", -1); /* may happen in mask tree */
        iptT_set_int(L, "_rn_mlen", key_tolen(rn->rn_key));
      }


    } else {
      iptT_set_int(L, "_INTERNAL_", 1);
      iptT_set_int(L, "rn_offset", rn->rn_offset);
      iptT_set_fstr(L, "rn_left", "%p", rn->rn_left);
      iptT_set_fstr(L, "rn_right", "%p", rn->rn_right);
    }

    dbg_stack("out(1) ==>");

    return 1;
}

/* push a radix head onto L (as a table)
 */

static int
iptL_push_rh(lua_State *L, struct radix_head *rh)
{
    // create table and populate its fields for rn
    dbg_stack("inc(.) <--");

    lua_newtable(L);
    iptT_set_fstr(L, "_MEM_", "%p", rh);
    iptT_set_int(L, "_TYPE_", TRDX_HEAD);
    iptT_set_fstr(L, "_NAME_", "%s", "RADIX_HEAD");

    iptT_set_fstr(L, "rnh_treetop", "%p", rh->rnh_treetop);
    iptT_set_fstr(L, "rnh_masks", "%p", rh->rnh_masks);

    dbg_stack("out(1) ==>");

    return 1;
}

/* push a radix mask head onto L (as a table)
 */

static int
iptL_push_rmh(lua_State *L, struct radix_mask_head *rmh)
{
    // create table and populate its fields for rn
    dbg_stack("inc(.) <--");

    lua_newtable(L);
    iptT_set_fstr(L, "_MEM_", "%p", rmh);
    iptT_set_int(L, "_TYPE_", TRDX_MASK_HEAD);
    iptT_set_fstr(L, "_NAME_", "%s", "RADIX_MASK_HEAD");

    lua_pushliteral(L, "head");
    iptL_push_rh(L, &rmh->head);
    lua_settable(L, -3);

    lua_pushliteral(L, "mask_nodes");

    // new subtable: an array of 3 radix_node's
    lua_newtable(L);
    iptT_set_fstr(L, "_MEM_", "%p", rmh->mask_nodes);
    iptT_set_fstr(L, "_NAME_", "%s", "MASK_NODES[3]");
    lua_pushinteger(L, 1);
    iptL_push_rn(L, &rmh->mask_nodes[0]);
    lua_settable(L, -3);
    lua_pushinteger(L, 2);
    iptL_push_rn(L, &rmh->mask_nodes[1]);
    lua_settable(L, -3);
    lua_pushinteger(L, 3);
    iptL_push_rn(L, &rmh->mask_nodes[2]);
    lua_settable(L, -3);

    lua_settable(L, -3);  // mask_nodes -> subtable/array

    dbg_stack("out(1) ==>");

    return 1;
}

static int
iptL_push_rm(lua_State *L, struct radix_mask *rm)
{
    // create table and populate its fields for rn
    dbg_stack("inc(.) <--");

    char key[MAX_STRKEY];

    lua_newtable(L);
    iptT_set_fstr(L, "_MEM_", "%p", rm);
    iptT_set_int(L, "_TYPE_", TRDX_MASK);
    iptT_set_fstr(L, "_NAME_", "%s", "RADIX_MASK");

    iptT_set_int(L, "rm_bit", rm->rm_bit);
    iptT_set_int(L, "rm_unused", rm->rm_unused);
    iptT_set_int(L, "rm_flags", rm->rm_flags);

    // set _RNF_FLAGs_
    if (rm->rm_flags & RNF_NORMAL) iptT_set_int(L, "_NORMAL_", 1);
    if (rm->rm_flags & RNF_ROOT)   iptT_set_int(L, "_ROOT_", 1);
    if (rm->rm_flags & RNF_ACTIVE) iptT_set_int(L, "_ACTIVE_", 1);

    iptT_set_fstr(L, "rm_mklist", "%p", rm->rm_mklist);
    iptT_set_int(L, "rm_refs", rm->rm_refs);

    if (rm->rm_flags & RNF_NORMAL) {
      // NOTE: if its a NORMAL 'radix_mask' then union -> rm_leaf else rm_mask
      // - see radix.c:377 and and radix.c:773
      iptT_set_int(L, "_LEAF_", 1);
      iptT_set_fstr(L, "rm_leaf", "%p", rm->rm_leaf);

    } else {
      iptT_set_int(L, "_INTERNAL_", 1);
      iptT_set_fstr(L, "rm_mask", "%s", key_tostr(key, rm->rm_mask));
    }

    dbg_stack("out(1) ==>");

    return 1;
}
