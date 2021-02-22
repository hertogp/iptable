// Comments in this file are structured to be grep'd into a markdown file.

/* # `lua_iptable.c`
 * Lua bindings for iptable
 */

#include <malloc.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdarg.h>

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#include "radix.h"
#include "iptable.h"
#include "debug.h"

#include "lua_iptable.h"

/*
 * ## Structures
 *
 * ### `itr_gc_t`
 *
 * The `itr_gc_t` type  has 1 member: `table_t *t` and serves only to create a
 * userdata to be supplied as an upvalue to each iterator function.  That
 * userdata has a metatable with a `__gc` garbage collector, (see `ipt_itr_gc`)
 * which will remove radix nodes in `t` that are (still) flagged for deletion
 * only when it is safe to do so (i.e. `t->itr_lock` has reached zero).
 */

typedef struct itr_gc_t {
  table_t *t;
} itr_gc_t;


// library function called by Lua to initialize

int luaopen_iptable(lua_State *);

// helper funtions

static int lipt_error(lua_State *, int, int, const char *, ...);
static int lipt_vferror(lua_State *, int, int, const char *, va_list);
static table_t *iptL_gettable(lua_State *, int);
static int iptL_getpfxstr(lua_State *, int, const char **, size_t *);
static int *iptL_refpcreate(lua_State *);
static void iptL_refpdelete(void *, void **);
static int iptL_getaf(lua_State *L, int, int *);
static int iptL_getbinkey(lua_State *, int, uint8_t *, size_t *);
static int ipt_itr_gc(lua_State *);
static int iter_error(lua_State *, int, const char *, ...);
static int iter_fail_f(lua_State *);

// iter_xxx() helpers

static int _str2idx(const char *, const char *const []);
static void iptL_pushitrgc(lua_State *, table_t *);
static void iptT_setbool(lua_State *, const char *, int);
static void iptT_setfstr(lua_State *, const char *, const char *, const void *);
static void iptT_setint(lua_State *, const char *, int);
static void iptT_setkv(lua_State *, struct radix_node *);
static int iptL_pushrnh(lua_State *, struct radix_node_head *);
static int iptL_pushrn(lua_State *, struct radix_node *);
static int iptL_pushrh(lua_State *, struct radix_head *);
static int iptL_pushrmh(lua_State *, struct radix_mask_head *);
static int iptL_pushrm(lua_State *, struct radix_mask *);

// iptable module iterators

static int iter_hosts(lua_State *);
static int iter_hosts_f(lua_State *);
static int iter_interval(lua_State *);
static int iter_interval_f(lua_State *);
static int iter_subnets(lua_State *);
static int iter_subnets_f(lua_State *);

// iptable module functions

static int ipt_address(lua_State *);
static int ipt_broadcast(lua_State *);
static int ipt_dnsptr(lua_State *);
static int ipt_invert(lua_State *);
static int ipt_properties(lua_State *);
static int ipt_longhand(lua_State *);
static int ipt_mask(lua_State *);
static int ipt_masklen(lua_State *);
static int ipt_neighbor(lua_State *L);
static int ipt_network(lua_State *);
static int ipt_new(lua_State *);
static int ipt_offset(lua_State *);
static int ipt_reverse(lua_State *);
static int ipt_size(lua_State *);
static int ipt_split(lua_State *);
static int ipt_tobin(lua_State *);
static int ipt_toredo(lua_State *);
static int ipt_tostr(lua_State *);

// iptable instance iterators

static int iter_kv(lua_State *);
static int iter_kv_f(lua_State *);
static int iter_less(lua_State *);
static int iter_less_f(lua_State *);
static int iter_masks(lua_State *);
static int iter_masks_f(lua_State *);
static int iter_supernets(lua_State *);
static int iter_supernets_f(lua_State *);
static int iter_more(lua_State *);
static int iter_more_f(lua_State *);
static int iter_radix(lua_State *);
static int iter_radixes(lua_State *);

// iptable instance methods

static int iptm_counts(lua_State *);
static int iptm_gc(lua_State *);
static int iptm_index(lua_State *);
static int iptm_len(lua_State *);
static int iptm_newindex(lua_State *);
static int iptm_tostring(lua_State *);

// iptable module function array

static const struct luaL_Reg funcs [] = {
    {"address", ipt_address},
    {"broadcast", ipt_broadcast},
    {"dnsptr", ipt_dnsptr},
    {"hosts", iter_hosts},
    {"interval", iter_interval},
    {"invert", ipt_invert},
    {"properties", ipt_properties},
    {"longhand", ipt_longhand},
    {"mask", ipt_mask},
    {"masklen", ipt_masklen},
    {"neighbor", ipt_neighbor},
    {"network", ipt_network},
    {"new", ipt_new},
    {"offset", ipt_offset},
    {"reverse", ipt_reverse},
    {"size", ipt_size},
    {"split", ipt_split},
    {"subnets", iter_subnets},
    {"tobin", ipt_tobin},
    {"toredo", ipt_toredo},
    {"tostr", ipt_tostr},
    {NULL, NULL}
};

// iptable instance methods array

static const struct luaL_Reg meths [] = {
    {"__gc", iptm_gc},
    {"__index", iptm_index},
    {"__newindex", iptm_newindex},
    {"__len", iptm_len},
    {"__tostring", iptm_tostring},
    {"__pairs", iter_kv},
    {"counts", iptm_counts},
    {"masks", iter_masks},
    {"supernets", iter_supernets},
    {"more", iter_more},
    {"less", iter_less},
    {"radixes", iter_radixes},
    {NULL, NULL}
};

/*
 Special addresses used to check for properties, plus required masks
 See
 - https://tools.ietf.org/html/rfc6890 - special purpose ip addresses
 - https://tools.ietf.org/html/rfc8190 - update to the above
 - https://www.iana.org/assignments/iana-ipv4-special-registry
 - https://www.iana.org/assignments/iana-ipv6-special-registry

 6to4 -> ip4 = a.b.c.d => ip6to4 = 2002:ab:cd::/48
 teredo
 */

uint8_t IP4_MC_UNSPEC[]   = { 5, 224,   0, 0, 0}; /* rfc1112 */
uint8_t IP4_MC_HOSTS[]    = { 5, 224,   0, 0, 1};
uint8_t IP4_MC_ROUTERS[]  = { 5, 224,   0, 0, 2};
uint8_t IP4_MC_MAXLOCAL[] = { 5, 224,   0, 0, 255};

/* uint8_t IP4_MASK8[]       = { 5, 255,   0, 0, 0}; */
/* uint8_t IP4_MASK12[]      = { 5, 255, 240, 0, 0}; */
/* uint8_t IP4_MASK16[]      = { 5, 255, 255, 0, 0}; */

/*
 * ## Helper functions
 *
 * ### `_stridx`
 * ```c
 * static int _str2idx(const char *, const char * const []);
 * ```
 *
 * Find the index of a string in a NULL-terminated list of strings.  Used by
 * functions like iptL_getaf, that take strings arguments that need to be
 * converted to an index or number.
 * Returns index on success, -1 on failure.
 */
static int
_str2idx(const char *s, const char *const t[]) {
  for (int i = 0; t[i]; i++)
    if (strcmp(s, t[i]) == 0) return i;
  return -1;
}


/*
 * ## Lua library
 */

/*
 * ### `luaopen_iptable`
 * ```c
 * int luaopen_iptable(lua_State *);
 * ```
 * ```lua
 * -- lua
 * iptable = require "iptable"
 * ```
 *
 * Called by Lua upon requiring "iptable" to initialize the module.  Returns
 * `iptable`'s module-table with the module functions and constants.
 */

int
luaopen_iptable (lua_State *L)
{
    dbg_stack("inc(.) <--"); // <-- ['iptable', '<path>/iptable.so']`

    lua_settop(L, 0);                       // []

    /* LUA_IPT_ITR_GC metatable */
    luaL_newmetatable(L, LUA_IPT_ITR_GC);   // [GC{}]
    lua_pushstring(L, "__gc");              // [GC{} k]
    lua_pushcfunction(L, ipt_itr_gc);       // [GC{} k f]
    lua_settable(L, -3);                    // [GC{}]
    lua_settop(L, 0);                       // []

    /* LUA_IPTABLE_ID metatable */
    luaL_newmetatable(L, LUA_IPTABLE_ID);   // [{} ]
    lua_pushvalue(L, -1);                   // [{}, {} ]
    lua_setfield(L, -2, "__index");         // [{M}]
    luaL_setfuncs(L, meths, 0);             // [{M, meths}]
    lua_settop(L, 0);                       // []

    /* IPTABLE libary table */
    luaL_newlibtable(L, funcs);
    luaL_setfuncs(L, funcs, 0);             // [{F}]

    // lib AF constants                     // [{F,C}]
    lua_pushstring(L, LUA_IPTABLE_VERSION);
    lua_setfield(L, -2, "VERSION");
    lua_pushinteger(L, AF_INET);
    lua_setfield(L, -2, "AF_INET");
    lua_pushinteger(L, AF_INET6);
    lua_setfield(L, -2, "AF_INET6");

    /* Store a reference to the iptable library table for this lua_State in the
     * LUA_REGISTRY so lipt_vferror can retrieve it later to set
     * `iptable.error` to some error message.
     */
    lua_pushvalue(L, -1);
    lua_rawsetp(L, LUA_REGISTRYINDEX, (void *)L);

    dbg_stack("out(1) ==>");                // [{F,C}]

    return 1;
}

/*
 * ## error handlers
 *
 * In general, functions that return values will return all nil's for these in
 * case of an error and an extra string value describing the error is added to
 * the values returned.  In addition to this, an `iptable.error` is also set to
 * indicate the error.
 *
 * ```lua
 * iptable.address("10.10.10.10/24")
 * --> 10.10.10.10  24  2, for ip, mlen and af. Whereas
 * iptable.address("10.10.10.10/33")
 * --> nil nil nil "invalid prefix string"
 *
 * for host in iptable.hosts("10.10.10.0/33") do print(host) end
 * --> won't print anything, here's why:
 * iptable.error
 * --> stdin:1:12:error converting string to binary ('10.10.10.0/33' ?)
 * ```
 */

/*
 * ### `lipt_vferror`
 * ```c
 * static int lipt_vferror(lua_State *L, int, int, const char *, va_list);
 * ```
 *
 * Helper function that clears the stack, sets iptable.error module level
 * variable to a formatted error string `file:line:errno:description` and
 * finally loads the stack with as many nils as arguments that would've been
 * returned plus the `description` for the errno supplied.  In Lua space, the
 * user has access to both `iptable.error` as well as the last value returned
 * by the function that errored out.
 */
static int
lipt_vferror(lua_State *L, int errno, int nargs, const char *fmt, va_list ap)
{
    int err = LIPTE_UNKNOWN;
    lua_Debug ar;
    const char *fname = "(nofile)";
    int lineno = 0;

    dbg_stack("inc(.) <--");

    lua_settop(L, 0);  /* clear the stack, we're erroring out   [] */

    /* set ar to activation record from Lua interpreter's runtime stack*/
    if (lua_getstack(L, 1, &ar)) {
      if (lua_getinfo(L, "Sl", &ar)) {
        fname = ar.short_src;
        lineno = ar.currentline;
      }
    }

    if ((0 <= errno) && (errno < LIPTE_ZMAX))
        err = errno;

    /* set iptable.error to formatted error string w/ additional info */
    lua_rawgetp(L, LUA_REGISTRYINDEX, (void *)L);               // [mt]
    if (err == LIPTE_NONE)                                      // [mt e]
        lua_pushnil(L);
    else
        lua_pushfstring(L, "%s:%d:%d:%s", fname, lineno, err, LIPT_ERROR[err]);
    if (fmt && *fmt != '\0') {
        lua_pushstring(L, " (");
        lua_pushvfstring(L, fmt, ap);
        lua_pushstring(L, ")");
        lua_concat(L, 4);
    }

    /* set iptable.error */
    lua_setfield(L, -2, "error");                              // [mt]
    lua_pop(L, 1);                                             // []

    /* add nil's for the nargs that should've been returned */
    for(int i=0; i<nargs; i++)
        lua_pushnil(L);                                        // [nils]

    lua_pushstring(L, LIPT_ERROR[err]);                        // [nils errmsg]

    /* swap bottom and top of stack */ 
    /* lua_rotate(L, 1, -1);                                   // [.. e] */

    dbg_stack("out(1) ==>");

    return 1;
}

/*
 * ### `lipt_error`
 * ```c
 * static int lipt_error(lua_State *L, int, int, const char *);
 * ```
 * ```lua
 * -- lua
 * iptable.error = nil -- clear any previous error
 * ip, mlen, af, err = iptable.address("10.10.10.0/33")
 * --> nil nil nil invalid prefix string
 * iptable.error
 * --> "file:line:errno:invalid prefix string"
 * ```
 *
 * A helper function to set iptable's global error number, clear the stack,
 * push nil, and return 1.  Is used by functions to bail out while setting
 * an error indicator.  When an interation is not possible due to some error,
 * `iptable.error` is the only way to see what went wrong.
 *
 */

static int
lipt_error(lua_State *L, int errno, int nargs, const char *fmt, ...)
{
    va_list args;

    dbg_stack("inc(.) <--");

    /* clears the stack & fills it with nulls + error msg */
    va_start(args, fmt);
    lipt_vferror(L, errno, nargs, fmt, args);
    va_end(args);

    dbg_stack("out(nargs+1) ==>");

    return nargs + 1;
}


/*
 * ## Lua stack functions
 *
 * These are convencience functions to get/set values and parameters on the Lua
 * stack.  The include:
 *
 * - `iptL`-functions get/set/push stack values.
 * - `iptT`-functions manipulate k,v-pairs of a table on top of L
 */

/*
 * ### `iptL_gettable`
 * ```c
 * static table_t * iptL_gettable(lua_State *, int);
 * ```
 *
 * Checks whether the stack value at the given index contains a userdata of
 * type [`LUA_IPTABLE_ID`](### LUA_IPTABLE_ID) and returns a `table_t` pointer.
 * Errors out to Lua if the stack value has the wrong type.
 */

static table_t *
iptL_gettable(lua_State *L, int idx)
{
    dbg_stack("inc(.) <--");   // [.. t ..]

    void **t = luaL_checkudata(L, idx, LUA_IPTABLE_ID);
    luaL_argcheck(L, t != NULL, idx, "`iptable' expected");
    return (table_t *)*t;
}

/*
 * ### `iptL_getaf`
 * ```c
 * static int iptL_getaf(lua_State *L, int idx, int *af);
 * ```
 *
 * Checks whether the stack value at the given index is a known af_family
 * number or name and sets *af accordingly, otherwise it's set to `AF_UNSPEC`.
 * If the stack value does not exist, the int pointer `*af` is not modified.
 * Caller decides if a missing or unknown af_family is an error or not.
 */


static int
iptL_getaf(lua_State *L, int idx, int *af)
{
    static const char *const af_fam[] = {"AF_INET", "AF_INET6", NULL };
    static const int af_num[] = {AF_INET, AF_INET6};
    int af_idx = -1;

    switch (lua_type(L, idx)) {
        case LUA_TNIL:
            break;
        case LUA_TNUMBER:
            *af = lua_tointeger(L, idx);
            break;
        case LUA_TSTRING:
            af_idx = _str2idx(lua_tostring(L, idx), af_fam);
            *af = af_idx < 0 ? AF_UNSPEC : af_num[af_idx];
            break;
        default:
            *af = AF_UNSPEC;
            return 0;
    }
    return 1;
}

/*
 * ### `iptL_getbinkey`
 * ```c
 * static int iptL_getbinkey(lua_State *L, int idx, uint8_t *buf, size_t * len);
 * ```
 *
 * Copy a binary key, either an address or a mask, at given 'idx' into given
 * 'buf'.  'buf' size is assumed to be MAX_BINKEY.  A binary key is a byte
 * array [LEN | key bytes] and LEN is total length.  However, radix masks may
 * have set their LEN-byte equal to the nr of non-zero bytes in the array
 * instead.
 *
 */

static int
iptL_getbinkey(lua_State *L, int idx, uint8_t *buf, size_t *len)
{
    dbg_stack("inc(.) <--");   // [.. k ..]
    const char *key = NULL;

    if (lua_type(L, idx) != LUA_TSTRING)
        return 0;

    key = lua_tolstring(L, idx, len);

    if (key == NULL)
        return 0;
    if (IPT_KEYLEN(key) > MAX_BINKEY)
        return 0;
    if (*len < 1 || *len > MAX_BINKEY)
        return 0;

    memcpy(buf, key, *len);

    return 1;
}


/*
 * ### `iptL_getpfxstr`
 * ```c
 * static in iptL_getpfxstr(lua_State *L, int idx, const char **pfx, size_t *len);
 * ```
 *
 * Checks if `L[idx]` is a string and sets the const char ptr to it or NULL.
 * Also sets len to the string length reported by Lua's stack manager.  Lua
 * owns the memory pointed to by the const char ptr (no free by caller needed).
 * Returns 1 on success, 0 on failure.
 */

static int
iptL_getpfxstr(lua_State *L, int idx, const char **pfx, size_t *len)
{
    /* return const char to a (prefix) string.  NULL on failure. */
    dbg_stack("inc(.) <--");          // [.. s ..]
    if (lua_type(L, idx) != LUA_TSTRING)
        return 0;
    *pfx = lua_tolstring(L, idx, len);  // donot use luaL_tolstring!

    return 1;
}

/*
 * ### `iptL_refpcreate`
 * ```c
 * static int iptL_refpcreate(lua_State *L);
 * ```
 *
 * Create a reference id for the lua_State given.  This allocates an int
 * pointer, gets a new ref_id, stores it in the allocated space and returns a
 * pointer to it.
 */

static int *
iptL_refpcreate(lua_State *L)
{
    int *refp = calloc(1, sizeof(int));
    *refp = luaL_ref(L, LUA_REGISTRYINDEX);
    return refp;
}

/*
 * ### `iptL_refpdelete`
 * ```c
 * static void iptL_refpdelete(void *L, void **r);
 * ```
 *
 * Delete a value from `LUA_REGISTRYINDEX` indexed by **r (which is treated as
 * an **int).  Function signature is as per `purge_f_t` (see iptable.h) and
 * acts as the table's purge function to release user data.
 */

static void
iptL_refpdelete(void *L, void **r)
{
    lua_State *LL = L;
    int **refp = (int **)r;

    if(refp == NULL || *refp == NULL) return;
    luaL_unref(LL, LUA_REGISTRYINDEX, **refp);
    free(*refp);
    *refp = NULL;
}

// k,v-setters for Table on top of L (iter_radix/iter_supernets_f) helpers

/*
 * ### `iptT_setbool`
 * ```c
 * static void iptT_setbool(lua_State *L, const char *k, int v);
 * ```
 *
 * Needs a Lua table on top of the stack and sets key `k` to boolean for `v`.
 */

static void
iptT_setbool(lua_State *L, const char *k, int v)
{
    if (! lua_istable(L, -1)) {
        dbg_msg("need stack top to be a %s", "table");
        dbg_stack("not a table ? ->");
        return;
    }
    lua_pushstring(L, k);
    lua_pushboolean(L, v);
    lua_settable(L, -3);
}

/*
 * ### `iptT_setfstr`
 * ```c
 * static void iptT_setfstr(lua_State *L, const char *k, const char *fmt,
 * const void *v)
 * ```
 *
 * Needs a Lua table on top of the stack and sets key `k` to the formatted
 * string using `fmt` and `v`.
 */

static void
iptT_setfstr(lua_State *L, const char *k, const char *fmt, const void *v)
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

/*
 * ### `iptT_setint`
 * ```c
 * static void iptT_setint(lua_State *L, const char *k, int v);
 * ```
 *
 * Needs a Lua table on top of the stack and sets key `k` to integer value `v`.
 */

static void
iptT_setint(lua_State *L, const char *k, int v)
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

/*
 * ### `iptT_setkv`
 * ```c
 * static void iptT_setkv(lua_State *L, struct radix_node *rn);
 * ```
 *
 * Needs a Lua table on top of the stack.  It takes the radix node's key
 * `rn->rn_key` and the value pointed to by the radix_node and sets that as a
 * key,value-pair in the table on top.
 *
 * The `rn` pointer actually points to the start of the user data structures
 * built into the radix tree.  Hence a cast to `(entry_t *)rn` gives access to
 * the `rn`'s index number, which is used to retrieve the prefix's (aka
 * `rn->key`) value from the `LUA_REGISTRYINDEX`.
 */

static void
iptT_setkv(lua_State *L, struct radix_node *rn)
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
            key_masklen(rn->rn_mask));
    lua_rawgeti(L, LUA_REGISTRYINDEX, *(int *)e->value);  // [.. {} p v]
    lua_settable(L, -3);                                  // [.. {}]
}

/*
 * ### `iptL_pushrnh`
 * ```c
 * static int iptL_pushrnh(lua_State *L, struct radix_node_head *rnh)
 * ```
 *
 * Encodes a `radix_node_head` structure as a Lua table and adds some
 * additional members to make processing on the Lua side easier.  It will
 * include nodes flagged for deletion with `IPTF_DELETE`, so the user can
 * decide for themselves to ignore them or not.  The radix_node_head table
 * looks like:
 *
 * ```lua
 * { _NAME_  = "RADIX_NODE_HEAD",
 *   _MEM_   =  "0x<rnh>",
 *   rh = { RADIX_HEAD },
 *   rnh_nodes = {
 *     _NAME_ = "RNH_NODES[3]",
 *     _MEM_  = "0x<rh>",
 *     [1]    = { RADIX_NODE },
 *     [2]    = { RADIX_NODE },
 *     [3]    = { RADIX_NODE }
 *    }
 * }
 * ```
 */

static int
iptL_pushrnh(lua_State *L, struct radix_node_head *rnh)
{
    // create table and populate its fields for rnh
    dbg_stack("inc(.) <--");

    lua_newtable(L);
    iptT_setfstr(L, "_MEM_", "%p", rnh);
    iptT_setfstr(L, "_NAME_", "%s", "RADIX_NODE_HEAD");

    // rh goes into a subtable
    lua_pushliteral(L, "rh");
    iptL_pushrh(L, &rnh->rh);
    lua_settable(L, -3);

    // rnh_nodes -> {_MEM_,..{{RDX[0]}, {RDX[1]}, {RDX[2]}}}
    lua_pushliteral(L, "rnh_nodes");

    // new subtable: array of 3 RDX nodes; table has MEM/NAME but no type
    lua_newtable(L);
    iptT_setfstr(L, "_MEM_", "%p", rnh->rnh_nodes);
    iptT_setfstr(L, "_NAME_", "%s", "RNH_NODES[3]");
    lua_pushinteger(L, 1);
    iptL_pushrn(L, &rnh->rnh_nodes[0]);
    lua_settable(L, -3);
    lua_pushinteger(L, 2);
    iptL_pushrn(L, &rnh->rnh_nodes[1]);
    lua_settable(L, -3);
    lua_pushinteger(L, 3);
    iptL_pushrn(L, &rnh->rnh_nodes[2]);
    lua_settable(L, -3);  // last entry is subtable

    lua_settable(L, -3);


    dbg_stack("out(1) ==>");
    return 1;
}

/*
 * ### `iptL_pushrn`
 * ```c
 * static int iptL_pushrn(lua_State *L, struct radix_node *rn)
 * ```
 *
 * Encodes a `radix_node` structure as a Lua table and adds some additional
 * members to make processing on the Lua side easier.
 * ```lua
 * { _NAME_     = "RADIX_NODE",
 *   _MEM_      = "0x<rn-ptr>",
 *   _NORMAL_   = 1, -- if NORMAL flag is set
 *   _ROOT_     = 1, -- if ROOT flag is set
 *   _ACTIVE_   = 1, -- if ACTIVE flag is set
 *   _DELETE_   = 1, -- if IPTF_DELETE flag is set (i.e. a deleted node)
 *   _LEAF_     = 1, -- if it is a LEAF node
 *   _INTERNAL_ = 1, -- if it is not a LEAF node
 *
 *   rn_mklist  = "0x<ptr>",
 *   rn_parent  = "0x<ptr>",
 *   rn_bit     = rn->rn_bit,
 *   rn_bmask   = rn->rn_bmask,
 *   rn_flags   = rn->rn_flags,
 *
 *   -- LEAF NODES only
 *   rn_key     = "prefix as a string"
 *   rn_mask    = "mask as a string"
 *   rn_dupedkey = "0x<ptr>",
 *   _rn_key_LEN = key-length, -- in bytes, may be -1
 *   _rn_mask_len = key-length, -- in bytes, may be -1
 *   _rn_mlen   = num-of-consecutive msb 1-bits,
 *
 *   -- INTERNAL NODES only
 *   rn_offset  = rn->offset,
 *   rn_left    = rn->left,
 *   rn_right   = rn->right,
 * }
 * ```
 */

static int
iptL_pushrn(lua_State *L, struct radix_node *rn)
{
    // create table and populate its fields for rn
    // - uses the convenience rn->field_names
    char key[MAX_STRKEY];
    dbg_stack("inc(.) <--");

    lua_newtable(L);

    iptT_setfstr(L, "_MEM_", "%p", rn);
    iptT_setfstr(L, "_NAME_", "%s", "RADIX_NODE");

    iptT_setfstr(L, "rn_mklist", "%p", rn->rn_mklist);
    iptT_setfstr(L, "rn_parent", "%p", rn->rn_parent);
    iptT_setint(L, "rn_bit", rn->rn_bit);
    // its a char, pushed as int => print("%02x", 0xff & int_val)
    iptT_setint(L, "rn_bmask", rn->rn_bmask);
    iptT_setint(L, "rn_flags", rn->rn_flags);

    // set _RNF_FLAGs_
    if (rn->rn_flags & RNF_NORMAL)
        iptT_setint(L, "_NORMAL_", 1);
    if (rn->rn_flags & RNF_ROOT)
        iptT_setint(L, "_ROOT_", 1);
    if (rn->rn_flags & RNF_ACTIVE)
        iptT_setint(L, "_ACTIVE_", 1);
    if (rn->rn_flags & IPTF_DELETE)
        iptT_setint(L, "_DELETE_", 1);

    if(RDX_ISLEAF(rn)) {
      iptT_setint(L, "_LEAF_", 1);
      iptT_setfstr(L, "rn_key", "%s", key_tostr(key, rn->rn_key));
      iptT_setfstr(L, "rn_mask", "%s", key_tostr(key, rn->rn_mask));
      iptT_setfstr(L, "rn_dupedkey", "%p", rn->rn_dupedkey);

      /* additional diagnostics */
      if (rn->rn_key)
        iptT_setint(L, "_rn_key_LEN", 0xff & IPT_KEYLEN(rn->rn_key));
      else
        iptT_setint(L, "_rn_key_LEN", -1);

      if (rn->rn_mask) {
        iptT_setint(L, "_rn_mask_LEN", IPT_KEYLEN(rn->rn_mask));
        iptT_setint(L, "_rn_mlen", key_masklen(rn->rn_mask));
      } else {
        iptT_setint(L, "_rn_mask_LEN", -1); /* may happen in mask tree */
        iptT_setint(L, "_rn_mlen", key_masklen(rn->rn_key));
      }


    } else {
      iptT_setint(L, "_INTERNAL_", 1);
      iptT_setint(L, "rn_offset", rn->rn_offset);
      iptT_setfstr(L, "rn_left", "%p", rn->rn_left);
      iptT_setfstr(L, "rn_right", "%p", rn->rn_right);
    }

    dbg_stack("out(1) ==>");

    return 1;
}

/*
 * ### `iptL_pushrh`
 * ```c
 * static int iptL_pushrh(lua_State *L, struct radix_head *rh)
 * ```
 *
 * Encodes a `radix_head` structure as a Lua table and adds some additional
 * members to make processing on the Lua side easier.
 * ```lua
 * { _NAME_      = "RADIX_HEAD",
 *   _MEM_       = "0x<ptr>",
 *   rnh_treetop = "0x<ptr>",
 *   rnh_masks   = "0x<ptr>",
 * }
 * ```
 */

static int
iptL_pushrh(lua_State *L, struct radix_head *rh)
{
    // create table and populate its fields for rn
    dbg_stack("inc(.) <--");

    lua_newtable(L);
    iptT_setfstr(L, "_MEM_", "%p", rh);
    iptT_setfstr(L, "_NAME_", "%s", "RADIX_HEAD");

    iptT_setfstr(L, "rnh_treetop", "%p", rh->rnh_treetop);
    iptT_setfstr(L, "rnh_masks", "%p", rh->rnh_masks);

    dbg_stack("out(1) ==>");

    return 1;
}

/*
 * ### `iptL_pushrmh`
 * ```c
 * static int iptL_pushrmh(lua_State *L, struct radix_mask_head *rmh)
 * ```
 *
 * Encodes a `radix_head` structure as a Lua table and adds some additional
 * members to make processing on the Lua side easier.
 * ```lua
 * { _MEM_  = "0x<ptr>",
 *   _NAME_ = "RADIX_MASK_HEAD",
 *   head   = "0x<ptr>",
 *   mask_nodes = {
 *     _MEM_  = "0x<ptr>",
 *     _NAME_ = "MASK_NODES[3]",
 *     [1]    = { RADIX_NODE },
 *     [2]    = { RADIX_NODE },
 *     [3]    = { RADIX_NODE }
 *   }
 * }
 * ```
 */

static int
iptL_pushrmh(lua_State *L, struct radix_mask_head *rmh)
{
    // create table and populate its fields for rn
    dbg_stack("inc(.) <--");

    lua_newtable(L);
    iptT_setfstr(L, "_MEM_", "%p", rmh);
    iptT_setfstr(L, "_NAME_", "%s", "RADIX_MASK_HEAD");

    lua_pushliteral(L, "head");
    iptL_pushrh(L, &rmh->head);
    lua_settable(L, -3);

    lua_pushliteral(L, "mask_nodes");

    // new subtable: an array of 3 radix_node's
    lua_newtable(L);
    iptT_setfstr(L, "_MEM_", "%p", rmh->mask_nodes);
    iptT_setfstr(L, "_NAME_", "%s", "MASK_NODES[3]");
    lua_pushinteger(L, 1);
    iptL_pushrn(L, &rmh->mask_nodes[0]);
    lua_settable(L, -3);
    lua_pushinteger(L, 2);
    iptL_pushrn(L, &rmh->mask_nodes[1]);
    lua_settable(L, -3);
    lua_pushinteger(L, 3);
    iptL_pushrn(L, &rmh->mask_nodes[2]);
    lua_settable(L, -3);

    lua_settable(L, -3);  // mask_nodes -> subtable/array

    dbg_stack("out(1) ==>");

    return 1;
}

/*
 * ### `iptL_pushrm`
 * ```c
 * static int iptL_pushrm(lua_State *L, struct radix_mask *rm);
 * ```
 *
 * Encodes a `radix_mask` structure as a Lua table and adds some additional
 * members to make processing on the Lua side easier.
 * ```lua
 * { _NAME_ = "RADIX_MASK",
 *   _MEM_  = "0x<ptr>",
 *   _NORMAL_ = 1, -- if NORMAL-flag is set
 *   _ROOT_   = 1, -- if ROOT-flag is set
 *   _ACTIVE_ = 1, -- if ACTIVE-flag is set
 *   _LEAF_   = 1, -- if it's a LEAF node
 *   _NORMAL_ = 1, -- if it's not a LEAF node
 *   rm_bit = rm->rm_bit,
 *   rm_unused = rm->rm_unused,
 *   rm_flags  = rm->rm_flags,
 *
 *   -- LEAF NODE only
 *   rm_leaf   = "0x<ptr>"
 *
 *   -- INTERNAL NODE only
 *   rm_mask   = "0x<ptr>"
 *
 * ```
 */

static int
iptL_pushrm(lua_State *L, struct radix_mask *rm)
{
    // create table and populate its fields for rn
    dbg_stack("inc(.) <--");

    char key[MAX_STRKEY];

    lua_newtable(L);
    iptT_setfstr(L, "_MEM_", "%p", rm);
    iptT_setfstr(L, "_NAME_", "%s", "RADIX_MASK");

    iptT_setint(L, "rm_bit", rm->rm_bit);
    iptT_setint(L, "rm_unused", rm->rm_unused);
    iptT_setint(L, "rm_flags", rm->rm_flags);

    // set _RNF_FLAGs_
    if (rm->rm_flags & RNF_NORMAL) iptT_setint(L, "_NORMAL_", 1);
    if (rm->rm_flags & RNF_ROOT)   iptT_setint(L, "_ROOT_", 1);
    if (rm->rm_flags & RNF_ACTIVE) iptT_setint(L, "_ACTIVE_", 1);

    iptT_setfstr(L, "rm_mklist", "%p", rm->rm_mklist);
    iptT_setint(L, "rm_refs", rm->rm_refs);

    if (rm->rm_flags & RNF_NORMAL) {
      // NOTE: if its a NORMAL 'radix_mask' then union -> rm_leaf else rm_mask
      // - see radix.c:377 and and radix.c:773
      iptT_setint(L, "_LEAF_", 1);
      iptT_setfstr(L, "rm_leaf", "%p", rm->rm_leaf);

    } else {
      iptT_setint(L, "_INTERNAL_", 1);
      iptT_setfstr(L, "rm_mask", "%s", key_tostr(key, rm->rm_mask));
    }

    dbg_stack("out(1) ==>");

    return 1;
}

/* ## Garbage collection
 */

/*
 * ### `iptm_gc`
 * ```c
 * static int iptm_gc(lua_State *L);
 * ```
 *
 * Garbage collector function (`__gc`) for `LUA_IPTABLE_ID` metatable, which is
 * the metatable of `iptable`-table.  Once a table instance is garbage
 * collected this function gets called to fee up all its resources.
 */

static int
iptm_gc(lua_State *L) {
    dbg_stack("inc(.) <--");  // [t]

    table_t *t = iptL_gettable(L, 1);
    tbl_destroy(&t, L);

    dbg_stack("out(0) ==>");

    return 0;
}

/*
 * ### `iptL_pushitrgc`
 * ```c
 * static void iptL_pushitrgc(lua_State *L, table_t *t);
 * ```
 *
 * Each iterator factory function MUST call this function in order to push a
 * new userdata (an iterator guard) as an upvalue for its actual iterator
 * function.  Once that iterator is done, Lua will garbage collect this
 * userdata (the iterator's upvalues are being garbage collected, includeing
 * this iterator guard userdata).  The sole purpose of this iterator guard
 * userdata is to check for radix nodes flagged for deletion and actually
 * delete them, unless there are still iterators active for this table. So with
 * nested iterators, only the last userdata gets to actually delete radix nodes
 * from the tree.  Note, the actual iterator functions donot use this userdata
 * at all, its only there to get garbage collected at some point after the
 * iterator function is finished and its upvalues are garbage collected.
 *
 * Hence, deletions (in Lua) during tree iteration are safe, since deletion
 * operations also check the table for any active iterators.  If there are
 * none, deletion is immediate.  Otherwise, the node(s) only get flagged for
 * deletion which makes them 'inactive'.  All tree operations treat radix nodes
 * thus flagged as not being there at all.  Although inactive, they can still
 * be used to navigate around the tree by iterators.
 *
 * This function:
 *
 * - creates a new userdatum
 * - sets its metatable to the `LUA_IPT_ITR_GC` metatable
 * - points this userdata to this table (`t`-member)
 * - increments this table active iterator count `itr_lock`
 *
 * and leaves it on the top of the stack so it can be closed over by the
 * iteration (closure) function when created by its factory.
 */

static void
iptL_pushitrgc(lua_State *L, table_t *t)
{
  dbg_stack("inc(.) <--");

  itr_gc_t *g = (itr_gc_t *)lua_newuserdatauv(L, sizeof(itr_gc_t *), 1);

  if (g == NULL) {
    lua_pushliteral(L, "error creating iterator _gc guard");
    lua_error(L);
  }

  g->t = t;       /* point the garbage collector to *this* table */
  t->itr_lock++;  /* register presence of an active iterator in *this* table */

  /* get the LUA_IPT_ITR_GC metatable & associate it with this new userdata */
  luaL_newmetatable(L, LUA_IPT_ITR_GC);   // [... g M]
  lua_setmetatable(L, -2);                // [... g]

  dbg_stack("out(.) ==>");
}

/*
 * ### `ipt_itr_gc`
 * ```c
 * static int ipt_itr_gc(lua_State *L);
 * ```
 *
 * The garbage collector function of the LUA_IPT_ITR_GC metatable, used on the
 * iterator guard userdata pushed as an upvalue to all table iterator
 * functions.  Once an iterator is finished this userdata, since it is an
 * upvalue of the iterator function, is garbage collected and this function
 * gets called, which will:
 *
 * - decrease this table's active iterator count
 * - if it reaches zero, it'll delete all radix nodes flagged for deletion
 */

static int
ipt_itr_gc(lua_State *L)
{
  dbg_stack("inc(.) <--");
  struct radix_node *rn, *nxt;
  purge_t args;

  itr_gc_t *gc = luaL_checkudata(L, 1, LUA_IPT_ITR_GC);

  dbg_msg("gc->t is %p", (void *)gc->t);
  gc->t->itr_lock--;
  if (gc->t->itr_lock)
      return 0;  /* some iterators still active */

  /* apparently all iterator activity has ceased: run deferred deletions */
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




/* ## Iterators
 *
 * The functions in this section are two helper functions and the actual
 * iterator functions used by the iterator factory functions to setup some form
 * of iteration.  These are collected here whereas the factory functions are
 * listed in both the `modules functions` and `instance methods` sections since
 * the relate to functions callable from Lua.  Since the actual iterator
 * functions donot, they are listed here.
 */

/*
 * ### `iter_error`
 * ```c
 * static int iter_error(lua_State *L, int errno, const char *fmt, ...);
 * ```
 *
 * Helper function to bail out of an iteration factory function.  An iteration
 * factory function MUST return a valid iterator function (`iter_f`) and
 * optionally an `invariant` and `ctl_var`. By returning `iter_fail_f` as
 * `iter_f` we ensure the iteration in question will yield no results in Lua.
 */

static int
iter_error(lua_State *L, int errno, const char *fmt, ...) {

    dbg_stack("inc(.) <--");

    va_list args;

    va_start(args, fmt);
    lipt_vferror(L, errno, 1, fmt, args);
    va_end(args);
    lua_settop(L, 0);
    lua_pushcclosure(L, iter_fail_f, 0);  /* stops any iteration */

    dbg_stack("out(1) ==>");

    return 1;
}

/*
 * ### `iter_fail_f`
 * ```c
 * static int iter_fail_f(lua_State *L);
 * ```
 *
 * An iteration function that immediately terminates any iteration.
 */

static int
iter_fail_f(lua_State *L)
{
    dbg_stack("ignored ->");

    lua_settop(L, 0);
    return 0;
}

/*
 * ### `iter_hosts_f`
 * ```c
 * static int iter_hosts_f(lua_State *L);
 * ```
 *
 * The actual iterator function for iptable.hosts(pfx), yields the next host ip
 * until its stop value is reached.  Ignores the stack: it uses upvalues for
 * next, stop
 */

static int
iter_hosts_f(lua_State *L)
{
    dbg_stack("inc(.) <--");  // [h], h is nil on first call.

    size_t nlen = 0, slen = 0;
    uint8_t next[MAX_BINKEY], stop[MAX_BINKEY];
    char buf[MAX_STRKEY];

    lua_settop(L, 0);  /* clear stack */
    if (!iptL_getbinkey(L, lua_upvalueindex(1), next, &nlen))
        return lipt_error(L, LIPTE_LVAL, 1, "");
    if (!iptL_getbinkey(L, lua_upvalueindex(2), stop, &slen))
        return lipt_error(L, LIPTE_LVAL, 1, "");

    if (key_cmp(next, stop) == 0)
        return 0;  /* all done */

    if (! key_tostr(buf, next))
        return lipt_error(L, LIPTE_TOSTR, 1, "");
    lua_pushstring(L, buf);

    /* setup the next val */
    key_incr(next, 1);
    lua_pushlstring(L, (const char *)next, (size_t)IPT_KEYLEN(next));
    lua_replace(L, lua_upvalueindex(1));

    dbg_stack("out(1) ==>");


    return 1;
}

/*
 * ### `iter_interval_f`
 * ```c
 * static int iter_interval_f(lua_State *L)
 * ```
 *
 * The actual iterator function for `iter_interval`.  It calculates the
 * prefixes that, together make up the address space interval, by starting out
 * with the maximum size possible for given start address and stop address.
 * Usually ends with smaller prefixes.  On errors, it won't iterate anything in
 * which case `iptable.error` should provide some information.
 */

static int
iter_interval_f(lua_State *L)
{
    dbg_stack("(inc) <--");

    uint8_t start[MAX_BINKEY], stop[MAX_BINKEY], mask[MAX_BINKEY];
    size_t klen;
    char buf[MAX_STRKEY];

    if (lua_tointeger(L, lua_upvalueindex(3)))
        return 0;  /* all done */
    if (! iptL_getbinkey(L, lua_upvalueindex(1), start, &klen))
        return lipt_error(L, LIPTE_LVAL, 1, "");
    if (! iptL_getbinkey(L, lua_upvalueindex(2), stop, &klen))
        return lipt_error(L, LIPTE_LVAL, 1, "");

    if (key_cmp(start, stop) > 0)
        return 0;  /* all done */

    if (! key_byfit(mask, start, stop))
        return lipt_error(L, LIPTE_BINOP, 1, "");

    /* push the result; [pfx] */
    lua_settop(L, 0);
    lua_pushfstring(L, "%s/%d", key_tostr(buf, start), key_masklen(mask));

    /* setup next start address */
    if (! key_broadcast(start, mask))
        return lipt_error(L, LIPTE_BINOP, 1, "");

    /* wrap around protection, current pfx is the last one */
    if (key_cmp(start, stop) == 0) {
        lua_pushinteger(L, 1);
        lua_replace(L, lua_upvalueindex(3));
    } else {
        if (! key_incr(start, 1))
            return lipt_error(L, LIPTE_BINOP, 1, "");
        lua_pushlstring(L, (const char *)start, (size_t)IPT_KEYLEN(start));
        lua_replace(L, lua_upvalueindex(1));
    }

    dbg_stack("out(1) ==>");

    return 1;
}

/*
 * ### `iter_subnets_f`
 * ```c
 * static int iter_subnets_f(lua_State *L)
 * ```
 *
 * The actual iterator function for `iter_subnets`.  Uses upvalues: `start`,
 * `stop`, `mask`, `mlen` and a `sentinal` which is used to signal address
 * space wrap around.
 *
 * `stop` represents the broadcast address of the last prefix to return.  This
 * might actually be the max address possible in the AF's address space and
 * increasing beyond using `key_incr` would fail.  So if the current prefix,
 * which will be returned in this iteration, has a broadcast address equal to
 * `stop` the sentinal upvalue is set to 0 so iteration stops next time around
 * and no `key_incr` is done to arrive at the next 'network'-address of the
 * next prefix since we're done already..
 *
 * `mlen` is stored as a convenience and represents the prefix length of the
 * binary `mask` and alleviates the need to calculate it on every iteration.
 */

static int
iter_subnets_f(lua_State *L)
{
    dbg_stack("(inc) <--");

    uint8_t start[MAX_BINKEY], stop[MAX_BINKEY], mask[MAX_BINKEY];
    size_t klen;
    int mlen;
    char buf[MAX_STRKEY];

    if (lua_tointeger(L, lua_upvalueindex(5)))
        return 0; /* all done */
    if (! iptL_getbinkey(L, lua_upvalueindex(1), start, &klen))
        return lipt_error(L, LIPTE_LVAL, 1, "");
    if (! iptL_getbinkey(L, lua_upvalueindex(2), stop, &klen))
        return lipt_error(L, LIPTE_LVAL, 1, "");

    /* are we done? */
    if (key_cmp(start, stop) > 0)
        return 0;

    /* push start as the next subnet */
    lua_settop(L, 0);
    mlen = lua_tointeger(L, lua_upvalueindex(4));
    lua_pushfstring(L, "%s/%d", key_tostr(buf, start), mlen);

    /* setup next start address */
    if (! iptL_getbinkey(L, lua_upvalueindex(3), mask, &klen))
        return lipt_error(L, LIPTE_LVAL, 1, "");
    if (! key_broadcast(start, mask))
        return lipt_error(L, LIPTE_BINOP, 1, "");

    /* wrap around protection */
    if (key_cmp(start, stop) == 0) {
        lua_pushinteger(L, 1);
        lua_replace(L, lua_upvalueindex(5));
    } else {
        if (! key_incr(start, 1))
            return lipt_error(L, LIPTE_BINOP, 1, "");
        lua_pushlstring(L, (const char *)start, (size_t)IPT_KEYLEN(start));
        lua_replace(L, lua_upvalueindex(1));
    }

    dbg_stack("out(1) ==>");

    return 1;
}

/*
 * ### `iter_kv_f`
 * ```c
 * static int iter_kv_f(lua_State *L)
 * ```
 *
 * The actual iteration function for `iter_kv` yields all k,v pairs in the
 * tree(s).  When an iterator is active, deletion of entries are flagged and
 * only carried out when no iterators are active.  So it should be safe to
 * delete entries while iterating.
 *
 * Note: upvalue(1) is the leaf to process.
 */

static int
iter_kv_f(lua_State *L)
{
    dbg_stack("inc(.) <--");  // [t k]

    char saddr[MAX_STRKEY];

    table_t *t = iptL_gettable(L, 1);
    struct radix_node *rn = lua_touserdata(L, lua_upvalueindex(1));
    entry_t *e = (entry_t *)rn;

    if (rn == NULL || RDX_ISROOT(rn)) return 0; // we're done

    /* rn might have been deleted in the previous iteration */
    while(rn && (rn->rn_flags & IPTF_DELETE))
        rn = rdx_nextleaf(rn);

    if (rn == NULL || RDX_ISROOT(rn)) return 0; // we're done
    e = (entry_t *)rn;

    /* push the next key, value onto stack */
    if (! key_tostr(saddr, rn->rn_key))
        return lipt_error(L, LIPTE_TOSTR, 2, "");
    lua_pushfstring(L, "%s/%d", saddr, key_masklen(rn->rn_mask)); // [t k k']
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
 * ### `iter_more_f`
 * ```c
 * static int iter_more_f(lua_State *L);
 * ```
 *
 * The actual iteration function for `iter_more`.
 *
 * - `top` points to subtree where possible matches are located
 * - `rn` is the current leaf under consideration
 */

static int
iter_more_f(lua_State *L)
{
    dbg_stack("inc(.) <--");
    lua_settop(L, 0); // clear stack, not used

    char buf[MAX_STRKEY];
    struct entry_t *e = NULL;
    struct radix_node *rn = lua_touserdata(L, lua_upvalueindex(2));
    int inclusive = lua_tointeger(L, lua_upvalueindex(3));
    int mlen;
    size_t dummy;
    uint8_t addr[MAX_BINKEY], mask[MAX_BINKEY];

    if (rn == NULL) return 0;  /* we're done */
    if(!iptL_getbinkey(L, lua_upvalueindex(4), addr, &dummy))
        return lipt_error(L, LIPTE_LVAL, 2, "");
    if(!iptL_getbinkey(L, lua_upvalueindex(5), mask, &dummy))
        return lipt_error(L, LIPTE_LVAL, 2, "");
    mlen = key_masklen(mask);
    mlen = inclusive ? mlen : mlen + 1;

    while (rn) {

        /* costly key_isin check is last */
        if(key_masklen(rn->rn_mask) >= mlen
                && !(rn->rn_flags & IPTF_DELETE)
                && key_isin(addr, rn->rn_key, mask)) {

            e = (entry_t *)rn;
            lua_pushfstring(L, "%s/%d",
                    key_tostr(buf, e->rn->rn_key),
                    key_masklen(e->rn->rn_mask));
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
            return 0;  /* all done */
    }
    return 0;  /* NOT REACHED */
}

/*
 * ### `iter_less_f`
 * ```c
 * static int iter_less_f(lua_State *L);
 * ```
 *
 * The actual iteration function for `iter_less`.  It basically works by
 * decreasing the prefix length which needs to match for the given search
 * prefix.
 *
 */

static int
iter_less_f(lua_State *L)
{
    dbg_stack("inc(.) <--");  // [t k], k is ignored

    char buf[MAX_STRKEY];
    table_t *t = iptL_gettable(L, 1);
    entry_t *e;
    const char *pfx = lua_tostring(L, lua_upvalueindex(1));
    int mlen = lua_tointeger(L, lua_upvalueindex(2));

    if (mlen < 0)
        return 0;     /* all done */
    if (pfx == NULL)
        return lipt_error(L, LIPTE_LVAL, 2, "");

    for(; mlen >= 0; mlen--) {
        snprintf(buf, sizeof(buf), "%s/%d", pfx, mlen);
        buf[MAX_STRKEY-1] = '\0';

        if ((e = tbl_get(t, buf))) {
            lua_pushfstring(L, "%s/%d",
                    key_tostr(buf, e->rn->rn_key),
                    key_masklen(e->rn->rn_mask));
            lua_rawgeti(L, LUA_REGISTRYINDEX, *(int *)e->value);
            lua_pushinteger(L, mlen-1);
            lua_replace(L, lua_upvalueindex(2));
            return 2;
        }
    }
    return 0;  // all done
}

/*
 * ### `iter_masks_f`
 * ```c
 * static int iter_masks_f(lua_State *L);
 * ```
 *
 * The actual iteration function for `iter_masks`.  Masks are read-only: the
 * Lua bindings donot (need to) interact directly with a radix mask tree.
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
        return 0;  // we're done (or next rn was deleted ...)

    /* process current mask leaf node */
    mlen = key_masklen(rn->rn_key);              // contiguous masks only
    if (! key_bylen(binmask, mlen, af))        // fresh mask due to deviating
        return lipt_error(L, LIPTE_TOBIN, 2, "");
    if (! key_tostr(strmask, binmask))         // keylen's of masks
        return lipt_error(L, LIPTE_TOSTR, 2, "");

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
 * ### `iter_supernets_f`
 * ```c
 * static int iter_supernets_f(lua_State *L);
 * ```
 *
 * The actual iteration function for `iter_supernets`.
 *
 * The next node stored as upvalue before returning, must be the first node of
 * the next group.
 */

static int
iter_supernets_f(lua_State *L)
{
    dbg_stack("inc(.) <--");                   // [t p], upvalues(nxt, alt)

    struct radix_node *rn = lua_touserdata(L, lua_upvalueindex(1));
    struct radix_node *pair=NULL, *nxt = NULL, *super = NULL;
    char buf[MAX_STRKEY];

    if (rn == NULL)
        return 0;  /* all done, not an error */

    if (! RDX_ISLEAF(rn))
        return lipt_error(L, LIPTE_ITER, 2, "");  /* error: not a leaf */

    /* skip deleted nodes */
    while(rn && (rn->rn_flags & IPTF_DELETE))
        rn = rdx_nextleaf(rn);
    if (rn == NULL || RDX_ISROOT(rn)) return 0; /* we're done */

    /* skip leafs without a pairing key */
    while(rn && (pair = rdx_pairleaf(rn)) == NULL)
        rn = rdx_nextleaf(rn);

    if (rn == NULL || RDX_ISROOT(rn)) return 0;  /* we're done */

    /* search for supernet node on dupedkey chain of lowest key */
    super = key_cmp(rn->rn_key, pair->rn_key) > 0 ? pair : rn;
    if (! key_tostr(buf, super->rn_key))      /* supernet prefix as string */
        return lipt_error(L, LIPTE_TOSTR, 2, "");
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
    lua_settop(L, 0);                                             // []
    lua_pushfstring(L, "%s/%d", buf, key_masklen(rn->rn_mask)-1); // [s]

    /* new table and add key,value pairs */
    lua_newtable(L);                                              // [s {}]
    iptT_setkv(L, rn);
    iptT_setkv(L, pair);
    if (super) iptT_setkv(L, super);

    dbg_stack("out(2) ==>");

    return 2;
}

/*
 * ### `iter_radix`
 * ```c
 * static int iter_radix(lua_State *L);
 * ```
 *
 * The actual iterator function for `iter_radixes` which traverses a
 * prefix-tree (and possible its associated mask-tree) and yields all nodes one
 * at the time.
 *
 * Notes:
 *
 * - returns current node as a Lua table or nil to stop iteration
 * - saves next (type, node) as upvalues (1) resp. (2)
 */

static int
iter_radix(lua_State *L)
{
    dbg_stack("inc(.) <--");  // [ud k] ([nil nil] at first call)

    table_t *t = iptL_gettable(L, 1);
    void *node;
    int type;

    if (! rdx_nextnode(t, &type, &node))
        return 0; // we're done

    dbg_msg(">> node %p, type %d", node, type);

    switch (type) {
        case TRDX_NODE_HEAD:
            return iptL_pushrnh(L, node);
        case TRDX_HEAD:
            return iptL_pushrh(L, node);
        case TRDX_NODE:
            return iptL_pushrn(L, node);
        case TRDX_MASK_HEAD:
            if (! lua_toboolean(L, lua_upvalueindex(1)))
                return 0;  /* not doing the optional mask tree */
            return iptL_pushrmh(L, node);
        case TRDX_MASK:
            return iptL_pushrm(L, node);
        default:
            return lipt_error(L, LIPTE_RDX, 1, "");  /* unhandled node type */
    }

    return 0;
}

/* ## module functions
 *
 */

/*
 * ### `iptable.new`
 * ```c
 * static int ipt_new(lua_State *L);
 * ```
 *
 * Creates a new userdata, sets its `iptable` metatable and returns it to Lua.
 * It also sets the purge function for the table to
 * [*`iptL_refpdelete`*](### `iptL_refpdelete`) which frees any memory held by
 * the user's data once a prefix is deleted from the radix tree.
 */

static int
ipt_new(lua_State *L)
{
    dbg_stack("inc(.) <--");

    table_t **t = lua_newuserdatauv(L, sizeof(void **), 1);
    *t = tbl_create(iptL_refpdelete);      // usr_delete func to free values

    if (*t == NULL) luaL_error(L, "error creating table");

    luaL_getmetatable(L, LUA_IPTABLE_ID); // [t M]
    lua_setmetatable(L, 1);               // [t]

    /* for debug: */
    /* lua_pushlightuserdata(L, (void *)L); */
    /* lua_gettable(L, LUA_REGISTRYINDEX); */
    /* dbg_stack("42?"); */
    /* lua_pop(L, 1); */
    /* end for debug: */

    dbg_stack("out(1) ==>");

    return 1;
}

/*
 * ### `iptable.tobin`
 * ```c
 * static int iptable.tobin(lua_State *L);
 * ```
 * ```lua
 * -- lua
 *  binkey, mlen, af, err = iptable.tobin("10.10.10.10/24")
 * ```
 *
 * Convert the prefix string to a binary key and return it, together with its
 * prefix length & AF for a given prefix. Note: a byte array is length encoded
 * [LEN | key-bytes], where `LEN` is the total length of the byte array.
 * In case of errors, returns nil's and an error description.
 *
 */

static int
ipt_tobin(lua_State *L)
{
    dbg_stack("inc(.) <--");   // <-- [str]

    int af, mlen;
    uint8_t addr[MAX_BINKEY];
    size_t len = 0;
    const char *pfx = NULL;

    if (! iptL_getpfxstr(L, 1, &pfx, &len))
        return lipt_error(L, LIPTE_ARG, 3, "");
    if (! key_bystr(addr, &mlen, &af, pfx))
        return lipt_error(L, LIPTE_PFX, 3, "");

    lua_pushlstring(L, (const char *)addr, IPT_KEYLEN(addr));
    lua_pushinteger(L, mlen);
    lua_pushinteger(L, af);

    dbg_stack("out(3) ==>");

    return 3;
}

/*
 * ### `iptable.tostr`
 * ```c
 * static int ipt_tostr(lua_state *L);
 * ```
 * ```lua
 * -- lua
 * pfx, err = iptable.tostr(binkey)
 * ```
 *
 * Returns a string representation for given binary key or nil & an error msg.
 *
 */

static int
ipt_tostr(lua_State *L)
{
    dbg_stack("inc(.) <--");  // [binkey]

    uint8_t key[MAX_BINKEY];
    char str[MAX_STRKEY];
    size_t len = 0;

    if (! iptL_getbinkey(L, 1, key, &len))
        return lipt_error(L, LIPTE_ARG, 1, "");
    if (len != (size_t)IPT_KEYLEN(key))
        return lipt_error(L, LIPTE_BIN, 1, ""); // illegal binary
    if (! key_tostr(str, key))
        return lipt_error(L, LIPTE_TOSTR, 1, "");

    lua_pushstring(L, str);

    dbg_stack("out(1) ==>");

    return 1;
}

/*
 * ### `iptable.toredo`
 * ```c
 * static int ipt_tostr(lua_state *L);
 * ```
 * ```lua
 * -- lua
 * t, err = iptable.toredo(ipv6)
 * t, err = iptable.toredo(tserver, tclient, udp, flags)
 * ```
 * Either compose an ipv6 address using 4 arguments or decompose an ipv6 string
 * into a table with fields:
 * `ipv6`, the toredo ip6 address
 * `server`, toredo server's ipv4 address
 * `client`, toredo client's ipv4 address
 * `flags`, flags
 * `udp`, udp port
 *
 */

static int
ipt_toredo(lua_State *L)
{
    dbg_stack("inc(.) <--");  // [ip6] or [server, client, udp, flags]

    uint8_t ip6[MAX_BINKEY], server[MAX_BINKEY], client[MAX_BINKEY];
    int flags, udp, af = AF_UNSPEC, mlen = -1, ok = 0;
    char buf[MAX_STRKEY];
    const char *pfx = NULL;
    size_t len = 0;

    if (lua_gettop(L) == 1) {
        /* decompose ipv6 */
        if (! iptL_getpfxstr(L, 1, &pfx, &len))
            return lipt_error(L, LIPTE_ARG, 1, "");
        if (! key_bystr(ip6, &mlen, &af, pfx))
            return lipt_error(L, LIPTE_PFX, 1, "");
        if (af != AF_INET6)
            return lipt_error(L, LIPTE_AF, 1, "%s not ipv6", "toredo");
        if (! key_toredo(1, ip6, server, client, &udp, &flags))
            return lipt_error(L, LIPTE_ARG, 1, "");
    } else {
        /* compose an ipv6 */
        /* get server ipv4 */
        if (! iptL_getpfxstr(L, 1, &pfx, &len))
            return lipt_error(L, LIPTE_ARG, 1, "");
        if (! key_bystr(server, &mlen, &af, pfx))
            return lipt_error(L, LIPTE_PFX, 1, "%s ?", pfx);
        if (af != AF_INET)
            return lipt_error(L, LIPTE_AF, 1, "%s not ipv4", "server");

        /* get client ipv4 */
        if (! iptL_getpfxstr(L, 2, &pfx, &len))
            return lipt_error(L, LIPTE_ARG, 1, "");
        if (! key_bystr(client, &mlen, &af, pfx))
            return lipt_error(L, LIPTE_PFX, 1, "%s ?", pfx);
        if (af != AF_INET)
            return lipt_error(L, LIPTE_AF, 1, "%s not ipv4", "client");

        /* get udp and flags */
        udp = lua_tointegerx(L, 3, &ok);
        if (! ok)
            return lipt_error(L, LIPTE_ARG, 1, "%s udp", "illegal");
        if (udp < 0 || udp > 65535)
            return lipt_error(L, LIPTE_ARG, 1, "%s udp", "illegal");
        flags = lua_tointegerx(L, 4, &ok);
        if (! ok)
            return lipt_error(L, LIPTE_ARG, 1, "%s flags", "illegal");
        if (flags < 0 || flags > 65535)
            return lipt_error(L, LIPTE_ARG, 1, "%s flags", "illegal");

        /* compose the ipv6 toredo key */
        if (! key_toredo(0, ip6, server, client, &udp, &flags))
            return lipt_error(L, LIPTE_ARG, 1, "");
    }

    lua_settop(L, 0);
    lua_newtable(L);
    if (! key_tostr(buf, ip6))
        return lipt_error(L, LIPTE_TOSTR, 1, "");
    iptT_setfstr(L, "ipv6", "%s", buf);
    if (! key_tostr(buf, server))
        return lipt_error(L, LIPTE_TOSTR, 1, "");
    iptT_setfstr(L, "server", "%s", buf);
    if (! key_tostr(buf, client))
        return lipt_error(L, LIPTE_TOSTR, 1, "");
    iptT_setfstr(L, "client", "%s", buf);
    iptT_setint(L, "udp", udp);
    iptT_setint(L, "flags", flags);

    dbg_stack("out(1) ==>");

    return 1;
}

/*
 * ### `iptable.masklen`
 * ```c
 * static int ipt_masklen(lua_State *L);
 * ```
 * ```lua
 * -- lua
 * mlen, err = iptable.masklen(binkey)
 * ```
 *
 * Return the number of consecutive msb 1-bits, nil & error msg on errors.
 * Note: stops at the first zero bit, without checking remaining bits since
 * non-contiguous masks are not supported.
 */

static int
ipt_masklen(lua_State *L)
{
    dbg_stack("inc(.) <--");  // [binary key]

    uint8_t buf[MAX_BINKEY];
    size_t len = 0;
    int mlen = -1;

    if (!iptL_getbinkey(L, 1, buf, &len))
        return lipt_error(L, LIPTE_ARG, 1, "");

    mlen = key_masklen(buf);
    lua_pushinteger(L, mlen);

    dbg_stack("out(1) ==>");

    return 1;
}

/*
 * ### `iptable.size`
 * ```c
 * static int ipt_size(lua_State *L);
 * ```
 * ```lua
 * -- lua
 * num, err = iptable.size("10.10.10.0/24") -- 256.0
 * ```
 * Returns the number of hosts in a given prefix, nil & an error msg on errors.
 * Note: uses Lua's arithmatic (2^hostbits), since ipv6 can get large, so
 * numbers show up as floating points.
 */

static int
ipt_size(lua_State *L)
{
    dbg_stack("inc(.) <--");  // [pfx]

    uint8_t addr[MAX_BINKEY];
    size_t len = 0;
    int af = AF_UNSPEC, mlen = -1, hlen = -1;
    const char *pfx = NULL;

    if (! iptL_getpfxstr(L, 1, &pfx, &len))
        return lipt_error(L, LIPTE_ARG, 1, "");
    if (! key_bystr(addr, &mlen, &af, pfx))
        return lipt_error(L, LIPTE_PFX, 1, "");
    if (AF_UNKNOWN(af))
        return lipt_error(L, LIPTE_AF, 1, "");

    hlen = af == AF_INET ? IP4_MAXMASK : IP6_MAXMASK;
    hlen = mlen < 0 ? 0 : hlen - mlen;              // mlen<0 means host addr
    lua_pushinteger(L, 2);
    lua_pushinteger(L, hlen);
    lua_arith(L, LUA_OPPOW);
    dbg_stack("out(1) ==>");

    return 1;
}

/*
 * ### `iptable.address`
 * ```c
 * static int ipt_address(lua_State *L);
 * ```
 * ```lua
 * -- lua
 * addr, mlen, af, err = iptable.address("10.10.10.10/24")
 * ```
 *
 * Return host address, masklen and af_family for pfx; nil's & an error msg  on
 * errors.
 */

static int
ipt_address(lua_State *L)
{
    dbg_stack("inc(.) <--");  // [str]

    char buf[MAX_STRKEY];
    uint8_t addr[MAX_BINKEY], mask[MAX_BINKEY];
    size_t len = 0;
    int af = AF_UNSPEC, mlen = -1;
    const char *pfx = NULL;

    if (! iptL_getpfxstr(L, 1, &pfx, &len))
        return lipt_error(L, LIPTE_ARG, 3, "");
    if (! key_bystr(addr, &mlen, &af, pfx))
        return lipt_error(L, LIPTE_PFX, 3, "");
    if (! key_bylen(mask, mlen, af))
        return lipt_error(L, LIPTE_MLEN, 3, "");
    if (! key_tostr(buf, addr))
        return lipt_error(L, LIPTE_TOSTR, 3, "");

    lua_pushstring(L, buf);
    lua_pushinteger(L, mlen);
    lua_pushinteger(L, af);

    dbg_stack("out(3) ==>");

    return 3;
}

/*
 * ### `iptable.dnsptr`
 * ```c
 * static int ipt_dnsptr(lua_State *L);
 * ```
 * ```lua
 * -- lua
 * ptr, mlen, af, err = iptable.dnsptr("10.10.10.10/24")
 * --> 10.10.10.10.in-addr.arpa.
 * ptr, mlen, af, err = iptable.dnsptr("10.10.10.10/24", true)
 * --> 10.10.10.in-addr.arpa.
 *
 * ptr, mlen, af = iptable.dnsptr("acdc:1979:/32")
 * --> 0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.9.7.9.1.c.d.c.a.ip6.arpa.
 * --> 32 10 nil
 * ptr, mlen, af = iptable.dnsptr("acdc:1979:/32", true)
 * --> 9.7.9.1.c.d.c.a.ip6.arpa. 32 10
 * ```
 *
 * Return a reverse dns name for the address part of the prefix, along with its
 * mask length and address family.  If the optional 2nd argument is true and
 * the prefix has a mask larger than zero bits, skip as many leading labels as
 * the mask allows.  Note: this works on a byte resp. nibble boundary since
 * as represented by the dns labels for ipv4 resp. ipv6 reverse names.  A
 * prefix length of zero would be non-sensical since at least 1 label needs to
 * be present left of in-addr.arpa or ip6.arpa.  In case of errors, returns all
 * nils plus an error message.
 */

static int
ipt_dnsptr(lua_State *L)
{
    dbg_stack("inc(.) <--");  // [str [skip]]

    uint8_t addr[MAX_BINKEY], *kp;
    static const char *hex = "0123456789abcdef";
    size_t len = 0;
    int af = AF_UNSPEC, mlen = -1, klen, skip=0;
    const char *pfx = NULL;

    if (! iptL_getpfxstr(L, 1, &pfx, &len))
        return lipt_error(L, LIPTE_ARG, 3, "");
    if (! key_bystr(addr, &mlen, &af, pfx))
        return lipt_error(L, LIPTE_PFX, 3, "");
    if (AF_UNKNOWN(af))
        return lipt_error(L, LIPTE_AF, 3, ": %d", af);
    if (! key_reverse(addr))
        return lipt_error(L, LIPTE_BINOP, 3, "to reverse %s", pfx);
    skip = lua_toboolean(L, 2);
    skip = mlen <= 0 ? 0 : skip;

    /* clear the stack & push the name labels onto the stack */
    lua_settop(L, 0);
    klen = IPT_KEYLEN(addr);
    kp = addr;
    if (af == AF_INET) {
        skip = skip ? (IP4_MAXMASK - mlen)/8 : 0;
        while (--klen > 0 && kp++)
            if (--skip < 0)
                lua_pushfstring(L, "%d.", (int)*kp);
        lua_pushstring(L, "in-addr.arpa.");

    } else {
        /* ipv6 address nibbles are labels, they're already reversed */
        /* lua_pushfstring has no %x conversion specifier, so do a lookup */
        skip = skip ? (IP6_MAXMASK - mlen)/4 : 0;
        while (--klen > 0 && kp++) {
            if (--skip < 0)
                lua_pushfstring(L, "%c.", hex[(*kp & 0xf0)>>4]);
            dbg_msg("skip is %d", skip);
            if (--skip < 0)
                lua_pushfstring(L, "%c.", hex[*kp & 0x0f]);
        }
        lua_pushstring(L, "ip6.arpa.");
    }

    lua_concat(L, lua_gettop(L));
    lua_pushinteger(L, mlen);
    lua_pushinteger(L, af);

    dbg_stack("out(3) ==>");

    return 3;
}

/*
 * ### `iptable.longhand`
 * ```c
 * static int ipt_longhand(lua_State *L);
 * ```
 * ```lua
 * -- lua
 * addr, mlen, af, err = iptable.longhand("2001::/120")
 * --> 2001:0000:0000:0000:0000:0000:0000:0000  120  10
 * ```
 *
 * Return unabbreviated address, masklen and af_family for pfx; nil's & an
 * error msg  on errors.  Only has a real effect on ipv6 prefixes.
 */

static int
ipt_longhand(lua_State *L)
{
    dbg_stack("inc(.) <--");  // [str]

    char buf[MAX_STRKEY];
    uint8_t addr[MAX_BINKEY], mask[MAX_BINKEY];
    size_t len = 0;
    int af = AF_UNSPEC, mlen = -1;
    const char *pfx = NULL;

    if (! iptL_getpfxstr(L, 1, &pfx, &len))
        return lipt_error(L, LIPTE_ARG, 3, "");
    if (! key_bystr(addr, &mlen, &af, pfx))
        return lipt_error(L, LIPTE_PFX, 3, "");
    if (! key_bylen(mask, mlen, af))
        return lipt_error(L, LIPTE_MLEN, 3, "");
    if (! key_tostr_full(buf, addr))
        return lipt_error(L, LIPTE_TOSTR, 3, "");

    lua_pushstring(L, buf);
    lua_pushinteger(L, mlen);
    lua_pushinteger(L, af);

    dbg_stack("out(3) ==>");

    return 3;
}

/*
 * ### `iptable.network`
 * ```c
 * static int ipt_network(lua_State *L);
 * ```
 * ```lua
 * -- lua
 * netw, mlen, af, err = iptable.network("10.10.10.10/24")
 * ```
 *
 * Return network address, masklen and af_family for pfx; nil's & an error msg
 * on errors.
 */

static int
ipt_network(lua_State *L)
{
    dbg_stack("inc(.) <--");  // [pfx]

    char buf[MAX_STRKEY];
    uint8_t addr[MAX_BINKEY], mask[MAX_BINKEY];
    size_t len = 0;
    int af = AF_UNSPEC, mlen = -1;
    const char *pfx = NULL;

    if (! iptL_getpfxstr(L, 1, &pfx, &len))
        return lipt_error(L, LIPTE_ARG, 3, "");

    if (! key_bystr(addr, &mlen, &af, pfx))
        return lipt_error(L, LIPTE_PFX, 3, "");
    if (! key_bylen(mask, mlen, af))
        return lipt_error(L, LIPTE_MLEN, 3, "");

    if (! key_network(addr, mask))
        return lipt_error(L, LIPTE_BINOP, 3, "");
    if (! key_tostr(buf, addr))
        return lipt_error(L, LIPTE_TOSTR, 3, "");

    lua_pushstring(L, buf);
    lua_pushinteger(L, mlen);
    lua_pushinteger(L, af);

    dbg_stack("out(3) ==>");

    return 3;
}

/*
 * ### `iptable.neighbor`
 * ```c
 * static int ipt_neighbor(lua_State *L);
 * ```
 * ```lua
 * -- lua
 * nei, mlen, af, err = iptable.neighbor("10.10.10.10/24")
 * --> 10.10.11.0  24  2
 * ```
 *
 * Given a prefix, return the neighbor prefix, masklen and af_family, such that
 * both can be combined into a supernet whose prefix length is 1 bit shorter.
 * Note that a /0 will not have a neighbor prefix whith which it could be
 * combined.  Returns nil's and an error msg on errors.
 */

static int
ipt_neighbor(lua_State *L)
{
    dbg_stack("inc(.) <--");  // [str]

    char buf[MAX_STRKEY];
    uint8_t addr[MAX_BINKEY], mask[MAX_BINKEY], nbor[MAX_BINKEY];
    size_t len = 0;
    int af = AF_UNSPEC, mlen = -1;
    const char *pfx = NULL;

    if (! iptL_getpfxstr(L, 1, &pfx, &len))
        return lipt_error(L, LIPTE_ARG, 3, "");
    if (! key_bystr(addr, &mlen, &af, pfx))
        return lipt_error(L, LIPTE_PFX, 3, "");
    if (mlen == 0)
       return lipt_error(L, LIPTE_NONE, 3, "");  /* Only a /0 has no neighbor*/
    if (! key_bylen(mask, mlen, af))
        return lipt_error(L, LIPTE_MLEN, 3, "");
    if (! key_bypair(nbor, addr, mask))
        return lipt_error(L, LIPTE_BINOP, 3, "");

    if (! key_tostr(buf, nbor))
        return lipt_error(L, LIPTE_TOSTR, 3, "");

    lua_pushstring(L, buf);
    lua_pushinteger(L, mlen);
    lua_pushinteger(L, af);

    dbg_stack("out(3) ==>");

    return 3;
}


/*
 * ### `iptable.invert`
 * ```c
 * static int ipt_invert(lua_State *L);
 * ```
 * ```lua
 * -- lua
 * inv, mlen, af, err = iptable.invert("255.255.255.0")
 * --> 0.255.255.255  -1  2
 * ```
 * Return inverted address, masklen and af_family.  Returns nil's and an error
 * message  on errors.  Note: the mask is NOT applied before invering the
 * address.
 */

static int
ipt_invert(lua_State *L)
{
    dbg_stack("inc(.) <--");  // [pfx]

    char buf[MAX_STRKEY];
    uint8_t addr[MAX_BINKEY];
    size_t len = 0;
    int af = AF_UNSPEC, mlen = -1;
    const char *pfx = NULL;

    if (! iptL_getpfxstr(L, 1, &pfx, &len))
        return lipt_error(L, LIPTE_ARG, 3, "");
    if (! key_bystr(addr, &mlen, &af, pfx))
        return lipt_error(L, LIPTE_PFX, 3, "");

    if (! key_invert(addr))
        return lipt_error(L, LIPTE_BINOP, 3, "");
    if (! key_tostr(buf, addr))
        return lipt_error(L, LIPTE_TOSTR, 3, "");

    lua_pushstring(L, buf);
    lua_pushinteger(L, mlen);
    lua_pushinteger(L, af);

    dbg_stack("out(3) ==>");

    return 3;
}

/*
 * ### `iptable.properties`
 * ```c
 * static int ipt_properties(lua_State *L);
 * ```
 * ```lua
 * -- lua
 * props, err = iptable.properties("192.168.1.1/24")
 * --> { address="192.168.1.1",
 *       masklength = 24,
 *       private = true,
 *       size = 256
 *       class = C
 *     }
 * ```
 * Returns a table with (some) properties for given prefix.  Returns nil's and
 * an error message  on errors.
 */

static int
ipt_properties(lua_State *L)
{
    dbg_stack("inc(.) <--");  // [pfx]

    char buf[MAX_STRKEY];
    uint8_t addr[MAX_BINKEY], mask[MAX_BINKEY], ip6[MAX_BINKEY], *kp;
    size_t len = 0;
    int af = AF_UNSPEC, mlen = -1;
    const char *pfx = NULL;

    if (! iptL_getpfxstr(L, 1, &pfx, &len))
        return lipt_error(L, LIPTE_ARG, 1, "");
    if (! key_bystr(addr, &mlen, &af, pfx))
        return lipt_error(L, LIPTE_PFX, 1, "");
    if (AF_UNKNOWN(af))
        return lipt_error(L, LIPTE_AF, 1, "af %d ?", af);

    /* clear the stack and push a table */
    lua_settop(L, 0);
    lua_newtable(L);
    kp = IPT_KEYPTR(addr);

    /* address, mlen & af */
    if (! key_tostr(buf, addr))
        return lipt_error(L, LIPTE_TOSTR, 1, "pfx %s ?", pfx);
    iptT_setfstr(L, "address", "%s", buf);
    iptT_setint(L, "pfxlen", mlen);
    iptT_setint(L, "af", af);

    /* mask and inverted mask */
    if (! key_bylen(mask, mlen, af))
        return lipt_error(L, LIPTE_MLEN, 1, "");
    if (! key_tostr(buf, mask))
        return lipt_error(L, LIPTE_TOSTR, 1, "");
    iptT_setfstr(L, "mask", "%s", buf);
    if (! key_invert(mask))
        return lipt_error(L, LIPTE_BINOP, 1, "");
    if (! key_tostr(buf, mask))
        return lipt_error(L, LIPTE_TOSTR, 1, "");
    iptT_setfstr(L, "imask", "%s", buf);


    if (af == AF_INET ) {
        /* class & multicast */
        if((kp[0] & 0x80) == 0x00)                     /* A 0... */
            iptT_setfstr(L, "class", "%s", "A");
        else if((kp[0] & 0xc0) == 0x80)                /* B 10.. */
            iptT_setfstr(L, "class", "%s", "B");
        else if((kp[0] & 0xe0) == 0xc0)                /* C 110. */
            iptT_setfstr(L, "class", "%s", "C");
        else if((kp[0] & 0xf0) == 0xe0) {              /* D 111. */
            iptT_setfstr(L, "class", "%s", "D");
            iptT_setbool(L, "multicast", 1); 
            /* make bool flag more specific if we can */
            if (key_cmp(addr, IP4_MC_UNSPEC) == 0)
                iptT_setfstr(L, "multicast", "%s", "unspecified");
            else if (key_cmp(addr, IP4_MC_HOSTS) == 0)
                iptT_setfstr(L, "multicast", "%s", "allhosts");
            else if (key_cmp(addr, IP4_MC_ROUTERS) == 0)
                iptT_setfstr(L, "multicast", "%s", "allrouters");
            else if (key_cmp(addr, IP4_MC_MAXLOCAL) == 0)
                iptT_setfstr(L, "multicast", "%s", "max-local");
        } else {
            iptT_setfstr(L, "class", "%s", "E");       /* E 1111 */
        }

        /* v4 compat, last since we'll muck about with addr */
        if (! key6_by4(ip6, addr, 0))
            return lipt_error(L, LIPTE_BINOP, 1, "");
        if (! key_tostr(buf, ip6))
            return lipt_error(L, LIPTE_TOSTR, 1, "");
        iptT_setfstr(L, "v4mapped", "%s", buf);
        if (! key6_by4(ip6, addr, 1))
            return lipt_error(L, LIPTE_BINOP, 1, "");
        if (! key_tostr(buf, ip6))
            return lipt_error(L, LIPTE_TOSTR, 1, "");
        iptT_setfstr(L, "v4compat", "%s", buf);
        if (! key6_6to4(ip6, addr))
            return lipt_error(L, LIPTE_BINOP, 1, "");
        if (! key_tostr(buf, ip6))
            return lipt_error(L, LIPTE_TOSTR, 1, "");
        iptT_setfstr(L, "ip6to4", "%s", buf);


    } else {
        /* some additional ipv6 properties; macros from <netinet/in.h> */

        /* in case we need ip6's last bytes as an ipv4 address string */
        if (! key4_by6(ip6, addr))
            return lipt_error(L, LIPTE_BINOP, 1, "");
        if (! key_tostr(buf, ip6))
            return lipt_error(L, LIPTE_TOSTR, 1, "");

        if(IN6_IS_ADDR_V4MAPPED(kp))
            iptT_setfstr(L, "v4mapped", "%s", buf);
        else if(IN6_IS_ADDR_V4COMPAT(kp))
            iptT_setfstr(L, "v4compat", "%s", buf);
        else if(IN6_IS_ADDR_UNSPECIFIED(kp))
            iptT_setbool(L, "unspecified", 1);
        else if(IN6_IS_ADDR_LOOPBACK(kp))
            iptT_setbool(L, "loopback", 1);
        else if(IN6_IS_ADDR_LINKLOCAL(kp))
            iptT_setbool(L, "linklocal", 1);
        else if(IN6_IS_ADDR_SITELOCAL(kp))
            iptT_setbool(L, "sitelocal", 1);
        else if(IN6_IS_ADDR_MULTICAST(kp)) {
            if(IN6_IS_ADDR_MC_NODELOCAL(kp))
                iptT_setfstr(L, "multicast", "%s", "nodelocal");
            else if(IN6_IS_ADDR_MC_LINKLOCAL(kp))
                iptT_setfstr(L, "multicast", "%s", "linklocal");
            else if(IN6_IS_ADDR_MC_SITELOCAL(kp))
                iptT_setfstr(L, "multicast", "%s", "sitelocal");
            else if(IN6_IS_ADDR_MC_ORGLOCAL(kp))
                iptT_setfstr(L, "multicast", "%s", "orglocal");
            else if(IN6_IS_ADDR_MC_GLOBAL(kp))
                iptT_setfstr(L, "multicast", "%s", "global");
            else
                iptT_setbool(L, "multicast", 1);

        } else {
        /* try toredo key extract */
            int flags, udp, get=1;
            uint8_t ts[MAX_BINKEY], tc[MAX_BINKEY];
            if (key_toredo(get, addr, ts, tc, &udp, &flags)) {
                if (! key_tostr(buf, ts))
                    return lipt_error(L, LIPTE_TOSTR, 1, "");
                iptT_setfstr(L, "toredo_server", "%s", buf);
                if (! key_tostr(buf, tc))
                    return lipt_error(L, LIPTE_TOSTR, 1, "");
                iptT_setfstr(L, "toredo_client", "%s", buf);
                iptT_setint(L, "toredo_udp", udp);
                iptT_setint(L, "toredo_flags", flags);
            }
        }
    }

    dbg_stack("out(1) ==>");

    return 1;
}

/*
 * ### `iptable.offset`
 * ```c
 * static int ipt_offset(lua_State *L);
 * ```
 * ```lua
 * -- lua
 * ip, mlen, af, err = iptable.offset("10.10.10.0/24", 1)
 * --> 10.10.10.1  24  2
 * ip, mlen, af, err = iptable.offset("10.10.10.0/24", -1)
 * --> 10.10.9.255 24  2
 * ```
 *
 * Return a new ip address, masklen and af_family by adding an offset to a
 * prefix.  If no offset is given, increments the key by 1.  Returns nil and an
 * error msg on errors such as trying to offset beyond the AF's valid address
 * space (i.e. it won't wrap around).  Note: any mask is ignored during
 * offsetting.
 */

static int
ipt_offset(lua_State *L)
{
    dbg_stack("inc(.) <--");  // [pfx] or [pfx n]

    char buf[MAX_STRKEY];
    uint8_t addr[MAX_BINKEY];
    size_t len = 0;
    lua_Number numb;
    long offset = 1;
    int af = AF_UNSPEC, mlen = -1;
    const char *pfx = NULL;

    /* offset is optional, defaults to 1 */
    if (lua_gettop(L) == 2) {
        /* long route so 2^x's are supported as well, despite being a float */
        numb = lua_tonumber(L, 2);
        if (! lua_numbertointeger(numb, &offset))
            return lipt_error(L, LIPTE_ARG, 3, "");
    }

    if (! iptL_getpfxstr(L, 1, &pfx, &len))
        return lipt_error(L, LIPTE_ARG, 3, "");

    if (! key_bystr(addr, &mlen, &af, pfx))
        return lipt_error(L, LIPTE_PFX, 3, "");

    if (offset > 0) {
        if (! key_incr(addr, offset))
            return lipt_error(L, LIPTE_BINOP, 3, "could %s increment", "not");
    } else {
        if (! key_decr(addr, -offset))
            return lipt_error(L, LIPTE_BINOP, 3, "could %s decrement", "not");
    }

    if (! key_tostr(buf, addr))
        return lipt_error(L, LIPTE_TOSTR, 3, "");

    lua_pushstring(L, buf);
    lua_pushinteger(L, mlen);
    lua_pushinteger(L, af);

    dbg_stack("out(3) ==>");

    return 3;
}
/*
 * ### `iptable.reverse`
 * ```c
 * static int ipt_reverse(lua_State *L);
 * ```
 * ```lua
 * -- lua
 * rev, mlen, af, err = iptable.reverse("1.2.3.4/24")
 * -> 4.3.2.1  24  2
 * ```
 *
 * Return a reversed address, masklen and af_family.  Returns nil's and an
 * error msg on errors.  Note: the mask is NOT applied before reversing the
 * address.
 */

static int
ipt_reverse(lua_State *L)
{
    dbg_stack("inc(.) <--");  // [pfx]

    char buf[MAX_STRKEY];
    uint8_t addr[MAX_BINKEY];
    size_t len = 0;
    int af = AF_UNSPEC, mlen = -1;
    const char *pfx = NULL;

    if (! iptL_getpfxstr(L, 1, &pfx, &len))
        return lipt_error(L, LIPTE_ARG, 3, "");

    if (! key_bystr(addr, &mlen, &af, pfx))
        return lipt_error(L, LIPTE_PFX, 3, "");

    if (! key_reverse(addr))
        return lipt_error(L, LIPTE_BINOP, 3, "");

    if (! key_tostr(buf, addr))
        return lipt_error(L, LIPTE_TOSTR, 3, "");

    lua_pushstring(L, buf);
    lua_pushinteger(L, mlen);
    lua_pushinteger(L, af);

    dbg_stack("out(3) ==>");

    return 3;
}

/*
 * ### `iptable.split`
 * ```c
 * static int ipt_split(lua_State *L);
 * ```
 * ```lua
 * -- lua
 * addr1, addr2, mlen, af, err = iptable.split("10.10.10.10/24")
 * --> 10.10.10.0  10.10.10.128  25  2  nil
 * ```
 *
 * Split a prefix into its two constituent parts.  Returns nils on errors plus
 * an error message.
 */

static int
ipt_split(lua_State *L)
{
    dbg_stack("inc(.) <--");  // [str]

    char buf[MAX_STRKEY], buf2[MAX_STRKEY];
    uint8_t addr[MAX_BINKEY], mask[MAX_BINKEY];
    size_t len = 0;
    int af = AF_UNSPEC, mlen = -1;
    const char *pfx = NULL;

    if (! iptL_getpfxstr(L, 1, &pfx, &len))
        return lipt_error(L, LIPTE_ARG, 4, "");
    if (! key_bystr(addr, &mlen, &af, pfx))
        return lipt_error(L, LIPTE_PFX, 4, "");
    if (mlen == -1)
        return lipt_error(L, LIPTE_SPLIT, 4, "%s", pfx);
    if (af == AF_INET && mlen == IP4_MAXMASK)
        return lipt_error(L, LIPTE_SPLIT, 4, "%s", pfx);
    if (af == AF_INET6 && mlen == IP6_MAXMASK)
        return lipt_error(L, LIPTE_SPLIT, 4, "%s", pfx);

    mlen += 1;
    if (! key_bylen(mask, mlen, af))
        return lipt_error(L, LIPTE_MLEN, 4, "");
    if (! key_network(addr, mask))
        return lipt_error(L, LIPTE_BINOP, 4, "");
    if (! key_tostr(buf, addr))
        return lipt_error(L, LIPTE_TOSTR, 4, "");
    if (! key_broadcast(addr, mask))
        return lipt_error(L, LIPTE_BINOP, 4, "");
    if (! key_incr(addr, 1))
        return lipt_error(L, LIPTE_BINOP, 4, "");
    if (! key_tostr(buf2, addr))
        return lipt_error(L, LIPTE_TOSTR, 4, "");

    lua_pushstring(L, buf);
    lua_pushstring(L, buf2);
    lua_pushinteger(L, mlen);
    lua_pushinteger(L, af);

    dbg_stack("out(3) ==>");

    return 4;
}

/*
 * ### `iptable.broadcast`
 * ```c
 * static int ipt_broadcast(lua_State *L);
 * ```
 * ```lua
 * -- lua
 * bcast, mlen, af, err = iptable.broadcast("10.10.10.10/24")
 * --> 10.10.10.255  24  2
 * ```
 *
 * Return broadcast address, masklen and af_family for pfx; nil's and an error
 * message on errors.
 */

static int
ipt_broadcast(lua_State *L)
{
    dbg_stack("inc(.) <--");  // [pfx]

    int af = AF_UNSPEC, mlen = -1;
    size_t len = 0;
    char buf[MAX_STRKEY];
    uint8_t addr[MAX_BINKEY], mask[MAX_BINKEY];
    const char *pfx = NULL;

    if (! iptL_getpfxstr(L, 1, &pfx, &len))
        return lipt_error(L, LIPTE_ARG, 3, "");
    if (! key_bystr(addr, &mlen, &af, pfx))
        return lipt_error(L, LIPTE_PFX, 3, "");
    if (! key_bylen(mask, mlen, af))
        return lipt_error(L, LIPTE_MLEN, 3, "");
    if (! key_broadcast(addr, mask))
        return lipt_error(L, LIPTE_BINOP, 3, "");
    if (! key_tostr(buf, addr))
        return lipt_error(L, LIPTE_TOSTR, 3, "");

    lua_pushstring(L, buf);
    lua_pushinteger(L, mlen);
    lua_pushinteger(L, af);

    dbg_stack("out(3) ==>");

    return 3;
}

/*
 * ### `iptable.mask`
 * ```c
 * static int ipt_mask(lua_State *L);
 * ```
 * ```lua
 * -- lua
 * mask = iptable.mask(iptable.AF_INET, 30)
 * --> 255.255.255.252
 * mask = iptable.mask(iptable.AF_INET, 30, true)
 * --> 0.0.0.3
 * ```
 *
 * Given an address family `af` and prefix length `mlen`, returns the mask or
 * or nil and an error message on errors.  If the third argument evaluates to
 * true, also inverts the mask.
 */

static int
ipt_mask(lua_State *L)
{
    dbg_stack("inc(.) <--");  // [af, mlen, invert]

    int af = AF_UNSPEC, mlen = -1, isnum = 0, invert = 0;
    char buf[MAX_STRKEY];
    uint8_t mask[MAX_BINKEY];

    if (! iptL_getaf(L, 1, &af))
            return lipt_error(L, LIPTE_ARG, 1, "");
    if (AF_UNKNOWN(af))
        return lipt_error(L, LIPTE_AF, 1, "");
    mlen = lua_tointegerx(L, 2, &isnum);
    if (! isnum)
        return lipt_error(L, LIPTE_ARG, 1, "");
    invert = lua_toboolean(L, 3);

    if (! key_bylen(mask, mlen, af))
        return lipt_error(L, LIPTE_MLEN, 1, "");
    if (invert && ! key_invert(mask))
        return lipt_error(L, LIPTE_BINOP, 1, "");
    if (! key_tostr(buf, mask))
        return lipt_error(L, LIPTE_TOSTR, 1, "");

    lua_pushstring(L, buf);

    dbg_stack("out(1) ==>");

    return 1;
}

/*
 * ### `iptable.hosts`
 * ```c
 * static int iter_hosts(lua_State *L);
 * ```
 * ```lua
 * -- lua
 * for host in iptable.hosts("10.10.10.0/30") do print(host) end
 * --> 10.10.10.1
 * --> 10.10.10.2
 * for host in iptable.hosts("10.10.10.0/30", true) do print(host) end
 * --> 10.10.10.0
 * --> 10.10.10.1
 * --> 10.10.10.2
 * --> 10.10.10.4
 * ```
 *
 * Iterate across host adresses in a given prefix.  An optional second argument
 * defaults to false, but when given & true, the network and broadcast address
 * will be included in the iteration results.  If prefix has no mask, the af's
 * max mask is used.  In which case, unless the second argument is true, it
 * won't iterate anything.  In case of errors (it won't iterate), check out
 * `iptable.error` for clues.
 */
static int iter_hosts(lua_State *L) { dbg_stack("inc(.) <--");  // [pfx [incl]]

    size_t len = 0;
    int af = AF_UNSPEC, mlen = -1, inclusive = 0;
    uint8_t addr[MAX_BINKEY], mask[MAX_BINKEY], stop[MAX_BINKEY];
    const char *pfx = NULL;

    if (lua_gettop(L) == 2 && lua_isboolean(L, 2))
        inclusive = lua_toboolean(L, 2);  // include netw/bcast (or not)

    if (! iptL_getpfxstr(L, 1, &pfx, &len))
        return iter_error(L, LIPTE_ARG, "?");
    if (! key_bystr(addr, &mlen, &af, pfx))
        return iter_error(L, LIPTE_TOBIN, "'%s' ?", pfx);
    if (! key_bystr(stop, &mlen, &af, pfx))
        return iter_error(L, LIPTE_TOBIN, "'%s' ?", pfx);
    if (! key_bylen(mask, mlen, af))
        return iter_error(L, LIPTE_BINOP, "");
    if (! key_network(addr, mask))
        return iter_error(L, LIPTE_BINOP, "");
    if (! key_broadcast(stop, mask))
        return iter_error(L, LIPTE_BINOP, "");

    if (inclusive)                                     // incl network/bcast?
        key_incr(stop, 1);
    else if (key_cmp(addr, stop) < 0)
        key_incr(addr, 1); // not inclusive, so donot 'iterate' a host ip addr.

    lua_pushlstring(L, (const char *)addr, IPT_KEYLEN(addr));
    lua_pushlstring(L, (const char *)stop, IPT_KEYLEN(stop));
    dbg_stack("suc6! 2+");
    lua_pushcclosure(L, iter_hosts_f, 2);  // [.., func]

    dbg_stack("out(1) ==>");

    return 1;
}


/*
 * ### `iptable.interval`
 * ```c
 * static int ipt_interval(lua_State *L);
 * ```
 * ```lua
 * -- lua
 *   for subnet in iptable.interval("10.10.10.0", "10.10.10.9") do
 *     print(subnet)
 *   end
 *   --> 10.10.10.0/29
 *   --> 10.10.10.8/31
 * ```
 *
 * Iterate across the prefixes that, combined, cover the address space
 * between the `start` & `stop` addresses given (inclusive).  Any masks in
 * either `start` or `stop` are ignored and both need to belong to the same
 * AF_family.  In case of errors it won't iterate anything, in that case
 * `iptable.error` will show the last error seen.
 *
 */

static int
iter_interval(lua_State *L)
{
    dbg_stack("(inc) <--");   // <-- [start, stop]

    uint8_t start[MAX_BINKEY], stop[MAX_BINKEY];
    const char *pfx = NULL;
    int mlen = -1, af = AF_UNSPEC, af2 = AF_UNSPEC;;
    size_t len;

    /* pickup start */
    if (! iptL_getpfxstr(L, 1, &pfx, &len))
        return iter_error(L, LIPTE_ARG, "");
    if (! key_bystr(start, &mlen, &af, pfx))
        return iter_error(L, LIPTE_PFX, "");
    if (AF_UNKNOWN(af))
        return iter_error(L, LIPTE_AF, "");

    /* pickup stop */
    if (! iptL_getpfxstr(L, 2, &pfx, &len))
        return iter_error(L, LIPTE_ARG, "");
    if (! key_bystr(stop, &mlen, &af2, pfx))
        return iter_error(L, LIPTE_PFX, "");
    if (af != af2)
        return iter_error(L, LIPTE_AF, "");

    lua_pushlstring(L, (const char *)start, IPT_KEYLEN(start));
    lua_pushlstring(L, (const char *)stop, IPT_KEYLEN(stop));
    lua_pushinteger(L, 0); /* wrap around protection */
    lua_pushcclosure(L, iter_interval_f, 3);

    dbg_stack("out(1) ==>");

    return 1;
}

/*
 * ### `iptable.subnets`
 * ```c
 * static int ipt_subnets(lua_State *L);
 * ```
 * ```lua
 * -- lua
 *   for subnet in iptable.subnets("10.10.10.0/24", 26) do
 *     print(subnet)
 *   end
 *   --> 10.10.10.0/26
 *   --> 10.10.10.64/26
 *   --> 10.10.10.128/26
 *   --> 10.10.10.192/26
 * ```
 *
 * Iterate across the smaller prefixes given a start prefix and a larger
 * network mask, which is optional and defaults to being 1 bit longer than
 * that of the given prefix (similar to split).  In case of errors, it won't
 * iterate anything in which case `iptable.error` might shed some light on the
 * error encountered.
 */

static int
iter_subnets(lua_State *L)
{
    dbg_stack("(inc) <--");   // <-- [pfx, mlen]

    uint8_t start[MAX_BINKEY], stop[MAX_BINKEY], mask[MAX_BINKEY];
    const char *pfx = NULL;
    int mlen = -1, mlen2, af = AF_UNSPEC;
    size_t len;

    /* pickup start */
    if (! iptL_getpfxstr(L, 1, &pfx, &len))
        return iter_error(L, LIPTE_ARG, "prefix?");
    if (! key_bystr(start, &mlen, &af, pfx))
        return iter_error(L, LIPTE_PFX, "prefix %s ?", pfx);
    if (AF_UNKNOWN(af))
        return iter_error(L, LIPTE_AF, "af %d ?", af);

    /* are subnets possible ? */
    if (mlen == -1)
        return iter_error(L, LIPTE_SPLIT, "%s", pfx);
    if (af == AF_INET && mlen == IP4_MAXMASK)
        return iter_error(L, LIPTE_SPLIT, "%s", pfx);
    if (af == AF_INET6 && mlen == IP6_MAXMASK)
        return iter_error(L, LIPTE_SPLIT, "%s", pfx);

    /* pick up new masklen, check validity and calculate binary mask*/
    mlen2 = mlen + 1;
    if (lua_gettop(L) == 2 && lua_isinteger(L, 2))
        mlen2 = lua_tointeger(L, 2);
    if (mlen2 < 0 || mlen2 <= mlen)
        return iter_error(L, LIPTE_ARG, "new mask %d ?", mlen2);
    if (af == AF_INET && mlen2 > IP4_MAXMASK)
        return iter_error(L, LIPTE_ARG, "invalid new mask %d", mlen2);
    if (af == AF_INET6 && mlen2 > IP6_MAXMASK)
        return iter_error(L, LIPTE_ARG, "invalid new mask %d", mlen2);

    /* calculate stop as broadcast address using original mask*/
    memcpy(stop, start, IPT_KEYLEN(start));
    if (! key_bylen(mask, mlen, af))
        return iter_error(L, LIPTE_BINOP, "binmask for /%d", mlen);
    if (! key_network(start, mask))
        return iter_error(L, LIPTE_BINOP, "%s", "no network");
    if (! key_broadcast(stop, mask))
        return iter_error(L, LIPTE_BINOP, "[%s]", "no broadcast");

    /* setup iterator function */
    if (! key_bylen(mask, mlen2, af))
        return iter_error(L, LIPTE_BINOP, "binmask for /%d", mlen2);
    lua_settop(L, 0);
    lua_pushlstring(L, (const char *)start, IPT_KEYLEN(start));
    lua_pushlstring(L, (const char *)stop, IPT_KEYLEN(stop));
    lua_pushlstring(L, (const char *)mask, IPT_KEYLEN(stop));
    lua_pushinteger(L, mlen2);
    lua_pushinteger(L, 0); /* wrap around protection */
    lua_pushcclosure(L, iter_subnets_f, 5);

    dbg_stack("out(1) ==>");

    return 1;
}


/*
 * ## instance methods
 */

/*
 * ### `iptm_newindex`
 * ```c
 * static int iptm_newindex(lua_State *L);
 * ```
 * ```lua
 * -- lua
 * ipt = require"iptable".new()
 * ipt["acdc:1979::"] = "Jailbreak"
 * ```
 *
 * Implements `t[k] = v`
 *
 * If v is nil, t[k] is deleted.  Otherwise, v is stored in the lua_registry
 * and its ref-value is stored in the radix tree. If k is not a valid ipv4/6
 * prefix, cleanup and ignore the request.
 */

static int
iptm_newindex(lua_State *L)
{
    dbg_stack("inc(.) <--");   // [t k v]

    const char *pfx = NULL;
    size_t len = 0;
    table_t *t = iptL_gettable(L, 1);
    int *refp = NULL;

    if (! iptL_getpfxstr(L, 2, &pfx, &len))
        return lipt_error(L, LIPTE_ARG, 1, "");

    if (lua_isnil(L, -1))
        tbl_del(t, pfx, L);   // assigning nil deletes the entry
    else
        if ((refp = iptL_refpcreate(L)))
            if (! tbl_set(t, pfx, refp, L))
                iptL_refpdelete(L, (void**)&refp);

    dbg_stack("out(0) ==>");

    return 0;
}

/*
 * ### `iptm_index`
 * ```c
 * static int iptm_index(lua_State *L);
 * ```
 * ```lua
 * -- lua
 * ipt = require"iptable".new()
 * ipt["10.10.10.0/25"] = "lower half"
 * ipt["10.10.10.1"]    --> lower half
 * ipt["10.1.10.128"]   --> nil
 * ipt["10.10.10.0/24"] --> nil
 * ```
 *
 * Given an index `k`:
 *
 * - do longest prefix search if `k` is a prefix without mask,
 * - do an exact match if `k` is a prefix with a mask
 * - otherwise, do metatable lookup for property named by `k`.
 */

static int
iptm_index(lua_State *L)
{
    dbg_stack("inc(.) <--");  // [t k]

    entry_t *entry = NULL;
    size_t len = 0;
    const char *pfx = NULL;
    table_t *t = iptL_gettable(L, 1);

    if (! iptL_getpfxstr(L, 2, &pfx, &len))
        return lipt_error(L, LIPTE_ARG, 1, "");

    if(pfx)
        entry = strchr(pfx, '/') ? tbl_get(t, pfx) : tbl_lpm(t, pfx);

    if(entry)
        lua_rawgeti(L, LUA_REGISTRYINDEX, *(int *)entry->value); // [t k v]
    else
        if (luaL_getmetafield(L, 1, pfx) == LUA_TNIL)
            return 0;


    dbg_stack("out(1) ==>");

    return 1;
}

/*
 * ### `iptm_len`
 * ```c
 * static int iptm_len(lua_State *L);
 * ```
 * ```lua
 * -- lua
 * t = require"iptable".new()
 * t["1.2.3.4/24"] = "boring"
 * t["acdc:1979::/120"] = "touch too much"
 * #t --> 2
 * ```
 *
 * Return the sum of the number of entries in the ipv4 and ipv6 radix trees as
 * the 'length' of the table.
 */

static int
iptm_len(lua_State *L)
{
    dbg_stack("inc(.) <--");  // [t]

    table_t *t = iptL_gettable(L, 1);
    lua_pushinteger(L, t->count4 + t->count6);

    dbg_stack("out(1) ==>");

    return 1;
}

/*
 * ### `iptm_tostring`
 * ```c
 * static int iptm_tostring(lua_State *L);
 * ```
 * ```lua
 * -- lua
 * ipt = require"iptable".new()
 * ipt -- iptable{#ipv4=0, #ipv6=0}  --- an empty ip table
 * ```
 * Return a string representation of the iptable instance the respective ipv4
 * and ipv6 counters.  Note that the ipv6 counter may overflow at some point...
 */

static int
iptm_tostring(lua_State *L)
{
    dbg_stack("inc(.) <--");  // [t]

    table_t *t = iptL_gettable(L, 1);
    lua_pushfstring(L, "iptable{#ipv4=%d, #ipv6=%d}", t->count4, t->count6);

    dbg_stack("out(1) ==>");

    return 1;
}

/*
 * ### `iptm_counts`
 * ```c
 * static int iptm_counts(lua_State *L);
 * ```
 * ```lua
 * -- lua
 * ipt = require"iptable".new()
 * ip4c, ip6c = ipt:counts()
 * --> 0  0
 * ```
 *
 * Return the number of entries in both the ipv4 and ipv6 radix tree.
 */

static int
iptm_counts(lua_State *L)
{
    dbg_stack("inc(.) <--");               // [t]

    table_t *t = iptL_gettable(L, 1);
    lua_pushinteger(L, t->count4);         // [t count4]
    lua_pushinteger(L, t->count6);         // [t count4 count6]

    dbg_stack("out(2) ==>");

    return 2;                              // [.., count4, count6]
}

/*
 * ### `iter_kv`
 * ```c
 * static int iter_kv(lua_State *L);
 * ```
 * ```lua
 * -- lua
 * ipt = require"iptable".new()
 * ipt["1.1.1.1"] = 1
 * ipt["2001:abab::"] = 2
 *
 * for k,v in pairs(ipt) do print(k,v) end
 * --> 1.1.1.1       1
 * --> 2001:abab::   2
 * ```
 *
 * Iterate across key,value-pairs in the table.  The first ipv4 or ipv6
 * leaf node is pushed.  The `iter_kv_f` iterator uses nextleaf to go through
 * all leafs of the tree.  It will traverse ipv6 as well if we started with the
 * ipv4 tree first.  If an errors occurs, it won't iterate anything and
 * `iptable.error` should provide some information.
 */

static int
iter_kv(lua_State *L)
{
    dbg_stack("inc(.) <--");             // [t], for k,v in pairs(t) do.. end

    table_t *t = iptL_gettable(L, 1);
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

    if (rn == NULL) return iter_error(L, LIPTE_NONE, "");

    lua_pushlightuserdata(L, rn);        // [t rn], rn is 1st node
    iptL_pushitrgc(L, t);                // [t rn gc], itr garbage collector
    lua_pushcclosure(L, iter_kv_f, 2);   // [t f]
    lua_rotate(L, 1, 1);                 // [f t]
    lua_pushnil(L);                      // [f t nil]

    dbg_stack("out(3) ==>");

    return 3;                            // [iter_f invariant ctl_var]
}

/*
 * ### `iter_more`
 * ```c
 * static int iter_more(lua_State *L);
 * ```
 * ``` lua
 * -- lua
 * ipt = require"iptable".new()
 * for prefix in ipt:more("10.10.10.0/24") do ... end
 * for prefix in ipt:more("10.10.10.0/24", true) do ... end
 * ```
 *
 * Iterate across more specific prefixes. AF_family is deduced from the
 * prefix given.  Note this traverses the entire tree if pfx has a /0 mask.
 *
 * The second optional argument may be used to include the search prefix in the
 * search results should it exist in tree.
 */

static int
iter_more(lua_State *L)
{
    dbg_stack("inc(.) <--");  // [t pfx bool], bool is optional

    size_t len = 0;
    int af = AF_UNSPEC, mlen = -1, maxb = -1;
    uint8_t addr[MAX_BINKEY], mask[MAX_BINKEY];
    struct radix_node_head *head = NULL;
    struct radix_node *rn = NULL, *top = NULL;
    int inclusive = 0;

    table_t *t = iptL_gettable(L, 1);
    const char *pfx = NULL;
    if (! iptL_getpfxstr(L, 2, &pfx, &len))
        return lipt_error(L, LIPTE_ARG, 2, "");

    if (! key_bystr(addr, &mlen, &af, pfx))
        return iter_error(L, LIPTE_PFX, "");

    if (lua_gettop(L) == 3 && lua_isboolean(L, 3))
      inclusive = lua_toboolean(L, 3);
    if (af == AF_INET) {
      head = t->head4;
      mlen = mlen < 0 ? IP4_MAXMASK : mlen;
    } else if (af == AF_INET6) {
      head = t->head6;
      mlen = mlen < 0 ? IP6_MAXMASK : mlen;
    } else
      return iter_error(L, LIPTE_AF, "");

    if (! key_bylen(mask, mlen, af))
        return iter_error(L, LIPTE_MLEN, "");
    if (! key_network(addr, mask))
        return iter_error(L, LIPTE_BINOP, "");
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
    iptL_pushitrgc(L, t);
    lua_pushcclosure(L, iter_more_f, 6);            // [t f]
    lua_rotate(L, 1, 1);                          // [f t]

    dbg_stack("out(1) ==>");

    return 2;                                     // [iter_f invariant]
}

/*
 * ### `iter_less`
 * ```c
 * static int iter_less(lua_State *L);
 * ```
 * ```lua
 * -- lua
 * ipt = require"iptable".new()
 * for prefix in ipt:less("10.10.10.10/26") do ... end
 * for prefix in ipt:less("10.10.10.10/26", true) do ... end
 * ```
 *
 * Iterate across prefixes in the tree that are less specific than pfx.  The
 * optional second argumnet, when true, causes the search prefix to be included
 * in the search results should it be present in the table itself.
 */

static int
iter_less(lua_State *L)
{
    dbg_stack("inc(.) <--");  // [t pfx incl]

    table_t *t = iptL_gettable(L, 1);
    size_t len = 0;
    int mlen = 0, inclusive = 0, af = AF_UNSPEC;
    uint8_t addr[MAX_BINKEY];
    const char *pfx = NULL;
    char buf[MAX_STRKEY];

    iptL_getpfxstr(L, 2, &pfx, &len);
    if (pfx == NULL || len < 1)
        return iter_error(L, LIPTE_ARG, "");

    if (lua_gettop(L) > 2 && lua_isboolean(L, 3))
      inclusive = lua_toboolean(L, 3);

    lua_pop(L, lua_gettop(L) - 1);                        // [t]

    if (! key_bystr(addr, &mlen, &af, pfx))
        return iter_error(L, LIPTE_PFX, "");
    if (! key_tostr(buf, addr))
        return iter_error(L, LIPTE_PFX, "");

    if (af == AF_INET)
      mlen = mlen < 0 ? IP4_MAXMASK : mlen;
    else if (af == AF_INET6)
      mlen = mlen < 0 ? IP6_MAXMASK : mlen;
    else
      return iter_error(L, LIPTE_AF, "");

    mlen = inclusive ? mlen : mlen -1;
    if (mlen < 0)
        // less specific than /0 is a no-op if not allowed to include self
        return iter_error(L, LIPTE_NONE, "");

    lua_pushstring(L, buf);                              // [t pfx]
    lua_pushinteger(L, mlen);                            // [t pfx mlen]
    iptL_pushitrgc(L, t);                              // [t pfx mlen gc]
    lua_pushcclosure(L, iter_less_f, 3);                 // [t f]
    lua_rotate(L, 1, 1);                                 // [f t]

    dbg_stack("out(2) ==>");

    return 2;     // [iter_f invariant] (ctl_var not needed)
}

/*
 * ### `iter_masks`
 * ```c
 * static int iter_masks(lua_State *L);
 * ```
 * ```lua
 * -- lua
 * iptable = require"iptable"
 * ipt = iptable.new()
 * for mask in ipt:masks(iptable.AF_INET4) do ... end
 * for mask in ipt:masks(iptable.AF_INET6) do ... end
 * ```
 *
 * Iterate across all masks used in the given `af`-family's radix tree.
 * Notes:
 *
 * - a mask tree stores masks in rn_key fields.
 * - a mask's KEYLEN is the nr of non-zero mask bytes, not a real LEN byte
 * - a /0 (zeromask) is never stored in the radix mask tree (!).
 * - a /0 (zeromask) is stored in ROOT(0.0.0.0)'s *last* dupedkey-chain leaf.
 * - the AF_family cannot be deduced from the mask in rn_key.
 *
 * So, the iteration function needs the AF to properly format masks for the
 * given family (an ipv6/24 mask would otherwise come out as 255.255.255.0) and
 * an explicit flag needs to be passed to iter_f that a zeromask entry is
 * present.
 */

static
int iter_masks(lua_State *L) { 

    dbg_stack("inc(.) <--");                         // [t af]

    uint8_t binmask[MAX_BINKEY];
    char strmask[MAX_STRKEY];

    struct radix_node_head *rnh;
    struct radix_node *rn;
    int isnum = 0, af = AF_UNSPEC;
    table_t *t = iptL_gettable(L, 1);

    if (lua_gettop(L) != 2)
        return iter_error(L, LIPTE_AF, "");            // no AF_family

    af = lua_tointegerx(L, 2, &isnum);
    if (!isnum || AF_UNKNOWN(af))
        return iter_error(L, LIPTE_AF, "");            // bad AF_family
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
        if (! key_bylen(binmask, 0, af))
            return iter_error(L, LIPTE_TOBIN, "");
        if (! key_tostr(strmask, binmask))
            return iter_error(L, LIPTE_TOSTR, "");
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
    lua_pushcclosure(L, iter_masks_f, 3);            // [t f]
    lua_rotate(L, 1, 1);                             // [f t]

    dbg_stack("out(2) ==>");

    return 2;                                        // [iter_f invariant]
}

/*
 * ### `iter_supernets`
 * ```c
 * static int iter_supernets(lua_State *L);
 * ```
 * ```lua
 * -- lua
 * iptable = require"iptable"
 * ipt = iptable.new()
 * for super, group in ipt:supernets(iptable.AF_INET) do ... end
 * for super, group in ipt:supernets(iptable.AF_INET6) do ... end
 * ```
 *
 * Iterate across pairs of pfx's that may be combined into their parental
 * supernet whose prefix length is 1 less than that of its subnets.  The
 * iterator returns the supernet prefix (string) and a regular Lua table that
 * contains either 2 of 3 prefix,value-pairs.  In case the supernet itself is
 * also present in the table, it's included the group table as well.
 */

static int
iter_supernets(lua_State *L)
{
    dbg_stack("inc(.) <--");                  // [t af]

    struct radix_node *rn;
    table_t *t = iptL_gettable(L, 1);
    int af = AF_UNSPEC;
    iptL_getaf(L, 2, &af);

    lua_pop(L, 1);                            // [t]
    if (af == AF_INET)
      rn = rdx_firstleaf(&t->head4->rh);
    else if (af == AF_INET6)
      rn = rdx_firstleaf(&t->head6->rh);
    else
      return iter_error(L, LIPTE_AF, "");

    lua_pushlightuserdata(L, rn);             // [t af rn]
    lua_pushlightuserdata(L, NULL);           // [t af rn NULL]
    iptL_pushitrgc(L, t);                     // [t af rn NULL gc]
    lua_pushcclosure(L, iter_supernets_f, 3);     // [t f]
    lua_rotate(L, 1, -1);                     // [f t]

    dbg_stack("out(2) ==>");

    return 2;                                 // [iter_f invariant]
}

/*
 * ### `iter_radixes`
 * ```c
 * static int iter_radixes(lua_State *L);
 * ```
 * ```lua
 * -- lua
 * iptable = require"iptable"
 * ipt = iptable.new()
 * for rdx in ipt:radixes(iptable.AF_INET) do ... end
 * for rdx in ipt:radixes(iptable.AF_INET6) do ... end
 * ```
 *
 * Iterate across all nodes of all types in the given af's radix tree.  By
 * default it will only iterate across the prefix-tree.  To include the
 * radix nodes of the associated mask-tree include a second argument that
 * evaluates to `true`.
 *
 * The iterator will return the C-structs as Lua tables and is used to graph
 * the radix trees.  Useful for debugging iptable's code and for getting the
 * hang of the radix structures built by [*FreeBSD*](https://freebsd.org)'s
 * `radix.c` code.
 */

static int
iter_radixes(lua_State *L)
{
    dbg_stack("inc(.) <--");                        // [t af maskp]

    table_t *t = iptL_gettable(L, 1);
    int maskp = lua_toboolean(L, 3);
    int af = AF_UNSPEC;

    iptL_getaf(L, 2, &af);
    if (AF_UNKNOWN(af))
        return iter_error(L, LIPTE_AF, "");

    /* pushes af_fam's radix_node_head onto t's stack */
    if (! rdx_firstnode(t, af))
        return iter_error(L, LIPTE_NONE, "");

    /* maskp & itr_gc as upvalues for iterator */
    lua_settop(L, 1);                                // [t]
    lua_pushboolean(L, maskp);                       // [t maskp]
    iptL_pushitrgc(L, t);                            // [t maskp {}]
    lua_pushcclosure(L, iter_radix, 2);              // [t f]
    lua_rotate(L, 1, 1);                             // [f t]

    dbg_stack("out(2) ==>");

    return 2;                                       // [iter_f invariant]
}

