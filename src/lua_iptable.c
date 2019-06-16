// file lua_iptable.c -- Lua bindings for iptable

#include <malloc.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <string.h>
#include <math.h>

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#include "radix.h"
#include "iptable.h"
#include "debug.h"


// lua_iptable defines

#define LUA_IPTABLE_ID "iptable"
#define AF_UNKNOWN(f) (f != AF_INET && f!= AF_INET6)

// lua functions

int luaopen_iptable(lua_State *);

// helper funtions

table_t *check_table(lua_State *, int);
static int check_binkey(lua_State *, int, char *, size_t *);
const char *check_pfxstr(lua_State *, int, size_t *);
static int *ud_create(int);                        // userdata stored as entry->value
static void ud_delete(void *, void **);            // ud_delete(L, &ud)
static int iter_kv(lua_State *);
static int iter_hosts(lua_State *);

// iptable module functions

static int ipt_new(lua_State *);
static int ipt_tobin(lua_State *);
static int ipt_tostr(lua_State *);
static int ipt_tolen(lua_State *);
static int ipt_numhosts(lua_State *);
static int ipt_network(lua_State *);
static int ipt_broadcast(lua_State *);
static int ipt_mask(lua_State *);
static int ipt_iter_hosts(lua_State *);


// (ip)table instance methods

static int _gc(lua_State *);
static int _index(lua_State *);
static int _newindex(lua_State *);
static int _len(lua_State *);
static int _tostring(lua_State *);
static int _pairs(lua_State *);
static int counts(lua_State *);
static int more(lua_State *);
static int less(lua_State *);


// iptable module function array

static const struct luaL_Reg funcs [] = {
    {"new", ipt_new},
    {"tobin", ipt_tobin},
    {"tostr", ipt_tostr},
    {"tolen", ipt_tolen},
    {"network", ipt_network},
    {"broadcast", ipt_broadcast},
    {"mask", ipt_mask},
    {"numhosts", ipt_numhosts},
    {"hosts", ipt_iter_hosts},
    {NULL, NULL}
};

// iptable instance methods array

static const struct luaL_Reg meths [] = {
    {"__gc", _gc},
    {"__index", _index},
    {"__newindex", _newindex},
    {"__len", _len},
    {"__tostring", _tostring},
    {"__pairs", _pairs},
    {"counts", counts},
    {"more", more},
    {"less", less},
    {NULL, NULL}
};

// libopen

int
luaopen_iptable (lua_State *L)
{
    // require("iptable") <-- ['iptable', '<path>/iptable.so' ]
    dbg_stack("inc(.) <--");

    luaL_newmetatable(L, LUA_IPTABLE_ID);   // [.., {} ]
    lua_pushvalue(L, -1);                   // [.., {}, {} ]
    lua_setfield(L, -2, "__index");         // [.., {__index={}} ]
    luaL_setfuncs(L, meths, 0);             // [.., {__index={m's}} ]
    luaL_newlib(L, funcs);                  // [.., {__index={m's}, f's} ]
    lua_pushinteger(L, AF_INET);            // lib constant
    lua_setfield(L, -2, "AF_INET");
    lua_pushinteger(L, AF_INET6);           // lib constant
    lua_setfield(L, -2, "AF_INET6");

    dbg_stack("out(1) ==>");

    return 1;
}

// helpers

table_t *
check_table (lua_State *L, int index)
{
    void **ud = luaL_checkudata(L, index, LUA_IPTABLE_ID);
    luaL_argcheck(L, ud != NULL, index, "`iptable' expected");
    return (table_t *)*ud;
}

static int
check_binkey(lua_State *L, int idx, char *buf, size_t *len)
{
    // Write a binary key @ idx into buffer buf;
    // returns 1 on success, 0 on failure; assumes -> char buf[KEYBUFLEN_MAX]

    // dbg_stack("<--");

    const char *key = NULL;

    if (!lua_isstring(L, idx)) return 0;

    key = lua_tolstring(L, idx, len);
    if (key == NULL) return 0;
    // LEN-byte cannot ever be larger than max buf length
    if (IPT_KEYLEN(key) > KEYBUFLEN_MAX-1) return 0;
    if (*len < 1 || *len > KEYBUFLEN_MAX-1) return 0;

    memcpy(buf, key, *len);  // copies any embedded 0's in a binary key
    buf[*len] = '\0';
    // dbg_stack("==>");

    return 1;
}

const char *
check_pfxstr(lua_State *L, int idx, size_t *len)
{
    // return const char to valid prefix string.  NULL on failure.
    const char *pfx = NULL;
    if (! lua_isstring(L, idx)) return NULL;
    pfx = lua_tolstring(L, idx, len);  // donot use luaL_tolstring!

    return pfx;
}

static int *ud_create(int ref)
{
    // store LUA_REGISTRYINDEX ref's in the radix tree as ptr->int
    int *p = calloc(1, sizeof(int));
    *p = ref;
    return p;
}

static void
ud_delete(void *L, void **refp)
{
    // unref the userdata and free associated ptr->int
    if (*refp) {
        luaL_unref((lua_State *)L, LUA_REGISTRYINDEX, *(int *)*refp);
        free(*refp);
    }
    *refp = NULL;
}

// iptable module functions

static int
ipt_new(lua_State *L)
{
    // void** -> tbl_destroy(&ud) sets t=NULL when done clearing it
    // Return a new iptable instance.  Bails on memory errors.
    dbg_stack("inc(.) <--");

    void **t = lua_newuserdata(L, sizeof(void **));
    *t = tbl_create(ud_delete);             // ud_delete func to free values

    if (*t == NULL) {
        lua_pushliteral(L, "error creating iptable");
        lua_error(L);
    }

    luaL_getmetatable(L, LUA_IPTABLE_ID); // [ud M]
    lua_setmetatable(L, 1);

    dbg_stack("out(1) ==>");

    return 1;
}

static int
ipt_tobin(lua_State *L)
{
    // iptable.tobin(strKey) <-- [str]
    // Return binary form, masklength & AF for a given prefix, nil on errors
    dbg_stack("inc(.) <--");

    int af, mlen;
    uint8_t addr[KEYBUFLEN_MAX];
    size_t len = 0;
    const char *pfx = check_pfxstr(L, 1, &len);

    if (! key_bystr(pfx, &mlen, &af, addr)) return 0;

    lua_pushlstring(L, (const char*)addr, IPT_KEYLEN(addr));
    lua_pushinteger(L, mlen);
    lua_pushinteger(L, af);

    dbg_stack("out(3) ==>");

    return 3;
}

static int
ipt_tostr(lua_State *L)
{
    // iptable.tostr(binKey) <-- [binkey]
    // Return string representation for a binary key, nil on errors
    dbg_stack("inc(.) <--");

    char buf[KEYBUFLEN_MAX];
    char str[KEYBUFLEN_MAX];
    size_t len = 0;

    if (!check_binkey(L, 1, buf, &len)) return 0;
    if (len != (size_t)IPT_KEYLEN(buf)) return 0; // illegal binary
    if (key_tostr(buf, str) == NULL) return 0;

    lua_pushstring(L, str);

    dbg_stack("out(1) ==>");

    return 1;
}

static int
ipt_tolen(lua_State *L)
{
    // iptable.tolen(binKey) <-- [key]
    // Return the number of consequtive msb 1-bits, nil on errors.
    // - stops at the first zero bit.
    dbg_stack("inc(.) <--");

    char buf[KEYBUFLEN_MAX];
    size_t len = 0;
    int mlen = -1;

    if (!check_binkey(L, 1, buf, &len)) return 0;

    mlen = key_tolen(buf);
    lua_pushinteger(L, mlen);

    dbg_stack("out(1) ==>");

    return 1;
}

static int
ipt_numhosts(lua_State *L)
{
    // iptable.numhosts(strKey) <-- [str]
    // Return the number of hosts in a given prefix, nil on errors
    // - uses Lua's arithmatic (2^hostbits), since ipv6 can get large.

    dbg_stack("inc(.) <--");

    uint8_t addr[KEYBUFLEN_MAX];
    size_t len = 0;
    int af = AF_UNSPEC, mlen = -1, hlen = -1;
    const char *pfx = NULL;

    pfx = check_pfxstr(L, 1, &len);
    if (! key_bystr(pfx, &mlen, &af, addr)) return 0;
    if (AF_UNKNOWN(af)) return 0;

    hlen = af == AF_INET ? IP4_MAXMASK : IP6_MAXMASK;
    hlen = mlen < 0 ? 0 : hlen - mlen;              // mlen<0 means host addr
    lua_pushinteger(L, 2);
    lua_pushinteger(L, hlen);
    lua_arith(L, LUA_OPPOW);
    dbg_stack("out(1) ==>");

    return 1;
}

static int
ipt_network(lua_State *L)
{
    // iptable.network(strKey) <-- [str]
    // Return network address & masklen for a given prefix, nil on errors
    dbg_stack("inc(.) <--");

    char buf[IP6_PFXSTRLEN];
    uint8_t addr[KEYBUFLEN_MAX], mask[KEYBUFLEN_MAX];
    size_t len = 0;
    int af = AF_UNSPEC, mlen = -1;
    const char *pfx = NULL;

    pfx = check_pfxstr(L, 1, &len);
    if (! key_bystr(pfx, &mlen, &af, addr)) return 0;
    if (! key_bylen(af, mlen, mask)) return 0;
    if (! key_network(addr, mask)) return 0;
    if (! key_tostr(addr, buf)) return 0;

    lua_pushstring(L, buf);
    lua_pushinteger(L, mlen);
    lua_pushinteger(L, af);

    dbg_stack("out(3) ==>");

    return 3;
}

static int
ipt_broadcast(lua_State *L)
{
    // iptable.broadcast(strKey) <-- [str]
    dbg_stack("inc(.) <--");

    int af = AF_UNSPEC, mlen = -1;
    size_t len = 0;
    char buf[KEYBUFLEN_MAX];
    uint8_t addr[KEYBUFLEN_MAX], mask[KEYBUFLEN_MAX];
    const char *pfx = NULL;

    pfx = check_pfxstr(L, 1, &len);
    if (! key_bystr(pfx, &mlen, &af, addr)) return 0;
    if (! key_bylen(af, mlen, mask)) return 0;
    if (! key_broadcast(addr, mask)) return 0;
    if (! key_tostr(addr, buf)) return 0;

    lua_pushstring(L, buf);
    lua_pushinteger(L, mlen);
    lua_pushinteger(L, af);

    dbg_stack("out(3) ==>");

    return 3;
}

static int
ipt_mask(lua_State *L)
{
    // iptable.mask(af, mlen) <-- [num]
    // Returns mask (as string) for mlen bits given. Nil on errors
    // - mlen < 0 means inverse mask of mlen, so mlen = -8 -> 0.255.255.255
    dbg_stack("inc(.) <--");

    int af = AF_UNSPEC, mlen = -1, isnum = 0;
    char buf[KEYBUFLEN_MAX];
    uint8_t mask[KEYBUFLEN_MAX];

    af = lua_tointegerx(L, 1, &isnum);
    if (! isnum) return 0;
    if (AF_UNKNOWN(af)) return 0;

    mlen = lua_tointegerx(L, 2, &isnum);
    if (! isnum) return 0;
    if (! key_bylen(af, mlen < 0 ? -mlen : mlen, mask)) return 0;
    if (mlen < 0 && ! key_invert(mask)) return 0;
    if (! key_tostr(mask, buf)) return 0;

    lua_pushstring(L, buf);

    dbg_stack("out(1) ==>");

    return 1;
}

static int
iter_hosts(lua_State *L)
{
    // actual iterator used by factory func ipt_iter_hosts
    // [prev.value], which is nil the first time around
    // we ignore prev.value, incr upvalue(1) instead till it equals upvalue(2)
    dbg_stack("inc(.) <--");

    size_t nlen = 0, slen = 0;
    char next[KEYBUFLEN_MAX], stop[KEYBUFLEN_MAX], buf[KEYBUFLEN_MAX];

    if (!check_binkey(L, lua_upvalueindex(1), next, &nlen)) return 0;
    if (!check_binkey(L, lua_upvalueindex(2), stop, &slen)) return 0;
    if (key_cmp(next, stop) == 0) return 0;

    key_tostr(next, buf);                               // return cur val
    lua_pushstring(L, buf);

    key_incr(next);                                     // setup next val
    lua_pushlstring(L, (const char *)next, (size_t)IPT_KEYLEN(next));
    lua_replace(L, lua_upvalueindex(1));

    dbg_stack("out(1) ==>");

    return 1;
}

static int
ipt_iter_hosts(lua_State *L)
{
    // iptable.iter_hosts(pfx) <-- [str, incl] (inclusive is optional)
    // Setup iteration across hosts in a given prefix.
    dbg_stack("inc(.) <--");

    size_t len = 0;
    int af = AF_UNSPEC, mlen = -1, inclusive = 0;
    int fail = 0;  // even on failure, gotta push iterfunc with 2 upvalues
    uint8_t addr[KEYBUFLEN_MAX], mask[KEYBUFLEN_MAX], stop[KEYBUFLEN_MAX];
    const char *pfx = NULL;

    if (lua_gettop(L) == 2 && lua_isboolean(L, 2))
        inclusive = lua_toboolean(L, 2);  // include netw/bcast (or not)

    pfx = check_pfxstr(L, 1, &len);
    if (! key_bystr(pfx, &mlen, &af, addr)) fail = 1;
    if (! key_bystr(pfx, &mlen, &af, stop)) fail = 1;
    if (! key_bylen(af, mlen, mask)) fail = 1;
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

static int
_gc(lua_State *L) {
    // __gc: utterly destroy the table
    table_t *ud = check_table(L, 1);
    tbl_destroy(&ud, L);
    return 0;  // Lua owns the memory for the pointer to-> *ud
}

static int
_newindex(lua_State *L)
{
    // __newindex() -- [tbl_ud pfx val]
    dbg_stack("inc(.) <--");

    void *ud;               // userdata to store (will be ptr->int)
    const char *pfx = NULL;
    size_t len = 0;
    int ref = LUA_NOREF;
    table_t *t = check_table(L, 1);

    pfx = check_pfxstr(L, 2, &len);
    dbg_msg("got pfx %s", pfx);

    if (lua_isnil(L, -1)) {
        dbg_msg("tbl_del on %s", pfx);
        tbl_del(t, pfx, L);
    }
    else {
        ref = luaL_ref(L, LUA_REGISTRYINDEX); // pop top & store in registry
        ud = ud_create(ref);
        if (!tbl_set(t, pfx, ud, L)) {
            ud_delete(L, &ud);
            dbg_msg("unref'd %d", ref);
        } else {
            dbg_msg("stored as ref %d", ref);
        }
    }

    dbg_stack("out(0) ==>");

    return 0;
}

static int
_index(lua_State *L)
{
    // __index() -- [ud pfx] or [ud name]
    // - no mask -> do longest prefix search,
    // - with mask -> do exact lookup of prefix with mask
    // - if pfx lookup fails -> try metatable
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

static int
_len(lua_State *L)
{
    // #ipt -- [ud]  -- return sum of count4 and count6
    dbg_stack("inc(.) <--");

    table_t *t = check_table(L, 1);
    lua_pushinteger(L, t->count4 + t->count6);

    dbg_stack("out(1) ==>");

    return 1;
}

static int
_tostring(lua_State *L)
{
    // as string: iptable{#ipv4=.., #ipv6=..}
    dbg_stack("inc(.) <--");

    table_t *t = check_table(L, 1);
    lua_pushfstring(L, "iptable{#ipv4=%d, #ipv6=%d}", t->count4, t->count6);

    dbg_stack("out(1) ==>");

    return 1;
}

static int
counts(lua_State *L)
{
    // ipt:size() -- [t_ud]  -- return both count4 and count6 (in that order)
    dbg_stack("inc(.) <--");

    table_t *t = check_table(L, 1);
    lua_pushinteger(L, t->count4);         // [t_ud count4]
    lua_pushinteger(L, t->count6);         // [t_ud count4 count6]

    dbg_stack("out(2) ==>");

    return 2;                              // [.., count4, count6]
}

static int
iter_kv(lua_State *L)
{
    // iter_kv() <-- [ud k] (key k is nil if first call)
    // - returns next [k' v']-pair or nil [] to stop iteration
    dbg_stack("inc(.) <--");

    table_t *t = check_table(L, 1);
    struct radix_node *rn = lua_touserdata(L, lua_upvalueindex(1));
    entry_t *e = NULL;
    char saddr[KEYBUFLEN_MAX];

    if (rn == NULL || RDX_ISROOT(rn)) return 0; // we're done

    // push k',v' onto stack
    key_tostr(rn->rn_key, saddr);
    e = (entry_t *)rn;
    lua_pushfstring(L, "%s/%d", saddr, key_tolen(rn->rn_mask)); // [t_ud k k']
    lua_rawgeti(L, LUA_REGISTRYINDEX, *(int *)e->value); // [t_ud k k' v']

    // get next node & save it for next time around
    rn = rdx_next(rn);
    if (rn == NULL && KEY_IS_IP4(e->rn[0].rn_key))
        rn = rdx_first(t->head6);
    lua_pushlightuserdata(L, rn);                       // [t_ud k k' v' lud]
    lua_replace(L, lua_upvalueindex(1));                // [t_ud k k' v']

    dbg_stack("out(2) ==>");

    return 2;                                           // [.., k', v']
}


static int
_pairs(lua_State *L)
{
    // __pairs(ipt) <-- [t_ud]
    dbg_stack("inc(.) <--");

    table_t *t = check_table(L, 1);
    struct radix_node *rn = rdx_first(t->head4);
    if (rn == NULL)
        rn = rdx_first(t->head6);

    if (rn == NULL) return 0;

    lua_pushlightuserdata(L, rn);        // [t_ud lud], rn is 1st node
    lua_pushcclosure(L, iter_kv, 1);     // [t_ud f], rn as upvalue(1)
    lua_rotate(L, 1, 1);                 // [f t_ud]
    lua_pushnil(L);                      // [f t_ud nil]

    dbg_stack("out(3) ==>");

    return 3;                           // [iter_f invariant ctl_var]
}

static int cb_collect(struct radix_node *, void *);
static int
cb_collect(struct radix_node *rn, void *LL)
{
    // collect prefixes into table on top <-- [t_ud, pfx bool* ref]
    // - where bool* may be absent.
    lua_State *L = LL;
    dbg_stack("cb_more()");

    char addr[KEYBUFLEN_MAX];
    int mlen = -1, tlen = 0;

    if (! lua_istable(L, -1)) return 1;
    if (! key_tostr(rn->rn_key, addr)) return 1;
    mlen = key_tolen(rn->rn_mask);

    // working version
    lua_len(L, -1);                                 // get table length
    tlen = lua_tointeger(L, -1) + 1;                // new array index
    lua_pop(L,1);
    lua_pushinteger(L, tlen);
    lua_pushfstring(L, "%s/%d", addr, mlen);        // more specific pfx
    dbg_stack("new k,v 2+");
    lua_settable(L, -3);                            // t[n]=pfx


    dbg_stack("out(0) ==>");

    return 1;
}

static int
more(lua_State *L)
{
    // ipt:more(pfx, inclusive) <-- [t_ud pfx bool]
    // Return array of more specific prefixes in the iptable
    dbg_stack("inc(.) <--");

    size_t len = 0;
    int af = AF_UNSPEC, mlen = -1, inclusive = 0;
    uint8_t addr[KEYBUFLEN_MAX];
    const char *pfx = NULL;

    table_t *t = check_table(L, 1);
    pfx = check_pfxstr(L, 2, &len);
    if (! key_bystr(pfx, &mlen, &af, addr)) return 0; // invalid prefix
    if (af == AF_UNSPEC) return 0;                    // unknown family

    if (lua_gettop(L) == 3 && lua_isboolean(L, 3))
        inclusive = lua_toboolean(L, 3);  // include search prefix (or not)

    lua_newtable(L);                     // collector table on top
    if (! tbl_more(t, pfx, inclusive, cb_collect, L)) return 0;

    // XXX delme: show table length
    lua_len(L, -1);
    dbg_stack("tbl len +");
    lua_pop(L, 1);

    dbg_stack("out(1) ==>");

    return 1;
}

static int
less(lua_State *L)
{
    // ipt:less(pfx, inclusive) <-- [ud pfx bool*]
    // Return array of less specific prefixes in the iptable
    dbg_stack("inc(.) <--");

    size_t len = 0;
    int af = AF_UNSPEC, mlen = -1, inclusive = 0;
    uint8_t addr[KEYBUFLEN_MAX];
    const char *pfx = NULL;

    table_t *t = check_table(L, 1);
    pfx = check_pfxstr(L, 2, &len);
    if (! key_bystr(pfx, &mlen, &af, addr)) return 0; // invalid prefix
    if (af == AF_UNSPEC) return 0;                    // unknown family

    if (lua_gettop(L) == 3 && lua_isboolean(L, 3))
        inclusive = lua_toboolean(L, 3);              // include search prefix (or not)

    lua_newtable(L);                                  // collector table
    if (! tbl_less(t, pfx, inclusive, cb_collect, L)) return 0;

    dbg_stack("out(1) ==>");

    return 1;
}
