// file lua_iptable.c -- Lua bindings for iptable

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


// lua_iptable defines

#define LUA_IPTABLE_ID "iptable"

// size for local buffer var to temporary store keys (str or binary)
#define KEY_BUFLEN     IP6_PFXSTRLEN + 1

// lua functions

int luaopen_iptable(lua_State *);

// helper funtions

table_t *check_table(lua_State *, int);
static int check_key(lua_State *, int, char *, size_t *);
static int *ud_create(int);                        // userdata stored as entry->value
static void ud_delete(void *, void **);            // ud_delete(L, &ud)
static int iter_kv(lua_State *);
static int iter_hosts(lua_State *);

// iptable module functions

static int ipt_new(lua_State *);
static int ipt_tobin(lua_State *);
static int ipt_tostr(lua_State *);
static int ipt_tolen(lua_State *);
static int ipt_network(lua_State *);
static int ipt_broadcast(lua_State *);
static int ipt_iter_hosts(lua_State *);


// (ip)table instance methods

static int get(lua_State *);
static int _gc(lua_State *);
static int _index(lua_State *);
static int _newindex(lua_State *);
static int _len(lua_State *);
static int _tostring(lua_State *);
static int _pairs(lua_State *);
static int counts(lua_State *);


// iptable function array

static const struct luaL_Reg funcs [] = {
    {"new", ipt_new},
    {"tobin", ipt_tobin},
    {"tostr", ipt_tostr},
    {"tolen", ipt_tolen},
    {"network", ipt_network},
    {"broadcast", ipt_broadcast},
    {"hosts", ipt_iter_hosts},
    {NULL, NULL}
};

// iptable methods array

static const struct luaL_Reg meths [] = {
    {"__gc", _gc},
    {"__index", _index},
    {"__newindex", _newindex},
    {"__len", _len},
    {"__tostring", _tostring},
    {"__pairs", _pairs},
    {"get", get},
    {"counts", counts},
    {NULL, NULL}
};

// libopen

int
luaopen_iptable (lua_State *L)
{
    // ['iptable', '<path>/iptable.so' ]
    dbg_stack("stack .");

    // get & register ipt's metatable
    luaL_newmetatable(L, LUA_IPTABLE_ID);  // [.., {} ]
    dbg_stack("new mt +");

    // duplicate the (meta)table
    lua_pushvalue(L, -1);                   // [.., {}, {} ]
    dbg_stack("duplicate +");

    // set prototypical inheritance
    lua_setfield(L, -2, "__index");         // [.., {} ]
    dbg_stack("set as __index");

    // set object methods, no upvalues (0)
    luaL_setfuncs(L, meths, 0);             // [.., {+m's} ]
    dbg_stack("_setfuncs");
    luaL_newlib(L, funcs);                  // [.., {+m'} {+f's} ]
    dbg_stack("_newlib");

    lua_pushinteger(L, AF_INET);
    dbg_stack("value");
    lua_setfield(L, -2, "AF_INET");
    dbg_stack("setfield -2");

    lua_pushinteger(L, AF_INET6);
    dbg_stack("value");
    lua_setfield(L, -2, "AF_INET6");
    dbg_stack("setfield -2");

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
check_key(lua_State *L, int idx, char *buf, size_t *len)
{
    // Write string key @ idx in buffer; returns 1 on success, 0 on failure
    const char *key = NULL;

    if (!lua_isstring(L, idx)) return 0;

    key = lua_tolstring(L, idx, len);
    // dbg_msg("got key %s, len %lu", key, *len);

    if (key == NULL) return 0;
    if (*len < 1 || *len > KEY_BUFLEN-1) return 0;

    memcpy(buf, key, *len);  // handles any embedded 0's in a (binary) key
    buf[*len] = '\0';

    return 1;
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
    // void** -> tbl_destroy(&ud) sets ud=NULL when done clearing it
    void **ud = lua_newuserdata(L, sizeof(void **));
    *ud = tbl_create(ud_delete);             // ud_delete func to free values

    if (*ud == NULL) {
        lua_pushliteral(L, "error creating iptable");
        lua_error(L);
    }

    luaL_getmetatable(L, LUA_IPTABLE_ID); // [ud M]
    lua_setmetatable(L, 1);

    return 1;
}

static int
ipt_tobin(lua_State *L)
{
    // iptable.tobin(strKey) <-- [str]

    int af, mlen;
    size_t len = 0;
    char buf[KEY_BUFLEN];
    uint8_t *addr = NULL;

    dbg_stack("stack .");

    if (!check_key(L, 1, buf, &len)) return 0;

    addr = key_bystr(buf, &mlen, &af);
    if (addr == NULL) return 0;

    lua_pushlstring(L, (const char*)addr, IPT_KEYLEN(addr));
    lua_pushinteger(L, mlen);
    lua_pushinteger(L, af);
    free(addr);

    return 3;
}

static int
ipt_tostr(lua_State *L)
{
    // iptable.tostr(binKey) <-- [key]
    char buf[KEY_BUFLEN];
    char str[KEY_BUFLEN];
    size_t len = 0;

    if (!check_key(L, 1, buf, &len)) return 0;
    if (len != (size_t)IPT_KEYLEN(buf)) return 0; // illegal binary
    if (key_tostr(buf, str) == NULL) return 0;

    lua_pushstring(L, str);

    return 1;
}

static int
ipt_tolen(lua_State *L)
{
    // iptable.masklen(binKey) <-- [key]
    char buf[KEY_BUFLEN];
    size_t len = 0;
    int mlen = -1;

    if (!check_key(L, 1, buf, &len)) return 0;

    mlen = key_tolen(buf);
    lua_pushinteger(L, mlen);

    return 1;
}

static int
ipt_network(lua_State *L)
{
    // iptable.network(strKey) <-- [str]
    dbg_stack("stack .");

    char buf[KEY_BUFLEN];
    uint8_t mask[IPT_KEYBUFLEN];
    size_t len = 0;
    int af = AF_UNSPEC, mlen = -1, rv = 0;
    uint8_t *addr = NULL; //, *mask = NULL;

    if (!check_key(L, 1, buf, &len)) return 0;

    addr = key_bystr(buf, &mlen, &af);
    key_bylen2(af, mlen, mask);

    if (key_network(addr, mask)) {
        key_tostr(addr, buf);
        lua_pushstring(L, buf);
        lua_pushinteger(L, mlen);
        lua_pushinteger(L, af);
        rv = 3;
    }

    if (addr) free(addr);
//     if (mask) free(mask);

    return rv;
}

static int
ipt_broadcast(lua_State *L)
{
    // iptable.broadcast(strKey) <-- [str]
    dbg_stack("stack .");

    int af = AF_UNSPEC, mlen = -1, rv = 0;
    size_t len = 0;
    char buf[KEY_BUFLEN];
    uint8_t *addr = NULL, *mask = NULL;

    if (!check_key(L, 1, buf, &len)) return 0;

    addr = key_bystr(buf, &mlen, &af);
    mask = key_bylen(af, mlen);

    if (key_broadcast(addr, mask)) {
        key_tostr(addr, buf);
        lua_pushstring(L, buf);
        lua_pushinteger(L, mlen);
        lua_pushinteger(L, af);
        dbg_stack("results +");
        rv = 3;
    }

    if (addr) free(addr);
    if (mask) free(mask);

    return rv;
}

static int
iter_hosts(lua_State *L)
{
    // actual iterator used by factory func ipt_iter_hosts
    // [prev.value], which is nil the first time around
    // we ignore prev.value, incr upvalue(1) instead till it equals upvalue(2)
    size_t nlen = 0, slen = 0;
    char next[KEY_BUFLEN], stop[KEY_BUFLEN], buf[KEY_BUFLEN];

    if (!check_key(L, lua_upvalueindex(1), next, &nlen)) return 0;
    if (!check_key(L, lua_upvalueindex(2), stop, &slen)) return 0;

    if (key_cmp(next, stop) == 0) return 0;

    key_tostr(next, buf);                               // return cur val
    lua_pushstring(L, buf);

    key_incr(next);                                     // setup next val
    lua_pushlstring(L, (const char *)next, (size_t)IPT_KEYLEN(next));
    lua_replace(L, lua_upvalueindex(1));

    return 1;
}

static int
ipt_iter_hosts(lua_State *L)
{
    // iptable.iter_hosts(pfx) <-- [str, incl] (inclusive is optional)
    dbg_stack("stack .");

    char buf[KEY_BUFLEN];
    size_t len = 0;
    int af = AF_UNSPEC, mlen = -1, rv = 0, inclusive = 0;
    uint8_t *addr = NULL, *mask = NULL, *stop = NULL;

    if (!check_key(L, 1, buf, &len)) return 0;

    if (lua_gettop(L) == 2 && lua_isboolean(L, 2))
        inclusive = lua_toboolean(L, 2);  // include netw/bcast (or not)

    addr = key_bystr(buf, &mlen, &af);                     // start
    stop = key_bystr(buf, &mlen, &af);                     // sentinel
    mask = key_bylen(af, mlen);

    if (key_network(addr, mask) && key_broadcast(stop, mask)) {
        // setup closure with start, stop, inclusive upvalues
        if (inclusive)                                     // incl net/bcast
            key_incr(stop);
        else if (key_cmp(addr, stop) < 0)                  // not iter host ip
            key_incr(addr);

        lua_pushlstring(L, (const char *)addr, IPT_KEYLEN(addr));
        lua_pushlstring(L, (const char *)stop, IPT_KEYLEN(stop));
        lua_pushcclosure(L, iter_hosts, 2);  // [.., func]
        rv = 1;
    }

    if (addr) free(addr);
    if (mask) free(mask);
    if (stop) free(stop);

    return rv;
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
    dbg_stack("stack .");

    void *ud;               // userdata to store (will be ptr->int)
    char pfx[KEY_BUFLEN];
    size_t len = 0;
    table_t *t = check_table(L, 1);

    if (!check_key(L, 2, pfx, &len)) return 0;

    if (lua_isnil(L, -1))
        tbl_del(t, pfx, L);
    else {
        ud = ud_create(luaL_ref(L, LUA_REGISTRYINDEX));
        if (!tbl_set(t, pfx, ud, L)) ud_delete(L, &ud);
    }

    return 0;
}

static int
get(lua_State *L)
{
    // ipt:get() -- [ud pfx]
    // FIXME: not needed anymore since ipt[addr/mask] does specific match due to
    // the presence of the mask?

    table_t *ud = check_table(L, 1);
    // const char *s = luaL_checkstring(L, 2);
    char *pfx = strdup(luaL_checkstring(L,2));
    entry_t *e = tbl_get(ud, pfx);
    free(pfx);

    if(e)
        lua_rawgeti(L, LUA_REGISTRYINDEX, *(int *)e->value);
    else
        return 0;

    return 1;
}

static int
_index(lua_State *L)
{
    // __index() -- [ud pfx] or [ud name]
    // - no mask -> do longest prefix search,
    // - with mask -> do exact lookup of prefix with mask
    // - if pfx lookup fails -> try metatable

    dbg_stack("__index() .");

    entry_t *e = NULL;
    size_t len = 0;
    char pfx[KEY_BUFLEN];

    table_t *t = check_table(L, 1);

    if (!check_key(L, 2, pfx, &len)) {
        // note: check_key will fail on a really long function/property name
        // which we don't have currently but maybe later ...
        dbg_msg("a %s function/property name", "loooooong");
        if (luaL_getmetafield(L, 1, luaL_checkstring(L,2)) == LUA_TNIL)
            return 0;

    } else {
        e = strchr(pfx, '/') ? tbl_get(t, pfx) : tbl_lpm(t, pfx);
        if(e) {
            lua_rawgeti(L, LUA_REGISTRYINDEX, *(int *)e->value);
            dbg_stack("val by ref +");

        } else {
            // pfx might still be a short(er) function/property name
            if (luaL_getmetafield(L, 1, luaL_checkstring(L,2)) == LUA_TNIL)
                return 0;
            dbg_stack("metatable lookup +");
        }
    }

    return 1;
}

static int
_len(lua_State *L)
{
    // #ipt -- [ud]  -- return sum of count4 and count6
    table_t *t = check_table(L, 1);
    lua_pushinteger(L, t->count4 + t->count6);

    return 1;
}

static int
_tostring(lua_State *L)
{
    // as string: iptable{#ipv4=.., #ipv6=..}
    table_t *t = check_table(L, 1);
    lua_pushfstring(L, "iptable{#ipv4=%d, #ipv6=%d}", t->count4, t->count6);

    return 1;
}

static int
counts(lua_State *L)
{
    // ipt:size() -- [t_ud]  -- return both count4 and count6 (in that order)
    dbg_stack("stack .");

    table_t *t = check_table(L, 1);
    lua_pushinteger(L, t->count4);         // [t_ud count4]
    lua_pushinteger(L, t->count6);         // [t_ud count4 count6]

    return 2;                              // [.., count4, count6]
}

static int
iter_kv(lua_State *L)
{
    // iter_kv() <-- [ud k] (key k is nil if first call)
    // - returns next [k' v']-pair or nil [] to stop iteration
    dbg_stack("stack .");

    table_t *t = check_table(L, 1);
    struct radix_node *rn = lua_touserdata(L, lua_upvalueindex(1));
    entry_t *e = NULL;
    char saddr[KEY_BUFLEN];

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

    return 2;                                           // [.., k', v']
}


static int
_pairs(lua_State *L)
{
    // __pairs(ipt) <-- [t_ud]
    dbg_stack("stack .");

    table_t *ud = check_table(L, 1);
    struct radix_node *rn = rdx_first(ud->head4);
    if (rn == NULL)
        rn = rdx_first(ud->head6);

    if (rn == NULL) return 0;

    lua_pushlightuserdata(L, rn);        // [t_ud lud], rn is 1st node
    lua_pushcclosure(L, iter_kv, 1);     // [t_ud f], rn as upvalue(1)
    lua_rotate(L, 1, 1);                 // [f t_ud]
    lua_pushnil(L);                      // [f t_ud nil]

    return 3;                           // [iter_f invariant ctl_var]
}
