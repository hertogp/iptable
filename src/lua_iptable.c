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

// userdata functions

int *ud_create(int);               // userdata stored as entry->value
void ud_delete(void *, void **);   // ud_delete(L, &ud)

int *ud_create(int ref)
{
  // for storing LUA_REGISTRYINDEX ref's in the radix tree
  int *p = calloc(1, sizeof(int));
  *p = ref;
  return p;
}

void
ud_delete(void *L, void **dta)
{
  // unref the userdata and free associated ref memory
  if (*dta) {
    luaL_unref((lua_State *)L, LUA_REGISTRYINDEX, *(int *)*dta);
    free(*dta);
  }
  *dta = NULL;
}


// - lua functions

int luaopen_iptable(lua_State *);

// - AUXILIARY funtions

table_t *checkUserDatum(lua_State *, int);
static int iter_kv(lua_State *);

// - iptable module functions

static int ipt_new(lua_State *);
static int ipt_tobin(lua_State *);

// - (ip)table instance methods

static int get(lua_State *);
static int _gc(lua_State *);
static int _index(lua_State *);
static int _newindex(lua_State *);
static int _len(lua_State *);
static int _tostring(lua_State *);
static int _pairs(lua_State *);
static int counts(lua_State *);


// - iptable function array
static const struct luaL_Reg funcs [] = {
    {"new", ipt_new},
    {"tobin", ipt_tobin},
    {NULL, NULL}
};

// - iptable methods array

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

int luaopen_iptable (lua_State *L)
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
    luaL_setfuncs(L, meths, 0);             // [.., {+meths} ]
    dbg_stack("_setfuncs");
    luaL_newlib(L, funcs);                  // [.., {+meths} {+funcs} ]
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
checkUserDatum (lua_State *L, int index)
{
    void **ud = luaL_checkudata(L, index, LUA_IPTABLE_ID);
    luaL_argcheck(L, ud != NULL, index, "`iptable' expected");
    return (table_t *)*ud;
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
  // str_tokey() <-- [str]
  dbg_stack("stack .");

  int af, mlen;
  char *buf = strdup(luaL_checkstring(L,1)); // modifiable copy
  uint8_t *addr = key_bystr(buf, &mlen, &af);
  free(buf);

  if (addr == NULL) return 0;

  lua_pushlstring(L, (const char *)addr, IPT_KEYLEN(addr));
  free(addr);  // Lua makes its own copy
  lua_pushinteger(L, mlen);
  lua_pushinteger(L, af);
  dbg_stack("results +");

  return 3;
}

// iptable instance methods

static int
_gc(lua_State *L) {
    // __gc: utterly destroy the table
    table_t *ud = checkUserDatum(L, 1);
    tbl_destroy(&ud, L);
    return 0;  // Lua owns the memory for the pointer to-> *ud
}

static int
_newindex(lua_State *L)
{
    // __newindex() -- [ud pfx val]

    table_t *ud = checkUserDatum(L, 1);
    int ref = LUA_NOREF;
    char *pfx = strdup(luaL_checkstring(L,2)); // modifiable copy

    if (lua_isnil(L, -1))
       tbl_del(ud, pfx, L);
     else {
       ref = luaL_ref(L, LUA_REGISTRYINDEX);
       tbl_set(ud, pfx, ud_create(ref), L);
     }
    free(pfx);

    return 0;
}

static int
get(lua_State *L)
{
  // ipt:get() -- [ud pfx]
  // FIXME: not needed anymore since ipt[addr/mask] does specific match due to
  // the presence of the mask?

  table_t *ud = checkUserDatum(L, 1);
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

    dbg_stack("__index() .");
    table_t *ud = checkUserDatum(L, 1);
    entry_t *e = NULL;
    char *pfx;
    const char *s = luaL_checkstring(L, 2);

    pfx = strdup(s);              // get modifiable copy
    e = strchr(s, '/') ? tbl_get(ud, pfx) : tbl_lpm(ud, pfx);
    free(pfx);

    if(e) {
        lua_rawgeti(L, LUA_REGISTRYINDEX, *(int *)e->value);
        dbg_stack("val by ref +");
    } else {
        // else, not found or not a pfx -> might be func name
        // NOTE: if checkstring(L,2) == NULL then getmetafield -> LUA_TNIL
        if (luaL_getmetafield(L, 1, luaL_checkstring(L,2)) == LUA_TNIL)
           return 0;
        dbg_stack("metatable lookup +");

        /* lua_getmetatable(L, 1);   // [ud name M] */
        /* dbg_stack("metatable +"); */
        /* lua_rotate(L, 2, 1);      // [ud M name] */
        /* dbg_stack("swap top ."); */
        /* lua_gettable(L, -2);      // [ud M func] or [ud M nil] */
        /* dbg_stack("mt value -+"); */
    }

    return 1;
}

static int
_len(lua_State *L)
{
    // #ipt -- [ud]  -- return sum of count4 and count6
  table_t *ud = checkUserDatum(L, 1);
  lua_pushinteger(L, ud->count4 + ud->count6);

  return 1;
}

static int
_tostring(lua_State *L)
{
    // as string: iptable{#ipv4=.., #ipv6=..}
  table_t *ud = checkUserDatum(L, 1);
  lua_pushfstring(L, "iptable{#ipv4=%d, #ipv6=%d}", ud->count4, ud->count6);

  return 1;
}

static int
counts(lua_State *L)
{
  // ipt:size() -- [ud]  -- return both count4 and count6 (in that order)
  table_t *ud = checkUserDatum(L, 1);
  dbg_stack("stack .");

  lua_pushinteger(L, ud->count4);         // [ud count4]
  dbg_stack("count4 +");

  lua_pushinteger(L, ud->count6);         // [ud count4 count6]
  dbg_stack("count6 +");

  return 2;                               // [.., count4, count6]
}

static int
iter_kv(lua_State *L)
{
  // iter_kv() <-- [ud k] (key k is nil if first call)
  // - returns next [k v]-pair or nil to stop iteration
  dbg_stack("stack .");

  table_t *ud = checkUserDatum(L, 1);
  struct radix_node *rn = lua_touserdata(L, lua_upvalueindex(1));
  entry_t *e = NULL;
  char saddr[IP6_PFXSTRLEN];

  if (rn == NULL || RDX_ISROOT(rn)) return 0; // we're done

  // push k,v onto stack
  key_tostr(rn->rn_key, saddr);
  e = (entry_t *)rn;

  lua_pushfstring(L, "%s/%d", saddr, key_tolen(rn->rn_mask)); // [ud k k']
  dbg_stack("key +");

  lua_rawgeti(L, LUA_REGISTRYINDEX, *(int *)e->value); // [ud k k' v']
  dbg_stack("value +");

  // get next node & save it for next time around
  rn = rdx_next(rn);
  if (rn == NULL && KEY_IS_IP4(e->rn[0].rn_key))
    rn = rdx_first(ud->head6);

  lua_pushlightuserdata(L, rn);                       // [ud k k' v' lud]
  dbg_stack("next radix node +");

  lua_replace(L, lua_upvalueindex(1));                // [ud k k' v']
  dbg_stack("set upvalue(1) -");

  return 2;                                           // [.., k', v']
}


static int
_pairs(lua_State *L)
{
  // __pairs(ipt('ipv4')) <-- [ud]
  // factory function for iterator (closure) function
  dbg_stack("stack .");

  table_t *ud = checkUserDatum(L, 1);
  struct radix_node *rn = rdx_first(ud->head4);
  if (rn == NULL)
    rn = rdx_first(ud->head6);

  if (rn == NULL) return 0;
  // save rn as 1st node
  lua_pushlightuserdata(L, rn);        // [ud lud], rn is 1st node
  dbg_stack("1st leaf +");

  lua_pushcclosure(L, iter_kv, 1);     // [ud f], rn as upvalue(1)
  dbg_stack("iter_f (1 arg) +-");

  lua_rotate(L, 1, 1);                 // [f ud]
  dbg_stack("swap .");

  lua_pushnil(L);                      // [f ud nil]
  dbg_stack("ctl var +");

  return 3;                           // [iter_f invariant ctl_var]
}
