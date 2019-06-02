// file lua_iptable.c -- Lua bindings for iptable

#include <malloc.h>
#include <sys/types.h>

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#include "radix.h"
#include "iptable.h"

// tmp debug function stackDump(L, "txt")
// --------------------------------------------------------------
#include <stdio.h>
#include <string.h>

// lua_iptable defines

#define LUA_USERDATUM_ID "iptable"

static void
stackDump (lua_State *L, const char *title)
{
    // print out the scalar value or type of args on the stack 
    int i;
    int top = lua_gettop(L); /* depth of the stack */
    printf("%20s : [", title);
    for (i = 1; i <= top; i++) { /* repeat for each level */
        int t = lua_type(L, i);
        switch (t)
        {
            case LUA_TNIL: { printf("nil"); break; }
            case LUA_TBOOLEAN: { printf(lua_toboolean(L, i) ? "true" : "false"); break; }
            case LUA_TLIGHTUSERDATA: { printf("lud@%p", lua_touserdata(L, i)); break; }
            case LUA_TNUMBER: { printf("%g", lua_tonumber(L, i)); break; }
            case LUA_TSTRING: { printf("'%s'", lua_tostring(L, i)); break; }
            case LUA_TTABLE: { printf("{}"); break; }
            case LUA_TFUNCTION: { printf("f@%p", lua_touserdata(L, i)); break; }
            case LUA_TUSERDATA: { printf("ud(%p)", lua_touserdata(L, i)); break; }
            case LUA_TTHREAD: { printf("Thrd(%p)", lua_touserdata(L, i)); break; }
            default: { printf("%s", lua_typename(L, t)); break; }
        }
        if (i<top) printf(" "); /* put a separator */
    }
    printf("]\n"); /* end the listing */
}

// --  end stackDump

// - lua functions
int luaopen_iptable(lua_State *);

// - AUXILIARY funtions

table_t *checkUserDatum(lua_State *, int);

// - USERDATA functions

static int new(lua_State *);
static int destroy(lua_State *);
static int set(lua_State *);
//static int get(lua_State *);
static int lpm(lua_State *);


// USERDATA function array
static const struct luaL_Reg funcs [] = {
    {"new", new},
    {"destroy", destroy},
    {NULL, NULL}
};

// USERDATA methods array
static const struct luaL_Reg meths [] = {
    {"__gc", destroy},
    {"__index", lpm},
    {"__newindex", set},
    {"set", set},
    {"destroy", destroy},
    {NULL, NULL}
};

//  LUA_USERDATUM_ID
int luaopen_iptable (lua_State *L)
{
                                            // []
    luaL_newmetatable(L, LUA_USERDATUM_ID);  // [ {} ]
    lua_pushvalue(L, -1);                   // [ {}, {} ]
    lua_setfield(L, -2, "__index");         // [ {} ]
    luaL_setfuncs(L, meths, 0);             // [ {+meths} ]
    luaL_newlib(L, funcs);                  // [ {+meths} {+funcs} ]

    return 1;
}

table_t *
checkUserDatum (lua_State *L, int index)
{
    void **ud = luaL_checkudata(L, index, LUA_USERDATUM_ID);
    luaL_argcheck(L, ud != NULL, index, "`iptable' expected");
    return (table_t *)*ud;
}

static int
new (lua_State *L)
{
    printf("ipt->new()\n");
        // []
    void **ud = lua_newuserdata(L, sizeof(void **));
    *ud = tbl_create();
    printf("- **ud @ %p\n", (void *)ud);
    printf("-  *ud @ %p\n", (void *)*ud);
    stackDump(L, "0");

    if (*ud == NULL) {
        lua_pushliteral(L, "error creating iptable");
        lua_error(L);
    }

    luaL_getmetatable(L, LUA_USERDATUM_ID); // [ud M]
    stackDump(L, "1");

    lua_setmetatable(L, 1);
    stackDump(L, "2");
    return 1;
}

static int
destroy(lua_State *L) {
    // __gc: utterly destroy the table
    table_t *ud = checkUserDatum(L, 1);
    printf("__gc -> destroy(ud @ %p)\n", (void *)ud);
    stackDump(L, "0");
    tbl_destroy(&ud);
    printf("ud ptr is now %p\n", (void *)ud);
    return 0;  // Lua owns the memory for the pointer -> *ud
}

static int
lpm(lua_State *L)
{
    // __index: longest prefix match -- [ud pfx|name]
    printf("__index -> lpm() - ");
    stackDump(L, "0");
    table_t *ud = checkUserDatum(L, 1);
    entry_t *e = NULL;
    const char *s = luaL_checkstring(L, 2);
    char *pfx = strdup(s);

    if((e = tbl_lpm(ud, pfx)))
        // found a pfx
        lua_rawgeti(L, LUA_REGISTRYINDEX, *(int *)e->value);
    else {
        // else, not found or not a pfx -> might be func name
        lua_getmetatable(L, 1);   // [ud name M]
        stackDump(L, "M");
        lua_rotate(L, 2, 1);      // [ud M name]
        stackDump(L, "M");
        lua_gettable(L, -2);      // [ud M func]
        stackDump(L, "return method");
    }
    free(pfx);
    return 1;
}

// methods

static int
set(lua_State *L)
{
    // __newindex:  --> [ud pfx val]
    printf("ipt->set()\n");
    stackDump(L, "0");
    table_t *ud = checkUserDatum(L, 1);
    const char *s = luaL_checkstring(L, 2);
    char *pfx = strdup(s);
    printf("prefix : %s\n",pfx);
    printf("ud @ %p\n", (void *)ud);
    int newref = luaL_ref(L, LUA_REGISTRYINDEX);
    printf("newref : %d\n", newref);
    luaL_unref(L, LUA_REGISTRYINDEX, newref);
    free(pfx);

    return 0;
}

/*
static int
get(lua_State *L);
{
    // ipt:get() - specific prefix -- [ud pfx]
    printf("ipt->get()\n");
    stackDump(L, "0");
    table_t *ud = checkUserDatum(L, 1);
    const char *s = lua_checkstring(L, 2);
    entry_t *e = tbl_get(ud, s);
    if(e)
        lua_rawgeti(L, LUA_REGISTRYINDEX, *e->value);
    else
        lua_pushnil(L);

    return 1;
}
*/
