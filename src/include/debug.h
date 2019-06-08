/* file debug.h
 *
 * - <dbg_<helper>'s
 */

#ifdef DEBUG
#include <stdio.h>

// helper for dbg_stack()

static void
stack_dump(lua_State *, const char *, const char *, int, const char*);

static void
stack_dump(lua_State *L, const char *msg, const char *s, int l, const char *f)
{
    // print out the scalar value or type of args on the stack 
    int i, width;
    int top = lua_gettop(L); // depth of the stack
    width = fprintf(stderr, "%s:%d:%s() ", s, l, f);
    width = width < 63 ? 63 - width : 20;
    fprintf(stderr, "%*s : [", width, msg);
    for (i = 1; i <= top; i++) { // repeat for each level
        switch (lua_type(L, i))
        {
            case LUA_TNIL:
              {
                fprintf(stderr, "nil");
                break;
              }
            case LUA_TBOOLEAN:
              {
                fprintf(stderr, lua_toboolean(L, i) ? "true" : "false");
                break;
              }
            case LUA_TLIGHTUSERDATA:
              {
                fprintf(stderr, "lud@%p", lua_touserdata(L, i));
                break;
              }
            case LUA_TNUMBER:
              {
                fprintf(stderr, "%g", lua_tonumber(L, i));
                break;
              }
            case LUA_TSTRING:
              {
                fprintf(stderr, "'%s'", lua_tostring(L, i));
                break;
              }
            case LUA_TTABLE:
              {
                fprintf(stderr, "{}");
                break;
              }
            case LUA_TFUNCTION:
              {
                fprintf(stderr, "f@%p", lua_touserdata(L, i));
                break;
              }
            case LUA_TUSERDATA:
              {
                fprintf(stderr, "ud%p", lua_touserdata(L, i));
                break;
              }
            case LUA_TTHREAD:
              {
                fprintf(stderr, "T%p", lua_touserdata(L, i));
                break;
              }
            default:
              {
                fprintf(stderr, "%s", lua_typename(L, i));
                break;
              }
        }
        if (i<top) fprintf(stderr, " "); // put a separator
    }
    fprintf(stderr, "]\n"); // end the listing

} // --  end stackDump

#define DBG(stmt) do {stmt;} while (0)
#define dbg_stack(m) stack_dump(L, m, __FILE__, __LINE__, __func__)
#define dbg_msg(fmt, ...) \
  do { if (DEBUG) fprintf(stderr, "%s:%d:%s() " fmt "\n", \
    __FILE__, __LINE__, __func__, __VA_ARGS__); } while(0)

#else

#define dbg_msg(fmt, ...)
#define dbg_stack(...)

#endif // DEBUG
