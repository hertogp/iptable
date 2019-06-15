rockspec_format = "3.0"
package = "iptable"
version = "1.0.1-1"

description = {
   summary = "A Lua longest prefix matching table for ipv4 and ipv6.",
   detailed = [[
     iptable provides an ip lookup table (longest prefix match when indexed
     with host addresses, exact match when indexed with a prefix) and some
     auxiliary functions for working with ipv4 and ipv6 addresses.  The library
     wraps the radix code from freeBSD, which implements a level/path
     compressed trie.
   ]],
   homepage = "https://github.com/hertogp/iptable.git",
   license = "BSD-2",
   issues_url = "https://github.com/hertogp/iptable.git/issues",
   maintainer="git.padh@gmail.com",
   labels={"network", "ip", "lookup", "longest prefix match"},
}
dependencies={"lua>=5.3"}
supported_platforms={"linux"}

source = {
   url = "https://github.com/hertogp/iptable.git",
   -- tag = "1", -- version's tag
   branch="master",
}

build = {
  type = "make",
  dependencies = {
    "lua >= 5.3",
  },

  -- luarocks passes these flags as cli-args to make thus overriding the
  -- the ones in the Makefile (unless 'override' is used in the Makefile).

  build_variables = {             --  defaults on Ubuntu:
    CFLAGS="$(CFLAGS)",           --> -O2 -fPIC
    LIBFLAG="$(LIBFLAG)",         --> -shared
    LUA_LIBDIR="$(LUA_LIBDIR)",   --> /usr/local/lib
    LUA_BINDIR="$(LUA_BINDIR)",   --> /usr/local/bin
    LUA_INCDIR="$(LUA_INCDIR)",   --> /usr/local/include
    LUA="$(LUA)",
  },

  install_variables = {         -- local => ~/.luarocks/lib/luarocks/rocks-5.3
                                -- sudo  =>  /usr/local/lib/luarocks/rocks-5.3
    INST_PREFIX="$(PREFIX)",       --> (local|sudo)/iptable/(version)/
    INST_BINDIR="$(BINDIR)",       --> (local|sudo)/iptable/(version)/bin
    INST_LIBDIR="$(LIBDIR)",       --> (local|sudo)/iptable/(version)/lib
    INST_LUADIR="$(LUADIR)",       --> (local|sudo)/iptable/(version)/lua
    INST_CONFDIR="$(CONFDIR)",     --> (local|sudo)/iptable/(version)conf
  },
}
