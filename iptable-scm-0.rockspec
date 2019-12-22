rockspec_format = "3.0"
package = "iptable"
version = "scm-0"

description = {
   summary = "A Lua longest prefix matching table for ipv4 and ipv6.",

   detailed = [[
     iptable provides an ip lookup table (longest prefix match when indexed
     with host addresses, exact match when indexed with a prefix) and some
     auxiliary functions for working with ipv4 and ipv6 addresses.  The library
     wraps the radix code from freeBSD, which implements a path compressed 
     radix trie.
   ]],

   homepage = "https://github.com/hertogp/iptable.git",
   license = "BSD-2",
   issues_url = "https://github.com/hertogp/iptable.git/issues",
   maintainer="git.hertogp@gmail.com",

   labels={
     "network", "ip", "lookup", "longest prefix match", "radix", "trie"
   },
}

dependencies={
  "lua>=5.3"
}

supported_platforms={
  "linux"
}

source = {
   url = "git+https://github.com/hertogp/iptable.git",
   branch="master",
}

build = {
  type = "builtin",
  dependencies = {
    "lua >= 5.3",
  },

  copy_directories = {
    "doc"
  },

  modules = {
    iptable = {
      sources = {
        "src/lua_iptable.c",
        "src/iptable.c",
        "src/radix.c",
      },
      incdirs = { "src" },
    }
  },
}

test = {
  type = "busted",
}
