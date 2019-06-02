#!/usr/bin/env lua
--
--------------------------------------------------------------------------------
--         File:  test_index.lua
--
--        Usage:  ./test_create.lua
--
--  Description:  
--
--      Options:  ---
-- Requirements:  ---
--         Bugs:  ---
--        Notes:  ---
--       Author:  YOUR NAME (), <>
-- Organization:  
--      Version:  1.0
--      Created:  01-06-19
--     Revision:  ---
--------------------------------------------------------------------------------
--

package.cpath = "./build/?.so;"..package.cpath

iptable = require("iptable");
print(string.rep("-", 20), "iptable.new\n");
ipt = iptable.new();

print("\n" ..string.rep("-", 20), "print(ipt[..])\n");
print("ipt[10.10.10.10] lpm (no mask) ->", ipt["10.10.10.10"]);

print("\n"..string.rep("-", 20), "ipt[10.10.10.10] = 42\n");
print("automask of /32");
ipt["10.10.10.10"] = 42;


print("\n"..string.rep("-", 20), "ipt[10.10.10.10/24] = 22\n");
print("explicit mask /24");
ipt["10.10.10.10/24"] = 42;


print("Done!");
