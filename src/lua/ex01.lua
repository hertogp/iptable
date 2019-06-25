#!/usr/bin/env lua
-------------------------------------------------------------------------------
--         File:  ex01.lua
--
--        Usage:  ./ex01.lua
--
--  Description:  creates radix tree image using graphviz: example 01
--
--      Options:  ---
-- Requirements:  ---
--         Bugs:  ---
--        Notes:  ---
--       Author:  YOUR NAME (), <>
-- Organization:  
--      Version:  1.0
--      Created:  25-06-19
--     Revision:  ---
-------------------------------------------------------------------------------
--

iptable = require("iptable")
dotify = require("ipt2dot")

local iptable = require("iptable")
local ipt = iptable.new()
ipt["1.1.1.0/24"] = 24

ipt["1.1.1.0/25"] = 25
ipt["1.1.1.128/25"] = 25

ipt["1.1.1.0/26"] = 25
ipt["1.1.1.64/26"] = 25
ipt["1.1.1.128/26"] = 25
ipt["1.1.1.192/26"] = 25

ipt["3.1.1.0/24"] = 24
ipt["3.1.1.0/25"] = 24
ipt["3.1.1.128/25"] = 24

local mylines = dotify(ipt, iptable.AF_INET)
print(table.concat(mylines, "\n"))
