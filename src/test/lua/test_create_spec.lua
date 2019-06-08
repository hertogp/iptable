#!/usr/bin/env lua
--
-------------------------------------------------------------------------------
--         File:  test_create.lua
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
-------------------------------------------------------------------------------
--

package.cpath = "./build/?.so;"..package.cpath

describe("require iptable: ", function()
  expose("iptable", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);

    it("requiring iptable", function()
      iptable = require("iptable");
      assert.is_truthy(iptable);
    end)

    it("create an iptable", function()
      ipt = iptable.new()
      assert.is_truthy(ipt);
    end)

    it("iptable constants", function()
      ipt = iptable.new();

      for k,v in pairs(iptable) do print(k,v) end

      assert.is_equal(2, iptable.AF_INET);
      assert.is_equal(10, iptable.AF_INET6);

    end)


  end)
end)

