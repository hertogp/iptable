#!/usr/bin/env lua
-------------------------------------------------------------------------------
--         File:  test_index.lua
--        Usage:  ./test_create.lua
--  Description:  unit test file for iptable
-------------------------------------------------------------------------------

package.cpath = "./build/?.so;"..package.cpath

describe("iptable object interface", function()

  expose("of iptable instance:", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);
    ipt = iptable.new();
    assert.is_truthy(ipt);

    it("new table must be empty", function()
      pending("--> implement ipt.size(v4, v6) first");
      assert.are_equal(0, ipt.size());
    end)

    it("assignment", function()
      ipt["10.10.10.0/24"] = 42;
      assert.are_equal(42, ipt["10.10.10.0/24"]);
      assert.are_equal(42, ipt["10.10.10.10/24"]);
      assert.are_equal(42, ipt["10.10.10.10"]);
    end)

    it("assignment uses exact match", function()
      ipt["10.10.10.0/24"] = 99;
      assert.are_equal(99, ipt["10.10.10.129/24"]);
      assert.are_equal(99, ipt["10.10.10.129"]);
      assert.are_equal(99, ipt["10.10.10.255"]);
    end)

    it("more specific", function()
      ipt["10.10.10.0/25"] = 99;
      assert.are_equal(99, ipt["10.10.10.10/25"]);
      assert.are_equal(99, ipt["10.10.10.10"]);
    end)

    it("more specific", function()
      ipt["10.10.10.0/24"] = 11;
      assert.are_equal(11, ipt["10.10.10.129/24"]);
    end)

    it("assigning nil deletes entry", function()
      ipt["10.10.10.0/24"] = nil;
      assert.are_equal(nil, ipt["10.10.10.129/24"]);
    end)

  end)
end)
