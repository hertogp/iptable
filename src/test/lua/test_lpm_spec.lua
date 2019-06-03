#!/usr/bin/env lua
-------------------------------------------------------------------------------
--         File:  test_index.lua
--        Usage:  ./test_create.lua
--  Description:  unit test file for iptable
-------------------------------------------------------------------------------

package.cpath = "./build/?.so;"..package.cpath

describe("iptable lookup: ", function()

  expose("obj[]: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);
    ipt = iptable.new();
    assert.is_truthy(ipt);
    ipt["10.10.10.0/26"] = 26;
    ipt["10.10.10.0/24"] = 24;  -- omit the /25 mask

    it(" without mask, does longest prefix", function()
      assert.are_equal(26, ipt["10.10.10.1"]);
      assert.are_equal(24, ipt["10.10.10.64"]);
    end)

    it(" with mask, does exact match", function()
      assert.are_equal(24, ipt["10.10.10.32/24"]);
      assert.are_equal(nil, ipt["10.10.10.64/25"]);
      assert.are_equal(nil, ipt["10.10.10.0/25"]);
    end)

  end)
end)
