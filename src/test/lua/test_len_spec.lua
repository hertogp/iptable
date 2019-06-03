#!/usr/bin/env lua
-------------------------------------------------------------------------------
--         File:  test_index.lua
--        Usage:  ./test_create.lua
--  Description:  unit test file for iptable
-------------------------------------------------------------------------------

package.cpath = "./build/?.so;"..package.cpath

describe("iptable __len: ", function()

  expose("ipt obj: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);
    ipt = iptable.new();
    assert.is_truthy(ipt);

    it(" without mask, does longest prefix", function()
      ipt["10.10.10.10/24"] = 24;
      assert.is_equal(1, #ipt);

      ipt["11.11.11.11/24"] = 42;
      assert.is_equal(2, #ipt);

      ipt["2f::/64"] = 64;
      assert.is_equal(3, #ipt);

      local v4, v6 = ipt:sizes();
      assert.is_equal(2, v4);
      assert.is_equal(1, v6);

      local str = string.format("%s", ipt);
      assert.is_equal("iptable{ipv4->(2), ipv6->(1)}", str);
    end)

    it(" with mask, does exact match", function()
      ipt["10.10.10.0/24"] = 99;  -- same as 10.10.10.10/24
      assert.is_equal(3, #ipt);
    end)

  end)
end)
