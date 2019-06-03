#!/usr/bin/env lua
-------------------------------------------------------------------------------
--         File:  test_index.lua
--        Usage:  ./test_create.lua
--  Description:  unit test file for iptable
-------------------------------------------------------------------------------

package.cpath = "./build/?.so;"..package.cpath

describe("iptable __pairs: ", function()

  expose("instance: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);
    ipt = iptable.new();
    assert.is_truthy(ipt);

    it(" iterate ipv4 k,v-pairs", function()
      ipt["10.10.10.10/24"] = 24;
      ipt["11.11.11.11/24"] = 42;

      local cnt = 0;
      t = {}
      for k, v in pairs(ipt) do
        cnt = cnt + 1;
        t[k] = v;
      end
      assert.is_equal(2, cnt);
      assert.is_equal(24, t["10.10.10.0/24"]);
      assert.is_equal(42, t["11.11.11.0/24"]);

    end)

    it(" iterate ipv6 k,v-pairs", function()
      ipt["10.10.10.10/24"] = nil; -- delete entries
      ipt["11.11.11.11/24"] = nil;
      ipt["2f::/128"] = 128;       -- only two ipv6 entries
      ipt["4b:aa::/64"] = 64;

      local cnt = 0;
      t = {}
      for k, v in pairs(ipt) do
        cnt = cnt + 1;
        t[k] = v;
      end
      assert.is_equal(2, cnt);
      assert.is_equal(128, t["2f::/128"]);
      assert.is_equal(64, t["4b:aa::/64"]);
    end)

    it(" iterate ipv4 & ipv6 k,v-pairs", function()
      ipt["10.10.10.10/24"] = 24; -- delete entries
      ipt["11.11.11.11/24"] = 42;
      ipt["2f::/128"] = 128;       -- only two ipv6 entries
      ipt["4b:aa::/64"] = 64;

      local cnt = 0;
      t = {}
      for k, v in pairs(ipt) do
        cnt = cnt + 1;
        t[k] = v;
      end
      assert.is_equal(4, cnt);
      assert.is_equal(24, t["10.10.10.0/24"]);
      assert.is_equal(42, t["11.11.11.0/24"]);
      assert.is_equal(128, t["2f::/128"]);
      assert.is_equal(64, t["4b:aa::/64"]);
    end)
  end)
end)
