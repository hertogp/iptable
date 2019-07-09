#!/usr/bin/env lua
-------------------------------------------------------------------------------
--         File:  test_instance_methods.lua
--
--        Usage:  busted src/test/lua/test_instance_methods.lua
--
--  Description:  
--
-------------------------------------------------------------------------------

package.cpath = "./build/?.so;"

-- helpers

F = string.format

-- tests

describe("ipt:more(pfx): ", function()

  expose("instance ipt: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);
    ipt = iptable.new();
    assert.is_truthy(ipt);

    ipt["1.2.3.0/24"] = 1
    ipt["1.2.3.0/25"] = 2
    ipt["1.2.3.128/25"] = 4
    ipt["1.2.3.128/26"] = 8
    ipt["1.2.3.192/26"] = 16
    ipt["1.2.3.128/27"] = 32
    ipt["1.2.3.128/28"] = 64
    ipt["1.2.3.144/28"] = 128


    it("finds prefixes that are able to merge", function()
      print("originally:\n")
      for k,v in pairs(ipt) do print(k,v) end
      print("start folding, 1st pass")
      for s, l, u in ipt:merge(iptable.AF_INET) do
        ipt[s] = ipt[l] + ipt[u] + (ipt[s] or 0)
        ipt[l] = nil; ipt[u] = nil
      end
      print("after 1st pass:")
      for k,v in pairs(ipt) do print(k,v) end
    end)
  end)
end)
