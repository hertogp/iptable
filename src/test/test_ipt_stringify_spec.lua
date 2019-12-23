#!/usr/bin/env lua
-------------------------------------------------------------------------------
--  Description:  unit test file for iptable
-------------------------------------------------------------------------------

package.cpath = "./build/?.so;"

F = string.format

describe("iptable tostring: ", function()

  expose("ipt obj: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);
    ipt = iptable.new();
    assert.is_truthy(ipt);

    it("shows both ipv4 and ipv6 counts", function()
      ipt["1.1.1.1"] = 1;
      ipt["2.2.2.2"] = 2;
      ipt["3.3.3.3"] = 2;
      ipt["2f::"] = 1;
      ipt["2f::/16"] = 2;
      local str = string.format("%s", ipt);
      assert.is_equal("iptable{#ipv4=3, #ipv6=2}", str);
    end)
  end)
end)


