#!/usr/bin/env lua
-------------------------------------------------------------------------------
--  Description:  unit test file for iptable
-------------------------------------------------------------------------------

package.cpath = "./build/?.so;"

describe("iptable.invert(pfx)", function()

  expose("module: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);

    it("inverts ipv4", function()
      assert.equal("255.255.255.255", iptable.invert("0.0.0.0"));
      assert.equal("0.0.0.0", iptable.invert("255.255.255.255"))
    end)
  end)
end)


