#!/usr/bin/env lua
-------------------------------------------------------------------------------
--  Description:  unit test file for iptable
-------------------------------------------------------------------------------

package.cpath = "./build/?.so;"

-- helpers

F = string.format

-- tests

describe("ipt:more(pfx): ", function()

  expose("instance ipt: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);

    it("finds single summary at the extremes", function()
      local start = "0.0.0.0"
      local stop = "255.255.255.255"
      local last
      for p in iptable.interval(start, stop) do
        last = p
      end
      assert.are_equal("0.0.0.0/0", last);
    end)


  end)
end)

