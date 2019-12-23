#!/usr/bin/env lua
-------------------------------------------------------------------------------
--  Description:  unit test file for iptable
-------------------------------------------------------------------------------

package.cpath = "./build/?.so;"

function bin2str(buf)
  local s = ""
  local len = buf:byte(1)
  for i=1, len, 1 do
    s = s ..string.format("%02x", buf:byte(i));
    if (i < len) then s = s .. ":"; end
  end
  return s;
end

describe("require iptable: ", function()
  expose("iptable", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);

    it("should yield a module", function()
      iptable = require("iptable");
      assert.is_truthy(iptable);
    end)
  end)
end)

