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

describe("iptable.tostr(): ", function()

  expose("module: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);

    it("host address", function()
      str = iptable.tostr('\x05\x0a\x0a\x0a\x0a');
      assert.are_equal("10.10.10.10", str);
    end)

    it("handles empty string arg", function()
      str = iptable.tostr("");
      assert.are_equal(nil, str);
    end)

    it("handles no arg", function()
      str = iptable.tostr();
      assert.are_equal(nil, str);
    end)

    it("handles nil arg", function()
      str = iptable.tostr(nil);
      assert.are_equal(nil, str);
    end)

    it("handles non-string arg", function()
      str = iptable.tostr(false);
      assert.are_equal(nil, str);

      str = iptable.tostr({});
      assert.are_equal(nil, str);
    end)

    it("handles mangled binaries", function()
      -- LEN-byte (1st one) should equal total length of the binary string
      str = iptable.tostr('\x04\x0a\x0a\x0a\x0a');
      assert.are_equal(nil, str);
    end)

  end)
end)
