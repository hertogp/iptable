#!/usr/bin/env lua
-------------------------------------------------------------------------------
--         File:  test_iptable_tobin_spec.lua
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

describe("iptable.tobin(): ", function()
  expose("ipt: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);

    it("returns mlen=-1 when no mask is given", function()
      addr, mlen, af = iptable.tobin("10.10.10.10");
      assert.are_equal(iptable.AF_INET, af);
      assert.are_equal(-1, mlen);
      assert.are_equal(5, #addr);
    end)

    it("returns 32 in case of an ipv4 maximum mask", function()
      addr, mlen, af = iptable.tobin("10.10.10.10/32");
      assert.are_equal(iptable.AF_INET, af);
      assert.are_equal(32, mlen);
      assert.are_equal("05:0a:0a:0a:0a", bin2str(addr));
    end)

    it("correctly return mlen=0 for a zero mask (/0)", function()
      addr, mlen, af = iptable.tobin("10.11.12.13/0");
      assert.are_equal(iptable.AF_INET, af);
      assert.are_equal(0, mlen);
      assert.are_equal("05:0a:0b:0c:0d", bin2str(addr));
    end)

    it("yields nil values for a bad mask (<0)", function()
      addr, mlen, af = iptable.tobin("10.10.10.10/-1");
      assert.are_equal(nil, af);
      assert.are_equal(nil, mlen);
      assert.are_equal(nil, addr);
    end)

    it("yields nil values for a bad mask (>max)", function()
      addr, mlen, af = iptable.tobin("10.10.10.10/33");
      assert.are_equal(nil, af);
      assert.are_equal(nil, mlen);
      assert.are_equal(nil, addr);
    end)

    it("yields mlen=-1 to signal absence of /mask in prefix string", function()
      addr, mlen, af = iptable.tobin("2f:aa:bb::");
      assert.are_equal(iptable.AF_INET6, af);
      assert.are_equal(-1, mlen);  -- -1 means no mask
      assert.are_equal(17, #addr);
    end)

    it("max ipv6 mask -> mlen=128", function()
      addr, mlen, af = iptable.tobin("2f:aa:bb::/128");
      assert.are_equal(iptable.AF_INET6, af);
      assert.are_equal(128, mlen);
      assert.are_equal("11:00:2f:00:aa:00:bb:00:00:00:00:00:00:00:00:00:00", bin2str(addr));
    end)

    it("zero mask (/0) -> mlen=0", function()
      addr, mlen, af = iptable.tobin("003f:cc:dd:ee::/0");
      assert.are_equal(iptable.AF_INET6, af);
      assert.are_equal(0, mlen);
      assert.are_equal("11:00:3f:00:cc:00:dd:00:ee:00:00:00:00:00:00:00:00", bin2str(addr));
    end)

    it("bad mask (<0) -> yields nil values", function()
      addr, mlen, af = iptable.tobin("2f:aa:bb::/-1");
      assert.are_equal(nil, af);
      assert.are_equal(nil, mlen);
      assert.are_equal(nil, addr);
    end)

    it("bad mask (>max) -> yields nil values", function()
      addr, mlen, af = iptable.tobin("2f:aa:bb::/129");
      assert.are_equal(nil, af);
      assert.are_equal(nil, mlen);
      assert.are_equal(nil, addr);
    end)

    it("handles empty string arg", function()
      addr, mlen, af = iptable.tobin("");
      assert.are_equal(nil, addr);
    end)

    it("handles nil arg", function()
      addr, mlen, af = iptable.tobin(nil);
      assert.are_equal(nil, addr);
    end)

    it("handles no arg", function()
      addr, mlen, af = iptable.tobin();
      assert.are_equal(nil, addr);
    end)

    it("handles table arg", function()
      addr, mlen, af = iptable.tobin({});
      assert.are_equal(nil, addr);
    end)

    it("handles binary arg", function()
      addr, mlen, af = iptable.tobin("10.10.10.10");
      assert.are_equal(5, #addr);
      addr, mlen, af = iptable.tobin(addr);
      assert.are_equal(nil, addr);
    end)

  end)
end)
