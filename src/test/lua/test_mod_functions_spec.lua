#!/usr/bin/env lua
-------------------------------------------------------------------------------
--         File:  test_index.lua
--        Usage:  ./test_create.lua
--  Description:  unit test file for iptable
-------------------------------------------------------------------------------

package.cpath = "./build/?.so;"..package.cpath

function key_str(buf)
  local s = ""
  local len = buf:byte(1)
  for i=1, len, 1 do
    s = s ..string.format("%02x", buf:byte(i));
    if (i < len) then s = s .. ":"; end
  end
  return s;
end

describe("iptable module functions: ", function()

  expose("tobin(): ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);
    ipt = iptable.new();
    assert.is_truthy(ipt);

    it("no mask -> mlen=-1", function()
      addr, mlen, af = iptable.tobin("10.10.10.10");
      assert.are_equal(iptable.AF_INET, af);
      assert.are_equal(-1, mlen);  -- -1 means no mask
      assert.are_equal(5, #addr);
    end)

    it("max ipv4 mask -> mlen=32", function()
      addr, mlen, af = iptable.tobin("10.10.10.10/32");
      assert.are_equal(iptable.AF_INET, af);
      assert.are_equal(32, mlen);
      assert.are_equal("05:0a:0a:0a:0a", key_str(addr));
    end)

    it("zero mask (/0) -> mlen=0", function()
      addr, mlen, af = iptable.tobin("10.11.12.13/0");
      assert.are_equal(iptable.AF_INET, af);
      assert.are_equal(0, mlen);
      assert.are_equal("05:0a:0b:0c:0d", key_str(addr));
    end)

    it("bad mask (<0) -> yields nil values", function()
      addr, mlen, af = iptable.tobin("10.10.10.10/-1");
      assert.are_equal(nil, af);
      assert.are_equal(nil, mlen);
      assert.are_equal(nil, addr);
    end)

    it("bad mask (>max) -> yields nil", function()
      addr, mlen, af = iptable.tobin("10.10.10.10/33");
      assert.are_equal(nil, af);
      assert.are_equal(nil, mlen);
      assert.are_equal(nil, addr);
    end)

    it("no mask -> mlen=-1", function()
      addr, mlen, af = iptable.tobin("2f:aa:bb::");
      print("\nipv6 key "..key_str(addr));
      assert.are_equal(iptable.AF_INET6, af);
      assert.are_equal(-1, mlen);  -- -1 means no mask
      assert.are_equal(17, #addr);
    end)

    it("max ipv6 mask -> mlen=128", function()
      addr, mlen, af = iptable.tobin("2f:aa:bb::/128");
      assert.are_equal(iptable.AF_INET6, af);
      assert.are_equal(128, mlen);
      assert.are_equal("11:00:2f:00:aa:00:bb:00:00:00:00:00:00:00:00:00:00", key_str(addr));
    end)

    it("zero mask (/0) -> mlen=0", function()
      addr, mlen, af = iptable.tobin("002f:00aa:00bb::/0");
      assert.are_equal(iptable.AF_INET6, af);
      assert.are_equal(0, mlen);
      assert.are_equal("11:00:2f:00:aa:00:bb:00:00:00:00:00:00:00:00:00:00", key_str(addr));
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
  end)
end)
