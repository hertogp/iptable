#!/usr/bin/env lua
-------------------------------------------------------------------------------
--  Description:  unit test file for iptable
-------------------------------------------------------------------------------

package.cpath = "./build/?.so;"

describe("iptable.masklen(): ", function()

  expose("module: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);

    it("calulates the minimum", function()
      local mask = "255.0.0.0";
      addr, mlen, af = iptable.tobin(mask);
      local mlen = iptable.masklen(addr);
      assert.are_equal(8, mlen);
    end)

    it("handles empty string arg", function()
      local mlen = iptable.masklen("");
      assert.are_equal(nil, mlen);
    end)

    it("handles no arg", function()
      local mlen = iptable.masklen();
      assert.are_equal(nil, mlen);
    end)

    it("handles nil arg", function()
      local mlen = iptable.masklen(nil);
      assert.are_equal(nil, mlen);
    end)

    it("handles non-string arg", function()
      local mlen = iptable.masklen(false);
      assert.are_equal(nil, mlen);

      mlen = iptable.masklen({});
      assert.are_equal(nil, mlen);
    end)

    -- LEN-byte of a mask binary may denotes the nr of non-zero bytes in the
    -- array rather than its total length (radix tree subtlety)
    -- So LEN=0 -> all bytes in the array (incl LEN) are zero.
    -- LEN=1 -> only LEN byte is non-zero -> doesn't check any mask bytes
    -- LEN=2 -> only first mask byte is non-zero
    -- LEN=3 -> only first two mask bytes are non-zero, ... etc...
    it("honors mask's LEN as #non-zero bytes (not array length)", function()
      local mlen = iptable.masklen('\x00\xff\xff\xf0\x00');
      assert.are_equal(0, mlen);  -- honor LEN=0
    end)
    it("honors mask's LEN as #non-zero bytes (not array length)", function()
      local mlen = iptable.masklen('\x01\xff\xff\xf0\x00');
      assert.are_equal(0, mlen);  -- honor LEN=1
    end)
    it("honors mask's LEN as #non-zero bytes (not array length)", function()
      local mlen = iptable.masklen('\x02\xff\xff\xf0\x00');
      assert.are_equal(8, mlen);  -- honor LEN=2
    end)
    it("honors mask's LEN as #non-zero bytes (not array length)", function()
      local mlen = iptable.masklen('\x03\xff\xff\xf0\x00');
      assert.are_equal(16, mlen);  -- honor LEN=3
    end)
    it("honors mask's LEN as #non-zero bytes (not array length)", function()
      local mlen = iptable.masklen('\x04\xff\xff\xf0\x00');
      assert.are_equal(20, mlen);  -- honor LEN=4
    end)
    it("honors mask's LEN as #non-zero bytes (not array length)", function()
      local mlen = iptable.masklen('\x05\xff\xff\xf0\x00');
      assert.are_equal(20, mlen);  -- honor LEN=5
    end)

  end)
end)
