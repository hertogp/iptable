#!/usr/bin/env lua

-- Test iptable instance method: t:masks(AF)

package.cpath = "./build/?.so;"

-- helpers

F = string.format

-- tests

describe("t:masks(af): ", function()

  expose("instance t ", function()

    iptable = require("iptable");
    assert.is_truthy(iptable);

    AF_INET = iptable.AF_INET
    AF_INET6 = iptable.AF_INET6


    it("finds no masks in an emtpy table", function()
      local t = iptable.new()
      local cnt = 0;

      for mask in t:masks(AF_INET) do cnt = cnt + 1 end
      assert.are_equal(0, cnt);

      cnt = 0
      for mask in t:masks(AF_INET6) do cnt = cnt + 1 end
      assert.are_equal(0, cnt);
    end)

    it("finds /0 masks in ipv4 tree", function()
      local t = iptable.new()
      local cnt = 0;

      t["0.0.0.0/0"] = 1
      for mask in t:masks(AF_INET) do cnt = cnt + 1 end
      assert.are_equal(1, cnt);

    end)

    it("finds /0 masks in ipv6 tree", function()
      local t = iptable.new()
      local cnt = 0;

      t["::/0"] = 1
      for mask in t:masks(AF_INET6) do cnt = cnt + 1 end
      assert.are_equal(1, cnt);
    end)

    it("finds /0 masks per protocol family", function()
      local t = iptable.new()
      local cnt = 0;

      t["0.0.0.0/0"] = 1
      t["::/0"] = 1
      for mask in t:masks(AF_INET) do cnt = cnt + 1 end
      assert.are_equal(1, cnt);

      cnt = 0
      for mask in t:masks(AF_INET6) do cnt = cnt + 1 end
      assert.are_equal(1, cnt);

    end)

    it("finds max masks per protocol family", function()
      local t = iptable.new()
      local cnt = 0;

      t["0.0.0.0/32"] = 1
      t["::/128"] = 1
      for mask in t:masks(AF_INET) do cnt = cnt + 1 end
      assert.are_equal(1, cnt);

      cnt = 0
      for mask in t:masks(AF_INET6) do cnt = cnt + 1 end
      assert.are_equal(1, cnt);

    end)

    it("finds both /0 and /max  masks per protocol family", function()
      local t = iptable.new()
      local cnt = 0;

      t["0.0.0.0/0"] = 1
      t["0.0.0.0/32"] = 1
      t["::/0"] = 1
      t["::/128"] = 1
      for mask in t:masks(AF_INET) do cnt = cnt + 1 end
      assert.are_equal(2, cnt);

      cnt = 0
      for mask in t:masks(AF_INET6) do cnt = cnt + 1 end
      assert.are_equal(2, cnt);
    end)

    it("finds all ipv4 masks", function()
      local t = iptable.new()
      local cnt = 0;

      -- load a prefix with all possible masks
      for mlen=0, 32 do t[F("1.1.1.1/%s", mlen)] = mlen end

      cnt = 0
      for mask, mlen in t:masks(AF_INET) do cnt = cnt + 1 end
      assert.are_equal(33, cnt);
    end)

    it("finds all ipv6 masks", function()
      local t = iptable.new()
      local cnt = 0;

      -- load a prefix with all possible masks
      for mlen=0, 128 do t[F("9f:ff::/%s", mlen)] = mlen end

      cnt = 0
      for mask in t:masks(AF_INET6) do cnt = cnt + 1 end
      assert.are_equal(129, cnt);
    end)

  end)
end)
