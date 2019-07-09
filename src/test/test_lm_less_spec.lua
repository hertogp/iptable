#!/usr/bin/env lua

package.cpath = "./build/?.so;"

F = string.format

describe("ipt:less(pfx) ", function()

  expose("instance: ", function()
    local iptable = require("iptable");
    assert.is_truthy(iptable);
    local ipt = iptable.new();
    assert.is_truthy(ipt);

    -- a string based table
    local pfx = {
      ["1.1.1.0/24"]   = 1,
      ["1.1.1.0/25"]   = 2,
      ["1.1.1.128/25"] = 4,
      ["1.1.1.0/26"]   = 8,
      ["1.1.1.64/26"]  = 16,
      ["1.1.1.128/26"] = 32,
      ["1.1.1.192/26"] = 64,
    }
    -- a longest prefix matching table
    for k,v in pairs(pfx) do ipt[k] = v end

    it("finds less specifics for host address", function()
      local sum = 0
      for p, v in ipt:less("1.1.1.130") do sum = sum + v end
      assert.are.equal(1 + 4 + 32, sum)
    end)

    it("finds less specifics for host address", function()
      local sum = 0
      for p, v in ipt:less("1.1.1.1") do sum = sum + v end
      assert.are.equal(1 + 2 + 8, sum)
    end)

    it("finds less specifics for host address", function()
      local sum = 0
      for p, v in ipt:less("1.1.1.64") do sum = sum + v end
      assert.are.equal(1 + 2 + 16, sum)
    end)

    it("finds less specifics for addr/mask", function()
      local sum = 0
      -- non-inclusive search, so the /26 won't be included
      for p, v in ipt:less("1.1.1.66/26") do sum = sum + v end
      assert.are.equal(1 + 2, sum)
    end)

    it("finds less specifics for addr/mask, inclusive", function()
      local sum = 0
      for p, v in ipt:less("1.1.1.66/26", true) do sum = sum + v end
      assert.are.equal(1 + 2 + 16, sum)
    end)
  end)

end)

describe("ipt:less(pfx) w/ 0/0 ", function()

  expose("instance: ", function()
    local iptable = require("iptable");
    assert.is_truthy(iptable);
    local ipt = iptable.new();
    assert.is_truthy(ipt);

    -- a string based table
    local pfx = {
      ["0.0.0.0/0"]    = 128,
      ["1.1.1.0/24"]   = 1,
      ["1.1.1.0/25"]   = 2,
      ["1.1.1.128/25"] = 4,
      ["1.1.1.0/26"]   = 8,
      ["1.1.1.64/26"]  = 16,
      ["1.1.1.128/26"] = 32,
      ["1.1.1.192/26"] = 64,
    }
    -- a longest prefix matching table
    for k,v in pairs(pfx) do ipt[k] = v end

    it("finds less specifics for host address", function()
      local sum = 0
      for p, v in ipt:less("1.1.1.130") do sum = sum + v end
      assert.are.equal(1 + 4 + 32 + 128, sum)
    end)

    it("finds less specifics for addr/mask", function()
      local sum = 0
      -- non-inclusive search, so the /26 won't be included
      for p, v  in ipt:less("1.1.1.66/26") do sum = sum + v end
      assert.are.equal(1 + 2 + 128, sum)
    end)

    it("finds less specifics for addr/mask, inclusive", function()
      local sum = 0
      for p, v in ipt:less("1.1.1.66/26", true) do sum = sum + v end
      assert.are.equal(1 + 2 + 16 + 128, sum)
    end)

    it("finds less specifics for addr/mask, inclusive", function()
      local sum = 0
      for p, v in ipt:less("1.1.1.66/26", true) do sum = sum + v end
      assert.are.equal(1 + 2 + 16 + 128, sum)
    end)
  end)

end)
