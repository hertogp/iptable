#!/usr/bin/env lua
-------------------------------------------------------------------------------
--         File:  test_lua_iptable_subnets.lua
--        Usage:  busted src/test/test_lua_iptable_subnets.lua
--  Description:  unit test file for iptable
-------------------------------------------------------------------------------

package.cpath = "./build/?.so;"
describe("iptable.subnets(): ", function()

  expose("ipt: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);

  it("iterates across prefix's subnets", function()
    local cnt = 0, pfx
    for pfx in iptable.subnets("11.12.13.0/24", 26) do
      cnt = cnt + 1
    end
    assert.are_equal(4, cnt)
    assert.is_falsy(iptable.error)

    cnt = 0
    for pfx in iptable.subnets("2001:acdc::/24", 26) do
      cnt = cnt + 1
    end
    assert.are_equal(4, cnt)
    assert.is_falsy(iptable.error)
  end)

  it("defaults to a new mask thats 1 bit longer", function()
    local cnt = 0, pfx
    for pfx in iptable.subnets("11.12.13.0/24") do
      cnt = cnt + 1
    end
    assert.are_equal(2, cnt)
    assert.is_falsy(iptable.error)

    cnt = 0
    for pfx in iptable.subnets("::/24") do
      cnt = cnt + 1
    end
    assert.are_equal(2, cnt)
    assert.is_falsy(iptable.error)
  end)

  it("subnets may have a max mask", function()
    local cnt = 0, pfx
    for pfx in iptable.subnets("11.12.13.0/24", 32) do
      cnt = cnt + 1
    end
    assert.are_equal(256, cnt)
    assert.is_falsy(iptable.error)

    cnt = 0
    for pfx in iptable.subnets("::/120", 128) do
      cnt = cnt + 1
    end
    assert.are_equal(256, cnt)
    assert.is_falsy(iptable.error)
  end)

  it("max mask in prefix yields error", function()
    local cnt = 0, pfx
    for pfx in iptable.subnets("11.12.13.0/32", 32) do
      cnt = cnt + 1
    end
    assert.are_equal(0, cnt)
    assert.is_truthy(iptable.error)
    iptable.error = nil

    cnt = 0
    for pfx in iptable.subnets("::/128", 128) do
      cnt = cnt + 1
    end
    assert.are_equal(0, cnt)
    assert.is_truthy(iptable.error)
    iptable.error = nil
  end)

  it("detects invalid new masks", function()
    local cnt = 0, pfx
    for pfx in iptable.subnets("11.12.13.0/24", 33) do
      cnt = cnt + 1
    end
    assert.are_equal(0, cnt)
    assert.is_truthy(iptable.error)
    iptable.error = nil

    cnt = 0
    for pfx in iptable.subnets("::/120", 129) do
      cnt = cnt + 1
    end
    assert.are_equal(0, cnt)
    assert.is_truthy(iptable.error)
    iptable.error = nil
  end)

  it("detects a new ipv4 mask smaller than the original", function()
    local cnt = 0, pfx
    for pfx in iptable.subnets("11.12.13.0/24", 23) do
      cnt = cnt + 1
    end
    assert.are_equal(0, cnt)
    assert.is_truthy(iptable.error)
    iptable.error = nil

    cnt = 0
    for pfx in iptable.subnets("::/120", 119) do
      cnt = cnt + 1
    end
    assert.are_equal(0, cnt)
    assert.is_truthy(iptable.error)
    iptable.error = nil
  end)

  it("handles odd ipv4 masks", function()
    local cnt = 0, pfx
    for pfx in iptable.subnets("11.12.13.0/31", 32) do
      cnt = cnt + 1
    end
    assert.are_equal(2, cnt)

    cnt = 0
    for pfx in iptable.subnets("11.12.13.0/0", 2) do
      cnt = cnt + 1
    end
    assert.are_equal(4, cnt)
    assert.is_falsy(iptable.error)
  end)

  it("handles odd ipv6 masks", function()
    local cnt = 0, pfx
    for pfx in iptable.subnets("::/127", 128) do
      cnt = cnt + 1
    end
    assert.are_equal(2, cnt)
    assert.is_falsy(iptable.error)

    cnt = 0
    for pfx in iptable.subnets("::/0", 2) do
      cnt = cnt + 1
    end
    assert.are_equal(4, cnt)
    assert.is_falsy(iptable.error)
  end)


  end)
end)
