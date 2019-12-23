#!/usr/bin/env lua
-------------------------------------------------------------------------------
--         File:  test_lua_iptable_split.lua
--        Usage:  busted src/test/test_lua_iptable_split.lua
--  Description:  unit test file for iptable
-------------------------------------------------------------------------------

package.cpath = "./build/?.so;"
describe("iptable.split(): ", function()

  expose("ipt: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);

  it("splits a prefix in two parts", function()
    local pfx1, pfx2, mlen, af, err = iptable.split("11.12.13.0/24")
    assert.are_equal("11.12.13.0", pfx1)
    assert.are_equal("11.12.13.128", pfx2)
    assert.are_equal(25, mlen)
    assert.are_equal(2, af)
    assert.is_falsy(err)

    local pfx1, pfx2, mlen, af, err = iptable.split("acdc:aaa0::/31")
    assert.are_equal("acdc:aaa0::", pfx1)
    assert.are_equal("acdc:aaa1::", pfx2)
    assert.are_equal(32, mlen)
    assert.are_equal(10, af)
    assert.is_falsy(err)
  end)

  it("won't split host addresses", function()
    local pfx1, pfx2, mlen, af, err = iptable.split("11.12.13.14/32")
    assert.are_equal(nil, pfx1)
    assert.are_equal(nil, pfx2)
    assert.are_equal(nil, mlen)
    assert.are_equal(nil, af)
    assert.is_truthy(err)

    local pfx1, pfx2, mlen, af, err = iptable.split("11.12.13.14")
    assert.are_equal(nil, pfx1)
    assert.are_equal(nil, pfx2)
    assert.are_equal(nil, mlen)
    assert.are_equal(nil, af)
    assert.is_truthy(err)

    local pfx1, pfx2, mlen, af, err = iptable.split("acdc:aaa0::/128")
    assert.are_equal(nil, pfx1)
    assert.are_equal(nil, pfx2)
    assert.are_equal(nil, mlen)
    assert.are_equal(nil, af)
    assert.is_truthy(err)

    local pfx1, pfx2, mlen, af, err = iptable.split("acdc:aaa0::")
    assert.are_equal(nil, pfx1)
    assert.are_equal(nil, pfx2)
    assert.are_equal(nil, mlen)
    assert.are_equal(nil, af)
    assert.is_truthy(err)
  end)

  it("also splits a /0 in two parts", function()
    local pfx1, pfx2, mlen, af, err = iptable.split("0.0.0.0/0")
    assert.are_equal("0.0.0.0", pfx1)
    assert.are_equal("128.0.0.0", pfx2)
    assert.are_equal(1, mlen)
    assert.are_equal(2, af)
    assert.is_falsy(err)

    local pfx1, pfx2, mlen, af, err = iptable.split("::/0")
    assert.are_equal("::", pfx1)
    assert.are_equal("8000::", pfx2)
    assert.are_equal(1, mlen)
    assert.are_equal(10, af)
    assert.is_falsy(err)
  end)

  it("detects faulty masks", function()
    local pfx1, pfx2, mlen, af, err = iptable.split("11.12.13.14/33")
    assert.are_equal(nil, pfx1)
    assert.are_equal(nil, pfx2)
    assert.are_equal(nil, mlen)
    assert.are_equal(nil, af)
    assert.is_truthy(err)

    local pfx1, pfx2, mlen, af, err = iptable.split("11.12.13.14/-3")
    assert.are_equal(nil, pfx1)
    assert.are_equal(nil, pfx2)
    assert.are_equal(nil, mlen)
    assert.are_equal(nil, af)
    assert.is_truthy(err)

    local pfx1, pfx2, mlen, af, err = iptable.split("acdc:aaa0::/129")
    assert.are_equal(nil, pfx1)
    assert.are_equal(nil, pfx2)
    assert.are_equal(nil, mlen)
    assert.are_equal(nil, af)
    assert.is_truthy(err)

    local pfx1, pfx2, mlen, af, err = iptable.split("acdc:aaa0::/-1")
    assert.are_equal(nil, pfx1)
    assert.are_equal(nil, pfx2)
    assert.are_equal(nil, mlen)
    assert.are_equal(nil, af)
    assert.is_truthy(err)
  end)

  it("handles edge cases", function()
    local pfx1, pfx2, mlen, af, err = iptable.split("11.12.13.0/31")
    assert.are_equal("11.12.13.0", pfx1)
    assert.are_equal("11.12.13.1", pfx2)
    assert.are_equal(32, mlen)
    assert.are_equal(2, af)
    assert.is_falsy(err)

    local pfx1, pfx2, mlen, af, err = iptable.split("acdc:aaa0::/127")
    assert.are_equal("acdc:aaa0::", pfx1)
    assert.are_equal("acdc:aaa0::1", pfx2)
    assert.are_equal(128, mlen)
    assert.are_equal(10, af)
    assert.is_falsy(err)
  end)


  end)
end)
