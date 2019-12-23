#!/usr/bin/env lua
-------------------------------------------------------------------------------
--  Description:  unit test file for iptable
-------------------------------------------------------------------------------

package.cpath = "./build/?.so;"

describe("iptable.reverse(pfx)", function()

  expose("module: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);

    it("reverses ipv4", function()
      assert.equal("0.0.0.0", iptable.reverse("0.0.0.0"))
      assert.equal("255.255.255.255", iptable.reverse("255.255.255.255"))
      assert.equal("4.3.2.1", iptable.reverse("1.2.3.4"))
      assert.equal("14.13.12.11", iptable.reverse("11.12.13.14"))
      assert.equal("114.113.112.111", iptable.reverse("111.112.113.114"))
    end)

    it("reverses ipv6", function()
      -- NOTE: ipv6 reversal is at nibble
      assert.equal("::", iptable.reverse("::"))
      assert.equal("2001:aacc::", iptable.reverse("::ccaa:1002"))
    end)

    it("returns reversed address, mlen and af", function()
      local ip,mlen,af
      ip, mlen, af = iptable.reverse("11.12.13.14/24")
      assert.equal("14.13.12.11", ip)
      assert.equal(24, mlen)
      assert.equal(iptable.AF_INET, af)

      ip, mlen, af = iptable.reverse("::acdc:1976/32")
      assert.equal("6791:cdca::", ip)
      assert.equal(32, mlen)
      assert.equal(iptable.AF_INET6, af)

      -- ipv4 in ipv6?
      ip, mlen, af = iptable.reverse("1112:1314:1516:1718:1920:2122:2324:2526/128")
      assert.equal("6252:4232:2212:291:8171:6151:4131:2111", ip)
      assert.equal(128, mlen)
      assert.equal(iptable.AF_INET6, af)

    end)

  end)
end)
