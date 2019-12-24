#!/usr/bin/env lua
-------------------------------------------------------------------------------
--  Description:  unit test file for iptable
-------------------------------------------------------------------------------

package.cpath = "./build/?.so;"
describe("iptable.dnsptr(): ", function()

  expose("ipt: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);

    it("provides a reverse dns name", function()
      ptr, mlen, af, err = iptable.dnsptr("1.2.3.4");
      assert.are_equal(iptable.AF_INET, af);
      assert.are_equal(-1, mlen);
      assert.are_equal("4.3.2.1.in-addr.arpa.", ptr);
      assert.are_equal(nil, err)

      ptr, mlen, af, err = iptable.dnsptr("255.254.253.252");
      assert.are_equal(iptable.AF_INET, af);
      assert.are_equal(-1, mlen);
      assert.are_equal("252.253.254.255.in-addr.arpa.", ptr);
      assert.are_equal(nil, err)

      ptr, mlen, af, err = iptable.dnsptr("1234:5678:9abc:def0::");
      assert.are_equal(iptable.AF_INET6, af);
      assert.are_equal(-1, mlen);
      assert.are_equal("0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.e.d.c.b.a.9.8.7.6.5.4.3.2.1.ip6.arpa.", ptr);
      assert.are_equal(nil, err)

      ptr, mlen, af, err = iptable.dnsptr("::1234:5678:9abc:def0");
      assert.are_equal(iptable.AF_INET6, af);
      assert.are_equal(-1, mlen);
      assert.are_equal("0.f.e.d.c.b.a.9.8.7.6.5.4.3.2.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.", ptr);
      assert.are_equal(nil, err)

      ptr, mlen, af, err = iptable.dnsptr("1234:5678::9abc:def0");
      assert.are_equal(iptable.AF_INET6, af);
      assert.are_equal(-1, mlen);
      assert.are_equal("0.f.e.d.c.b.a.9.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.7.6.5.4.3.2.1.ip6.arpa.", ptr);
      assert.are_equal(nil, err)
    end)

    it("ignores a mask", function()
      ptr, mlen, af, err = iptable.dnsptr("1.2.3.4/24");
      assert.are_equal(iptable.AF_INET, af);
      assert.are_equal(24, mlen);
      assert.are_equal("4.3.2.1.in-addr.arpa.", ptr);
      assert.are_equal(nil, err)

      ptr, mlen, af, err = iptable.dnsptr("1234:5678:9abc:def0::/128");
      assert.are_equal(iptable.AF_INET6, af);
      assert.are_equal(128, mlen);
      assert.are_equal("0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.e.d.c.b.a.9.8.7.6.5.4.3.2.1.ip6.arpa.", ptr);
      assert.are_equal(nil, err)
    end)

    it("detects illegal masks", function()
      ptr, mlen, af, err = iptable.dnsptr("1.2.3.4/128");
      assert.are_equal(nil, af);
      assert.are_equal(nil, mlen);
      assert.are_equal(nil, ptr);
      assert.is_truthy(err)

      ptr, mlen, af, err = iptable.dnsptr("::/129");
      assert.are_equal(nil, af);
      assert.are_equal(nil, mlen);
      assert.are_equal(nil, ptr);
      assert.is_truthy(err)
    end)

  end)
end)
