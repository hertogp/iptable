#!/usr/bin/env lua
-------------------------------------------------------------------------------
--         File:  test_index.lua
--        Usage:  ./test_create.lua
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

describe("require iptable: ", function()
  expose("iptable", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);

    it("should yield a module", function()
      iptable = require("iptable");
      assert.is_truthy(iptable);
    end)
  end)
end)

describe("iptable.tobin(): ", function()
  expose("ipt: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);

    it("returns mlen=-1 wen no mask is given", function()
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

describe("iptable.tolen(): ", function()

  expose("module: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);

    it("calulates the minimum", function()
      local mask = "255.0.0.0";
      addr, mlen, af = iptable.tobin(mask);
      local mlen = iptable.tolen(addr);
      assert.are_equal(8, mlen);
    end)

    it("handles empty string arg", function()
      local mlen = iptable.tolen("");
      assert.are_equal(nil, mlen);
    end)

    it("handles no arg", function()
      local mlen = iptable.tolen();
      assert.are_equal(nil, mlen);
    end)

    it("handles nil arg", function()
      local mlen = iptable.tolen(nil);
      assert.are_equal(nil, mlen);
    end)

    it("handles non-string arg", function()
      local mlen = iptable.tolen(false);
      assert.are_equal(nil, mlen);

      mlen = iptable.tolen({});
      assert.are_equal(nil, mlen);
    end)

    -- LEN-byte of a mask binary may denotes the nr of non-zero bytes in the
    -- array rather than its total length (radix tree subtlety)
    -- So LEN=0 -> all bytes in the array (incl LEN) are zero.
    -- LEN=1 -> only LEN byte is non-zero -> doesn't check any mask bytes
    -- LEN=2 -> only first mask byte is non-zero
    -- LEN=3 -> only first two mask bytes are non-zero, ... etc...
    it("honors mask's LEN as #non-zero bytes (not array length)", function()
      local mlen = iptable.tolen('\x00\xff\xff\xf0\x00');
      assert.are_equal(0, mlen);  -- honor LEN=0
    end)
    it("honors mask's LEN as #non-zero bytes (not array length)", function()
      local mlen = iptable.tolen('\x01\xff\xff\xf0\x00');
      assert.are_equal(0, mlen);  -- honor LEN=1
    end)
    it("honors mask's LEN as #non-zero bytes (not array length)", function()
      local mlen = iptable.tolen('\x02\xff\xff\xf0\x00');
      assert.are_equal(8, mlen);  -- honor LEN=2
    end)
    it("honors mask's LEN as #non-zero bytes (not array length)", function()
      local mlen = iptable.tolen('\x03\xff\xff\xf0\x00');
      assert.are_equal(16, mlen);  -- honor LEN=3
    end)
    it("honors mask's LEN as #non-zero bytes (not array length)", function()
      local mlen = iptable.tolen('\x04\xff\xff\xf0\x00');
      assert.are_equal(20, mlen);  -- honor LEN=4
    end)
    it("honors mask's LEN as #non-zero bytes (not array length)", function()
      local mlen = iptable.tolen('\x05\xff\xff\xf0\x00');
      assert.are_equal(20, mlen);  -- honor LEN=5
    end)

  end)
end)

describe("iptable.newtork(): ", function()

  expose("ipt: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);

    it("no mask -> network is itself", function()
      netw, mlen, af = iptable.network("10.10.10.10");
      assert.are_equal(iptable.AF_INET, af);
      assert.are_equal(-1, mlen);  -- -1 means no mask was provided
      assert.are_equal("10.10.10.10", netw);
    end)

    it("max mask -> network is itself", function()
      netw, mlen, af = iptable.network("10.10.10.10/32");
      assert.are_equal(iptable.AF_INET, af);
      assert.are_equal(32, mlen);  -- -1 means no mask was provided
      assert.are_equal("10.10.10.10", netw);
    end)

    it("zero mask -> network is all zeros", function()
      netw, mlen, af = iptable.network("10.10.10.10/0");
      assert.are_equal(iptable.AF_INET, af);
      assert.are_equal(0, mlen);  -- -1 means no mask was provided
      assert.are_equal("0.0.0.0", netw);
    end)

    it("normal mask -> network address", function()
      netw, mlen, af = iptable.network("10.10.10.10/8");
      assert.are_equal(iptable.AF_INET, af);
      assert.are_equal(8, mlen);  -- -1 means no mask was provided
      assert.are_equal("10.0.0.0", netw);
    end)

    it("normal mask -> network address", function()
      netw, mlen, af = iptable.network("10.10.10.10/30");
      assert.are_equal(iptable.AF_INET, af);
      assert.are_equal(30, mlen);  -- -1 means no mask was provided
      assert.are_equal("10.10.10.8", netw);
    end)

    it("yields nils when args absent", function()
      netw, mlen, af = iptable.network();
      assert.are_equal(nil, af);
      assert.are_equal(nil, mlen);  -- -1 means no mask was provided
      assert.are_equal(nil, netw);
    end)

    it("yields nils when args non-string", function()
      netw, mlen, af = iptable.network(true);
      assert.are_equal(nil, af);
      assert.are_equal(nil, mlen);  -- -1 means no mask was provided
      assert.are_equal(nil, netw);
    end)

    it("yields nils for illegal prefixes", function()
      netw, mlen, af = iptable.network("10.10.10.10/-1");
      assert.are_equal(nil, af);
      assert.are_equal(nil, mlen);  -- -1 means no mask was provided
      assert.are_equal(nil, netw);
    end)

    it("yields nils for illegal prefixes", function()
      netw, mlen, af = iptable.network("10.10.10.10/33");
      assert.are_equal(nil, af);
      assert.are_equal(nil, mlen);  -- -1 means no mask was provided
      assert.are_equal(nil, netw);
    end)


  end)
end)

describe("iptable.broadcast(): ", function()

  expose("ipt: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);

    it("no mask -> broadcast is itself", function()
      addr, mlen, af = iptable.broadcast("10.10.10.10");
      assert.are_equal(iptable.AF_INET, af);
      assert.are_equal(-1, mlen);  -- -1 means no mask was provided
      assert.are_equal("10.10.10.10", addr);
    end)

    it("max mask -> broadcast is itself", function()
      addr, mlen, af = iptable.broadcast("10.10.10.10/32");
      assert.are_equal(iptable.AF_INET, af);
      assert.are_equal(32, mlen);
      assert.are_equal("10.10.10.10", addr);
    end)

    it("zero mask -> broadcast is all broadcast", function()
      addr, mlen, af = iptable.broadcast("10.10.10.10/0");
      assert.are_equal(iptable.AF_INET, af);
      assert.are_equal(0, mlen);
      assert.are_equal("255.255.255.255", addr);
    end)

    it("normal mask -> broadcast is subnet broadcast", function()
      addr, mlen, af = iptable.broadcast("10.10.10.10/30");
      assert.are_equal(iptable.AF_INET, af);
      assert.are_equal(30, mlen);
      assert.are_equal("10.10.10.11", addr);
    end)

    it("normal mask -> broadcast is subnet broadcast", function()
      addr, mlen, af = iptable.broadcast("10.10.10.10/8");
      assert.are_equal(iptable.AF_INET, af);
      assert.are_equal(8, mlen);
      assert.are_equal("10.255.255.255", addr);
    end)

    it("normal mask -> broadcast is subnet broadcast", function()
      addr, mlen, af = iptable.broadcast("10.11.12.13/27");
      assert.are_equal(iptable.AF_INET, af);
      assert.are_equal(27, mlen);
      assert.are_equal("10.11.12.31", addr);
    end)

    it("yields nils on non-string args", function()
      addr, mlen, af = iptable.broadcast(true);
      assert.are_equal(nil, af);
      assert.are_equal(nil, mlen);
      assert.are_equal(nil, addr);
    end)

    it("yields nils on non-string args", function()
      addr, mlen, af = iptable.broadcast({});
      assert.are_equal(nil, af);
      assert.are_equal(nil, mlen);
      assert.are_equal(nil, addr);
    end)

    it("yields nils on non-string args", function()
      addr, mlen, af = iptable.broadcast(nil);
      assert.are_equal(nil, af);
      assert.are_equal(nil, mlen);
      assert.are_equal(nil, addr);
    end)

    it("yields nils on absent args", function()
      addr, mlen, af = iptable.broadcast();
      assert.are_equal(nil, af);
      assert.are_equal(nil, mlen);
      assert.are_equal(nil, addr);
    end)

  end)
end)


describe("iptable.hosts(): ", function()

  expose("ipt: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);

    -- unless specified, inclusive is false
    -- so no network/broadcast addresses are included.
    it("no mask, non-inclusive -> iteration yields 0 hosts", function()
      cnt = 0;
      for host in iptable.hosts("10.10.10.10") do
        cnt = cnt + 1;
      end
      assert.are_equal(0, cnt);
    end)

    it("no mask, inclusive -> iteration yields 1 host", function()
      cnt = 0;
      for host in iptable.hosts("10.10.10.10", true) do
        cnt = cnt + 1;
      end
      assert.are_equal(1, cnt);
    end)

    it("max mask, non-inclusive -> iteration yields 0 hosts", function()
      cnt = 0;
      for host in iptable.hosts("10.10.10.10/32") do
        cnt = cnt + 1;
      end
      assert.are_equal(0, cnt);
    end)

    it("max mask, inclusive -> iteration yields 1 host", function()
      cnt = 0;
      for host in iptable.hosts("10.10.10.10/32", true) do
        cnt = cnt + 1;
      end
      assert.are_equal(1, cnt);
    end)

    it("max network, inclusive -> iteration stops at all broadcast", function()
      cnt = 0;
      for host in iptable.hosts("255.255.255.252/30", true) do
        cnt = cnt + 1;
      end
      assert.are_equal(4, cnt);
    end)

    it("max network, non-inclusive -> iterates hostid's only ", function()
      cnt = 0;
      for host in iptable.hosts("255.255.255.252/30", false) do
        cnt = cnt + 1;
      end
      assert.are_equal(2, cnt);
    end)

    it("some network, non-inclusive -> iterates hostid's only ", function()
      cnt = 0;
      for host in iptable.hosts("10.11.12.13/24", false) do
        cnt = cnt + 1;
      end
      assert.are_equal(254, cnt);
    end)

    it("some network, inclusive -> iterates all ip's", function()
      cnt = 0;
      for host in iptable.hosts("10.11.12.13/24", true) do
        cnt = cnt + 1;
      end
      assert.are_equal(256, cnt);
    end)

  end)
end)

describe("iptable.numhosts(pfx): ", function()

  expose("ipt: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);

    it("no mask means 1 host", function()
      assert.are_equal(1, iptable.numhosts("1.1.1.1"));
    end)

    it("/32 mask means 1 host", function()
      assert.are_equal(1, iptable.numhosts("0.0.0.0/32"));
    end)

    it("/0 mask means a lot of hosts", function()
      assert.are_equal(2^32, iptable.numhosts("0.0.0.0/0"));
    end)

    -- ipv6 may represent a lot of hosts ...
    it("62 bits is the largets working nr right now", function()
      assert.are_equal(256, iptable.numhosts("2f::/120"));
    end)

    -- for 128 hostbits, it definitely fails!
    it("/0 mask means a lot more host for ipv6", function()
      assert.are_equal(2^128, iptable.numhosts("2f::/0"));
    end)

  end)
end)

describe("iptable.mask(af, num)", function()

  expose("module: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);

    it("handles ipv4 max (inv)mask", function()
      assert.equal("255.255.255.255", iptable.mask(iptable.AF_INET, 32));
      assert.equal("0.0.0.0", iptable.mask(iptable.AF_INET, -32));
    end)

    it("handles ipv4 min (inv)mask", function()
      assert.equal("0.0.0.0", iptable.mask(iptable.AF_INET, 0));
      assert.equal("0.0.0.0", iptable.mask(iptable.AF_INET, -0));
    end)

    it("handles ipv4 regular (inv)masks", function()
      assert.equal("255.255.255.254", iptable.mask(iptable.AF_INET, 31));
      assert.equal("0.0.0.1", iptable.mask(iptable.AF_INET, -31));

      assert.equal("255.255.255.252", iptable.mask(iptable.AF_INET, 30));
      assert.equal("0.0.0.3", iptable.mask(iptable.AF_INET, -30));

      assert.equal("255.255.255.128", iptable.mask(iptable.AF_INET, 25));
      assert.equal("0.0.0.127", iptable.mask(iptable.AF_INET, -25));

      assert.equal("255.255.255.0", iptable.mask(iptable.AF_INET, 24));
      assert.equal("0.0.0.255", iptable.mask(iptable.AF_INET, -24));

      assert.equal("255.255.0.0", iptable.mask(iptable.AF_INET, 16));
      assert.equal("0.0.255.255", iptable.mask(iptable.AF_INET, -16));

      assert.equal("255.0.0.0", iptable.mask(iptable.AF_INET, 8));
      assert.equal("0.255.255.255", iptable.mask(iptable.AF_INET, -8));

      assert.equal("128.0.0.0", iptable.mask(iptable.AF_INET, 1));
      assert.equal("127.255.255.255", iptable.mask(iptable.AF_INET, -1));
    end)

  end)
end)
