#!/usr/bin/env lua
-------------------------------------------------------------------------------
--  Description:  unit test file for iptable
-------------------------------------------------------------------------------

package.cpath = "./build/?.so;"

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

