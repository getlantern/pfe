package arp

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestCache(t *testing.T) {
	arpCache := &Cache{}

	neigh := netlink.Neigh{}
	neigh.LinkIndex = 0
	neigh.Family = unix.AF_INET
	neigh.State = unix.NUD_REACHABLE
	neigh.Type = netlink.NDA_DST
	neigh.IP = net.ParseIP("174.53.95.153")
	neigh.HardwareAddr = net.HardwareAddr{0xee, 0xff, 0xff, 0xff, 0xff, 0xff}
	arpCache.Update(neigh)

	ip := netip.MustParseAddr("174.53.95.153")
	n, found := arpCache.Get(ip)
	require.True(t, found)
	require.Equal(t, neigh.HardwareAddr, n)

	neigh.HardwareAddr = net.HardwareAddr{0, 1, 2, 3, 4, 5}
	arpCache.Update(neigh)
	n, found = arpCache.Get(ip)
	require.True(t, found)
	require.Equal(t, neigh.HardwareAddr, n)
}

func BenchmarkCache(b *testing.B) {
	cache := func() *Cache {
		b.Helper()
		arpCache := &Cache{}

		neigh := netlink.Neigh{}
		neigh.LinkIndex = 0
		neigh.Family = unix.AF_INET
		neigh.State = unix.NUD_REACHABLE
		neigh.Type = netlink.NDA_DST
		neigh.IP = net.ParseIP("174.53.95.153")
		neigh.HardwareAddr = net.HardwareAddr{0xee, 0xff, 0xff, 0xff, 0xff, 0xff}
		arpCache.Update(neigh)

		for i := 0; i < 10; i++ {
			neigh = netlink.Neigh{}
			neigh.LinkIndex = 0
			neigh.Family = unix.AF_INET
			neigh.State = unix.NUD_REACHABLE
			neigh.Type = netlink.NDA_DST
			neigh.IP = net.IPv4(10, 10, 10, byte(i))
			neigh.HardwareAddr = net.HardwareAddr{0, 0, 0, 0, 0, 0}
			arpCache.Update(neigh)
		}
		return arpCache
	}()

	ip := netip.MustParseAddr("174.53.95.153")
	for i := 0; i < b.N; i++ {
		_, found := cache.Get(ip)
		if !found {
			b.Fail()
		}
	}
}
