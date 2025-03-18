package main

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/getlantern/lantern-cloud/cmd/pfe/xdptun"
	"github.com/stretchr/testify/require"
)

func TestParseMapFile(t *testing.T) {
	s := `
#EIP           Private IP     Tunnel Src     Tunnel Dest   Tunnel Port
192.168.2.150, 192.168.2.250, 192.168.2.150, 192.168.2.23
192.168.2.151, 192.168.2.251, 192.168.2.151, 192.168.2.24, 4444
10.10.10.1,    10.0.0.1,      10.10.10.1,    10.0.0.2
8.209.96.178,  10.10.27.254,  8.209.96.178,  136.144.49.65
8.209.116.190, 10.10.27.209,  fdb7:308b:be59:cefe::dead:beef, fdb7:308b:be59:cefe::1
`

	ipMap, err := parseIPMap(strings.NewReader(s))
	require.NoError(t, err)

	expected := map[netip.Addr]xdptun.AssociatedIPs{
		netip.MustParseAddr("192.168.2.250"): {
			EIP:          netip.MustParseAddr("192.168.2.150"),
			TunnelSource: netip.MustParseAddr("192.168.2.150"),
			TunnelDest:   netip.MustParseAddr("192.168.2.23"),
			TunnelPort:   5555,
		},
		netip.MustParseAddr("192.168.2.251"): {
			EIP:          netip.MustParseAddr("192.168.2.151"),
			TunnelSource: netip.MustParseAddr("192.168.2.151"),
			TunnelDest:   netip.MustParseAddr("192.168.2.24"),
			TunnelPort:   4444,
		},
		netip.MustParseAddr("10.0.0.1"): {
			EIP:          netip.MustParseAddr("10.10.10.1"),
			TunnelSource: netip.MustParseAddr("10.10.10.1"),
			TunnelDest:   netip.MustParseAddr("10.0.0.2"),
			TunnelPort:   5555,
		},
		netip.MustParseAddr("10.10.27.254"): {
			EIP:          netip.MustParseAddr("8.209.96.178"),
			TunnelSource: netip.MustParseAddr("8.209.96.178"),
			TunnelDest:   netip.MustParseAddr("136.144.49.65"),
			TunnelPort:   5555,
		},
		netip.MustParseAddr("10.10.27.209"): {
			EIP:          netip.MustParseAddr("8.209.116.190"),
			TunnelSource: netip.MustParseAddr("fdb7:308b:be59:cefe::dead:beef"),
			TunnelDest:   netip.MustParseAddr("fdb7:308b:be59:cefe::1"),
			TunnelPort:   5555,
		},
	}

	require.Equal(t, expected, ipMap)

	for _, line := range []string{
		"asdf,fdsa,nope",
		"asdf",
		"asdf,",
		"asdf,asdf",
		"asdf,asdf,",
		",,",
		"asdf,,",
		",asdf,",
		",,asdf",
		"192.168.540.3,1.1.1.1,2.2.2.2",
	} {
		ipMap, err = parseIPMap(strings.NewReader(line))
		require.Error(t, err)
	}
}
