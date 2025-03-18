package xdptun

import (
	"net/netip"
	"sync/atomic"
)

const (
	fouHeaderLen int = 8 // An FOU header is really just a UDP header

	ipv4HeaderLen int = 20 // These could be longer, but we don't add options
	ipv6HeaderLen int = 40

	baseHeadroom int = ipv6HeaderLen // we make enough room to do IPv6 encap
	fouHeadroom  int = baseHeadroom + fouHeaderLen
)

type AssociatedIPs struct {
	EIP          netip.Addr
	TunnelSource netip.Addr
	TunnelDest   netip.Addr
	TunnelPort   uint16
}

type IPMap struct {
	ipMap atomic.Pointer[map[netip.Addr]AssociatedIPs]
}

func (m *IPMap) Load() *map[netip.Addr]AssociatedIPs {
	return m.ipMap.Load()
}

func (m *IPMap) Store(new *map[netip.Addr]AssociatedIPs) {
	m.ipMap.Store(new)
}

type TunnelType int

const (
	FOUTunnel TunnelType = iota
	GRETunnel
)
