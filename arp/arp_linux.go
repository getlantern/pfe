package arp

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/getlantern/lantern-cloud/log"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Resources:
// - http://www.policyrouting.com/iproute2.doc.html#ss9.4 (see the "ip neighbor show" section)
// - https://man7.org/linux/man-pages/man7/arp.7.html or just `man 7 arp` on a Linux machine
// - https://man7.org/linux/man-pages/man7/rtnetlink.7.html for the definition of the NUD_ constants

type CacheEntry struct {
	neigh              netlink.Neigh
	sweepsUntilReprobe int
}

type Cache struct {
	started bool
	cache   sync.Map

	done, stopUpdates chan struct{}
	updates           chan netlink.NeighUpdate
	link              netlink.Link

	ctx context.Context
}

func NewCache(ctx context.Context, link netlink.Link) (*Cache, error) {
	cache := Cache{
		link: link,
		// ctx:  log.With(ctx, "component", "arp cache"),
		ctx: ctx,
	}
	if err := cache.populateCache(); err != nil {
		return nil, err
	}

	return &cache, nil
}

func (c *Cache) Start() error {
	if c.started {
		return fmt.Errorf("arp cache already started")
	}

	log.Info(c.ctx, "arp cache starting")

	c.done = make(chan struct{})
	c.stopUpdates = make(chan struct{})
	c.updates = make(chan netlink.NeighUpdate)

	if err := netlink.NeighSubscribe(c.updates, c.stopUpdates); err != nil {
		return fmt.Errorf("error subscribing to arp updates: %w", err)
	}

	c.started = true

	go func() {
		ticker := time.NewTicker(time.Second * time.Duration(DefaultScanTime))

		for {
			select {
			case <-c.done:
				close(c.stopUpdates)
				log.Info(c.ctx, "arp cache stopped listening to updates")
				return
			case update := <-c.updates:
				switch update.Type {
				case unix.RTM_NEWNEIGH:
					log.Debug(c.ctx, "arp cache got a neighbor update",
						"ip", update.IP,
						"hwaddr", update.HardwareAddr,
						"link_idx", update.LinkIndex,
						"state", stateToString(update.State))
					c.Update(update.Neigh)
				case unix.RTM_DELNEIGH:
					log.Info(c.ctx, "arp cache not performing requested neighbor removal",
						"entry", update.IP)
				}
			case <-ticker.C:
				log.Info(c.ctx, "scanning arp cache")
				c.cache.Range(func(k, v any) bool {
					ip := k.(netip.Addr)
					entry := v.(CacheEntry)
					entry.sweepsUntilReprobe--
					if entry.sweepsUntilReprobe <= 0 ||
						entry.neigh.State == unix.NUD_NONE ||
						entry.neigh.State == unix.NUD_FAILED ||
						entry.neigh.State == unix.NUD_INCOMPLETE {

						c.ResolveMAC(ip, &entry)
					}
					c.cache.Store(k, entry)
					return true
				})
			}
		}
	}()

	c.started = true

	return nil
}

func (c *Cache) Stop() {
	if !c.started {
		return
	}

	log.Info(c.ctx, "arp cache stopping")
	close(c.done)
	c.started = false
}

func (c *Cache) Get(ip netip.Addr) (net.HardwareAddr, bool) {
	r, f := c.cache.Load(ip)

	if !f {
		return net.HardwareAddr{}, false
	}

	entry := r.(CacheEntry)
	if entry.neigh.State == unix.NUD_NONE ||
		entry.neigh.State == unix.NUD_FAILED ||
		entry.neigh.State == unix.NUD_INCOMPLETE {

		return net.HardwareAddr{}, false
	}

	return entry.neigh.HardwareAddr, f
}

func (c *Cache) Update(neigh netlink.Neigh) {
	expiry := MaxSweepsUntilReprobe
	ip, _ := netip.AddrFromSlice(neigh.IP)
	ip = ip.Unmap()

	r, found := c.cache.Load(ip)

	var entry CacheEntry
	if found {
		entry = r.(CacheEntry)
		entry.neigh = neigh
	} else {
		entry = CacheEntry{neigh: neigh}
	}

	switch neigh.State {
	case unix.NUD_NONE, unix.NUD_FAILED, unix.NUD_INCOMPLETE:
		expiry = 0
	case unix.NUD_PERMANENT, unix.NUD_NOARP, unix.NUD_REACHABLE:
		// we include "reachable" here because the network stack is already running a timer
		// counting down to switching the entry to "stale", so let's just let it tell us
		// when the state should change.
		expiry = math.MaxInt
	}

	entry.sweepsUntilReprobe = expiry
	c.cache.Store(ip, entry)
}

func (c *Cache) Set(ip net.IP, hwaddr net.HardwareAddr, state int) error {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return fmt.Errorf("not an IP: %v", ip)
	}
	addr = addr.Unmap()

	r, found := c.cache.Load(addr)

	var neigh *netlink.Neigh
	if found {
		entry := r.(CacheEntry)
		neigh = &entry.neigh

		if !ip.Equal(neigh.IP) {
			neigh.IP = ip
		}
		if !bytes.Equal(hwaddr, neigh.HardwareAddr) {
			neigh.HardwareAddr = hwaddr
		}
		neigh.State = state
	} else {
		neigh = &netlink.Neigh{}
		neigh.LinkIndex = c.link.Attrs().Index
		if ip.To4() != nil {
			neigh.Family = unix.AF_INET
		} else {
			neigh.Family = unix.AF_INET6
		}
		neigh.State = state
		neigh.Type = netlink.NDA_DST
		neigh.IP = ip
		neigh.HardwareAddr = hwaddr
	}

	return netlink.NeighSet(neigh)
}

func (c *Cache) PrintCache() {
	c.cache.Range(func(k, v any) bool {
		ip := k.(netip.Addr)
		entry := v.(CacheEntry)
		log.Info(c.ctx, "arp cache entry",
			"ip", ip,
			"hwaddr", entry.neigh.HardwareAddr,
			"state", stateToString(entry.neigh.State))
		return true
	})
}

func (c *Cache) populateCache() error {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		entries, err := netlink.NeighList(c.link.Attrs().Index, family)
		if err != nil {
			return fmt.Errorf("cannot populate arp cache: %w", err)
		}

		for _, entry := range entries {
			c.Update(entry)
		}
	}

	return nil
}

func stateToString(state int) string {
	switch state {
	case netlink.NUD_NONE:
		return "NONE"
	case netlink.NUD_INCOMPLETE:
		return "INCOMPLETE"
	case netlink.NUD_REACHABLE:
		return "REACHABLE"
	case netlink.NUD_STALE:
		return "STALE"
	case netlink.NUD_DELAY:
		return "DELAY"
	case netlink.NUD_PROBE:
		return "PROBE"
	case netlink.NUD_FAILED:
		return "FAILED"
	case netlink.NUD_NOARP:
		return "NOARP"
	case netlink.NUD_PERMANENT:
		return "PERMANENT"
	default:
		return "???"
	}
}

func (c *Cache) ResolveMAC(requestIP netip.Addr, entry *CacheEntry) error {
	if requestIP.Is6() {
		return nil
	}

	var neigh *netlink.Neigh

	if entry != nil {
		neigh = &entry.neigh
		neigh.State = netlink.NUD_PROBE
	} else {
		e, found := c.cache.Load(requestIP)
		if found {
			entry := e.(CacheEntry)
			neigh = &entry.neigh
			if neigh.State == netlink.NUD_INCOMPLETE || neigh.State == netlink.NUD_FAILED {
				neigh.HardwareAddr = []byte{0, 0, 0, 0, 0, 0}
			}
		} else {
			neigh = &netlink.Neigh{}
			neigh.LinkIndex = c.link.Attrs().Index
			if requestIP.Is4() {
				neigh.Family = unix.AF_INET
			} else {
				neigh.Family = unix.AF_INET6
			}
			neigh.State = netlink.NUD_INCOMPLETE
			neigh.Type = netlink.NDA_DST
			neigh.IP = net.IP(requestIP.AsSlice())
			neigh.HardwareAddr = []byte{0, 0, 0, 0, 0, 0}
		}
	}

	log.Info(c.ctx, "resolving MAC", "ip", requestIP, "current_hwaddr", neigh.HardwareAddr)

	if err := netlink.NeighSet(neigh); err != nil {
		return fmt.Errorf("error setting arp entry: %w", err)
	}

	if requestIP.Is4() {
		return sendARPRequest(c.ctx, c.link, requestIP)
	}
	return nil
}

func sendARPRequest(ctx context.Context, link netlink.Link, requestIP netip.Addr) error {
	// https://css.bz/2016/12/08/go-raw-sockets.html
	// NOTE: this is a very IPv4-only thing. IPv6 doesn't use ARP requests for discovery, but
	// instead uses ICMP Neighbor Discovery.
	addrs, err := netlink.AddrList(link, unix.AF_INET)
	if err != nil {
		return fmt.Errorf("error getting addresses on link: %w", err)
	}

	if len(addrs) == 0 {
		return fmt.Errorf("no addresses found on interface")
	}

	spa := addrs[0]
	sha := link.Attrs().HardwareAddr

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_ALL)
	if err != nil {
		return fmt.Errorf("error opening AF_PACKET socket for arp request: %w", err)
	}
	defer syscall.Close(fd)

	pkt := make([]byte, 42)
	copy(pkt, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) // destination MAC
	copy(pkt[6:], sha)                                    // source MAC
	copy(pkt[12:], []byte{0x08, 0x06})                    // EtherType == ARP

	arp := pkt[14:]
	copy(arp, []byte{
		0x00, 0x01, // HTYPE == Ethernet
		0x08, 0x00, // PTYPE == IPv4
		0x06,       // HLEN
		0x04,       // PLEN
		0x00, 0x01, // OPER == Request
	})
	copy(arp[8:], sha)                                         // SHA
	copy(arp[14:], spa.IP)                                     // SPA
	copy(arp[18:], []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) // THA
	copy(arp[24:], requestIP.AsSlice())                        // TPA

	addr := syscall.SockaddrLinklayer{
		Protocol: syscall.ETH_P_ARP,
		Ifindex:  2,
		Hatype:   syscall.ARPHRD_ETHER,
	}

	log.Debug(ctx, "sending arp request", "request_ip", requestIP, "link", link.Attrs().Name)
	err = syscall.Sendto(fd, pkt, 0, &addr)
	if err != nil {
		return fmt.Errorf("error sending arp request: %w", err)
	}

	return nil
}
