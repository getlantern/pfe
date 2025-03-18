package xdptun

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	clog "github.com/getlantern/lantern-cloud/cmd/pfe/conditional_log"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/Crosse/xdp"
	"github.com/getlantern/lantern-cloud/cmd/pfe/arp"
	"github.com/getlantern/lantern-cloud/log"
	"github.com/getlantern/lantern-cloud/metrics"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
	"github.com/vishvananda/netlink"
	"go.uber.org/atomic"
	"golang.org/x/sys/unix"
)

const (
	ChecksumSampleCount      uint64  = 1000
	InvalidChecksumThreshold float64 = 0.10
)

type Statistics struct {
	Started              time.Time
	RxFrames             uint64
	RxBytes              uint64
	TxFrames             uint64
	TxBytes              uint64
	DroppedFrames        uint64
	DroppedBytes         uint64
	RuntFrames           uint64
	ShortPackets         uint64
	ARPCacheMisses       uint64
	IgnoredEtherType     uint64
	InvalidIPVersion     uint64
	BackendPackets       uint64
	DroppedJumbograms    uint64
	AvgPacketServiceTime float64

	ProtoIPv4    uint64
	ProtoIPv6    uint64
	ProtoICMP    uint64
	ProtoTCP     uint64
	ProtoUDP     uint64
	ProtoSCTP    uint64
	ProtoUDPLite uint64
	ProtoOther   uint64

	XDPStats xdp.Stats
}

type Tunnel struct {
	link       netlink.Link
	linkMTU    int
	xdpMode    uint32
	arpCache   *arp.Cache
	sourcePort uint16
	ifaceAddrs []net.IP
	Gateway4   netip.Addr
	Gateway6   netip.Addr
	Headroom   int
	localNets  []*net.IPNet

	ipMap   IPMap
	queue   int
	sock    *Socket
	running atomic.Bool
	stats   Statistics

	doFastChecksums  bool
	invalidChecksums uint64

	pcapf *os.File
	pcapw *pcapgo.NgWriter

	egressLink   netlink.Link
	egressSocket int

	ctx context.Context
}

func NewTunnel(ctx context.Context, link netlink.Link, queue int, mode uint32) (*Tunnel, error) {
	tunnel := Tunnel{
		link:    link,
		linkMTU: link.Attrs().MTU,
		queue:   queue,
		xdpMode: mode,
		ctx:     ctx,
	}

	initialMap := make(map[netip.Addr]AssociatedIPs)
	tunnel.ipMap.Store(&initialMap)

	tunnel.Headroom = fouHeadroom

	v4Addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("cannot enumerate IPv4 addresses: %w", err)
	}

	v6Addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
	if err != nil {
		return nil, fmt.Errorf("cannot enumerate IPv6 addresses: %v", err)
	}
	addrs := make([]netlink.Addr, 0, len(v4Addrs)+len(v6Addrs))
	addrs = append(addrs, v4Addrs...)
	addrs = append(addrs, v6Addrs...)

	tunnel.localNets = make([]*net.IPNet, 0, len(v4Addrs))
	for _, addr := range addrs {
		clog.Debug(ctx, "found IP address on interface", "ip", addr.IP)
		tunnel.ifaceAddrs = append(tunnel.ifaceAddrs, addr.IP)
		if addr.IPNet != nil {
			found := false
			for _, net := range tunnel.localNets {
				if net.Contains(addr.IP) {
					found = true
					break
				}
			}
			if !found {
				tunnel.localNets = append(tunnel.localNets, addr.IPNet)
			}
		}
	}

	minPort := 49152
	tunnel.sourcePort = uint16(rand.Intn(65536-minPort) + minPort)
	log.Info(ctx, "source port for tunnel encapsulation", "port", tunnel.sourcePort)

	tunnel.arpCache, err = arp.NewCache(ctx, link)
	if err != nil {
		return nil, fmt.Errorf("initializing ARP cache: %w", err)
	}

	return &tunnel, nil
}

func (t *Tunnel) Stop() {
	log.Info(t.ctx, "stopping tunnel")
	t.running.Store(false)
}

func (t *Tunnel) Close() error {
	log.Info(t.ctx, "closing tunnel")
	t.Stop()
	t.arpCache.Stop()

	if t.pcapw != nil {
		t.pcapw.Flush()
	}
	if t.pcapf != nil {
		t.pcapf.Close()
	}

	if t.egressLink != nil {
		syscall.Close(t.egressSocket)
	}

	return t.sock.Close()
}

func (t *Tunnel) StartPCAPLogging() error {
	if t.pcapw != nil {
		return nil
	}

	filename := fmt.Sprintf("pfe-%d-%d.pcapng", os.Getpid(), time.Now().Unix())
	pcapf, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("creating %s: %w", filename, err)
	}

	pcapw, err := pcapgo.NewNgWriter(pcapf, 1) // I don't feel like pulling in gopacket/layers
	if err != nil {
		pcapf.Close()
		return fmt.Errorf("initializing %s: %w", filename, err)
	}

	t.pcapf = pcapf
	t.pcapw = pcapw

	log.Info(t.ctx, "pcap logging enabled", "filename", filename)
	return nil
}

func (t *Tunnel) CopyPacketsToInterface(link netlink.Link) error {
	if t.egressLink != nil {
		log.Info(t.ctx, "closing previous egress socket")
		syscall.Close(t.egressSocket)
		t.egressSocket = 0
		t.egressLink = nil
	}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_ALL)
	if err != nil {
		return err
	}

	if t.arpCache != nil {
		t.arpCache.Stop()
	}
	t.arpCache, err = arp.NewCache(t.ctx, link)
	if err != nil {
		syscall.Close(fd)
		return fmt.Errorf("re-initializing ARP cache: %w", err)
	}

	t.egressSocket = fd
	t.egressLink = link

	log.Info(t.ctx, fmt.Sprintf("will copy packets to interface %s", link.Attrs().Name))

	return nil
}

func (t *Tunnel) Link() netlink.Link {
	return t.link
}

func (t *Tunnel) SetIPMap(ipMap *map[netip.Addr]AssociatedIPs) {
	t.ipMap.Store(ipMap)
	log.Info(t.ctx, "set new IP map", "ip_mappings", *ipMap)
}

func (t *Tunnel) DiscoverGateway4() error {
	return t.discoverGateway(unix.AF_INET)
}

func (t *Tunnel) DiscoverGateway6() error {
	return t.discoverGateway(unix.AF_INET6)
}

func (t *Tunnel) discoverGateway(family int) error {
	ver := "IPv4"
	if family == unix.AF_INET6 {
		ver = "IPv6"
	}

	valid := false
	for _, ip := range t.ifaceAddrs {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			return fmt.Errorf("cannot convert %v to an IP address", ip)
		}
		if addr.Is4() && family == unix.AF_INET {
			valid = true
			break
		}
		if addr.Is6() && family == unix.AF_INET6 {
			valid = true
			break
		}
	}
	if !valid {
		log.Info(t.ctx,
			fmt.Sprintf("skipping gateway discovery: no %s addresses found on interface", ver))
		return nil
	}

	log.Info(t.ctx, fmt.Sprintf("attempting to discover the default %s gateway", ver))
	routes, err := netlink.RouteListFiltered(family, nil, 0)
	if err != nil {
		return fmt.Errorf("cannot enumerate routing table: %w", err)
	}

	var gw net.IP
	for _, route := range routes {
		// There is the possibility that a route has multiple paths to get to the gateway
		// address; for instance, if you have IP addresses in the same subnet on different
		// interfaces, you might see one route with multiple paths. This makes it somewhat
		// more difficult to suss out the default path, because now we have to check
		// `route.Gw` _and_ `route.MultiPath` and use the correct one. (Thankfully it looks
		// like if one is in use then the other is nil.) Additionally for the NextHopInfo
		// objects in `route.MultiPath`, each one tells you which link the route uses; we
		// want to make sure we pick out the one for the interface we're using.
		if route.Dst == nil && (route.Gw != nil || route.MultiPath != nil) {
			gw = route.Gw
			if gw == nil {
				egressLink := t.egressLink
				if egressLink == nil {
					egressLink = t.link
				}
				for _, nhi := range route.MultiPath {
					if nhi.LinkIndex == egressLink.Attrs().Index {
						gw = nhi.Gw
						break
					}
				}
			}

			if gw == nil {
				continue
			}

			log.Info(t.ctx, fmt.Sprintf("found default %s gateway", ver), "ip", gw)
			if family == unix.AF_INET {
				t.Gateway4, _ = netip.AddrFromSlice(gw)
			} else {
				t.Gateway6, _ = netip.AddrFromSlice(gw)
			}
			break
		}
	}

	if gw == nil {
		return fmt.Errorf("gateway discovery failed")
	}

	return nil
}

func (t *Tunnel) Stats() (Statistics, error) {
	var err error

	if t.sock == nil || t.sock.XSK == nil {
		msg := "can't get kernel status because the XDP socket is not fully initialized! The packet loop is probably not running"
		log.Error(t.ctx, msg, errors.New(msg))
	} else {
		if t.stats.XDPStats, err = t.sock.XSK.Stats(); err != nil {
			return Statistics{}, err
		}
	}
	return t.stats, nil
}

func (t *Tunnel) Redirect() error {
	t.stats.Started = time.Now()

	err := t.arpCache.Start()
	if err != nil {
		return fmt.Errorf("error starting ARP cache: %w", err)
	}

	log.Info(t.ctx, "Sending preemptive ARP requests for gateways")
	for _, gw := range []netip.Addr{t.Gateway4, t.Gateway6} {
		if gw.IsValid() && !gw.IsUnspecified() {
			if err := t.arpCache.ResolveMAC(gw, nil); err != nil {
				return fmt.Errorf("error resolving MAC for %s: %w", gw, err)
			}
		}
	}

	// Loop through all of the back-end IP addresses and see if they are in one of the networks
	// that are directly accessible via this NIC. If so, we'll preemptively send an ARP request
	// so that we can have a fresh entry when the time comes.
	log.Info(t.ctx, "Sending preemptive ARP requests for tunnel destination IPs")
	for _, v := range *t.ipMap.Load() {
		for _, n := range t.localNets {
			if n.Contains(net.IP(v.TunnelDest.AsSlice())) {
				if err := t.arpCache.ResolveMAC(v.TunnelDest, nil); err != nil {
					return fmt.Errorf("error resolving MAC for %s: %w", v.TunnelDest, err)
				}
				break
			}
		}
	}

	t.arpCache.PrintCache()

	if t.egressLink != nil {
		cancel := t.startGARPs()
		defer cancel()
	}

	log.Info(t.ctx, "opening XDP socket")
	t.sock, err = newSocket(t.ctx, t.link, t.queue, t.xdpMode, t.Headroom)
	if err != nil {
		return fmt.Errorf("error setting up XDP socket: %w", err)
	}

	var rxDescs []xdp.Desc
	var currentDesc *xdp.Desc
	txDescs := make([]xdp.Desc, 0, 64)
	noopDescs := make([]xdp.Desc, 0, 64)

	xsk := t.sock.XSK

	polls := 0

	// Down below we use 'skip' with the frame counter so that we only gather statistics on
	// packet service times every so often. It is too expensive to get the current timestamp on
	// every packet, since it's a syscall every time.
	skip := uint64(256 * 1024)
	var start time.Time

	defer func() {
		if e := recover(); e != nil {
			frame := "invalid"
			if currentDesc != nil {
				frame = frameToHex(xsk.GetFrameWithHeadroom(*currentDesc))
			}
			msg := "panicked while processing packets"
			log.Error(t.ctx, msg, errors.New(msg), "error", e, "frame", frame, "stack", string(debug.Stack()))
			// Doing this means we'll see the panic twice in the systemd journal, but
			// only once in Google Cloud Logging.
			log.Flush()
			panic(e)
		}
	}()

	log.Info(t.ctx, "starting packet loop")
	t.running.Store(true)
	for t.running.Load() {
		xsk.Fill(xsk.GetDescs(xsk.NumFreeFillSlots(), true))
		numRx, _, err := xsk.Poll(250)
		if err != nil {
			return err
		}
		polls++

		rxDescs = xsk.Receive(numRx)
		txDescs = txDescs[:0]
		noopDescs = noopDescs[:0]

		for i := 0; i < len(rxDescs); i++ {
			currentDesc = &rxDescs[i]

			t.stats.RxFrames++
			t.stats.RxBytes += uint64(currentDesc.Len)

			if t.stats.RxFrames%skip == 0 {
				start = time.Now()
			}

			shouldTx, err := t.handlePacket(currentDesc, t.ipMap.Load())
			if err != nil {
				return fmt.Errorf("error handling frame: %w", err)
			}

			if shouldTx {
				clog.Trace(t.ctx, "adding frame to the tx ring")
				txDescs = append(txDescs, *currentDesc)
				t.stats.TxFrames++
				t.stats.TxBytes += uint64(currentDesc.Len)
			} else {
				clog.Debug(t.ctx, "dropping frame")
				noopDescs = append(noopDescs, *currentDesc)
				t.stats.DroppedFrames++
				t.stats.DroppedBytes += uint64(currentDesc.Len)
			}

			if t.stats.RxFrames%skip == 0 {
				elapsed := time.Since(start).Nanoseconds()
				metrics.RecordDistribution(context.Background(), "pfe.packet.duration", elapsed)
			}
		}
		if len(txDescs)+len(noopDescs) != len(rxDescs) {
			panic("wat")
		}

		if t.egressLink == nil {
			xsk.Transmit(txDescs)
		} else {
			for _, desc := range txDescs {
				frame := xsk.GetFrame(desc)
				if err := t.afpacketSend(frame); err != nil {
					log.Error(t.ctx, "cannot send afpacket", err)
				}
			}
			xsk.Fill(txDescs)
		}

		xsk.Fill(noopDescs)
	}

	log.Info(t.ctx, "main packet loop done, shutting down")
	t.Stop()
	return nil
}

func (t *Tunnel) afpacketSend(frame []byte) error {
	if t.egressLink == nil {
		panic("call to afpacketSend() before CopyPacketsToInterface()")
	}

	addr := syscall.SockaddrLinklayer{
		Protocol: syscall.ETH_P_IPV6,
		Ifindex:  t.egressLink.Attrs().Index,
	}

	if err := syscall.Sendto(t.egressSocket, frame, 0, &addr); err != nil {
		return fmt.Errorf("sendto: %w", err)
	}

	return nil
}

func (t *Tunnel) handlePacket(desc *xdp.Desc, ipMap *map[netip.Addr]AssociatedIPs) (bool, error) {
	xsk := t.sock.XSK
	frame := xsk.GetFrameWithHeadroom(*desc)

	// NOTE: We ask for the frame data in this descriptor to have a certain amount of headroom
	// prepended to it. The way XDP handles this is that we tell it how much headroom to leave
	// in each packet, and it copies packets into the skb starting at that offset. (See
	// `xdp.SocketOptions` in newSocket(), in socket_linux.go.) When pfe first starts up, all
	// the memory used will be zeroed out (or it will come from zero pages? I don't know *waves
	// hands in Operating Systems Theory*). HOWEVER, after pfe has processed enough packets that
	// XDP starts to reuse the descriptors, you will notice that the headroom in a frame
	// _already has data in it_. This is normal. XDP will not explicitly zero out the frame
	// before writing packet data into it, because that would require a 2KiB write for every
	// packet, which is...not performant.
	//
	// tl;dr: don't worry if your frame comes prefilled with data in the headroom (and possibly
	// trailing data, if the current packet is shorter than the one it replaced in the
	// descriptor!), but also DO NOT READ ANY OF THE DATA THAT ISN'T PART OF THE PACKET, UNLESS
	// YOU JUST WROTE THAT DATA.

	clog.Trace(t.ctx, "handling packet",
		"frame_offset", desc.Addr,
		"frame_length", desc.Len,
		"packet_len", len(frame))

	if len(frame) < t.Headroom {
		err := fmt.Errorf("detected frame smaller than Headroom, with length %d!", len(frame))
		return false, err
	}

	data := frame[t.Headroom:]

	if t.pcapw != nil {
		err := t.pcapw.WritePacket(gopacket.CaptureInfo{
			Timestamp:      time.Now(),
			CaptureLength:  int(desc.Len),
			Length:         int(desc.Len),
			InterfaceIndex: 0,
		}, data)
		if err != nil {
			log.Error(t.ctx, "pcap: while dumping orignal packet", err)
		}
	}

	if len(data) < 14 {
		// Ethernet frames must be 60 bytes or larger. Frames that are shorter must have
		// padding added to the end when sent on the wire. However, it appears that frames
		// that originate on one VM going to another VM on the same host may not have this
		// padding. Since that is the case, we relax the limit and just ensure we have
		// enough to make a full Ethernet header, and go from there.
		clog.Debug(t.ctx, "dropping runt frame", "frame_length", len(data))
		t.stats.RuntFrames++
		return false, nil
	}

	var shouldTx bool
	var err error

	// ...but if we have an Ethernet header, then we have an EtherType and can use that.
	// XXX: we assume there are no VLAN headers.
	ethertype := binary.BigEndian.Uint16(data[12:14])
	switch ethertype {
	case unix.ETH_P_IP:
		shouldTx, err = t.handleIP(desc, frame, ipMap)
	case unix.ETH_P_ARP:
		// ARP doesn't need the headroom because it reuses the request in-place as the reply
		frame = frame[t.Headroom:]
		shouldTx, err = t.handleARP(frame, t.ifaceAddrs)
	default:
		// drop it on the floor?
		// NOTE: to my future self, if you see a value of 0x0027 for the EtherType, it's
		// actually an 802.3 Spanning Tree frame and 0x0027 is the length field. Just a
		// curiosity. Go on with your day now.
		// (If this isn't guarded on log.Level(), Go will format the EtherType as a hex
		// string on every packet before it knows whether it's going to actually print it
		// out.)
		clog.Debug(t.ctx, "dropping ignored ethertype",
			"ethertype", fmt.Sprintf("0x%04x", ethertype))
		t.stats.IgnoredEtherType++
		return false, nil
	}

	if shouldTx && err == nil {
		if t.pcapw != nil {
			err := t.pcapw.WritePacket(gopacket.CaptureInfo{
				Timestamp:      time.Now(),
				CaptureLength:  int(desc.Len),
				Length:         int(desc.Len),
				InterfaceIndex: 0,
			}, frame)
			if err != nil {
				log.Error(t.ctx, "pcap: while dumping modified packet", err, "frame", frameToHex(frame))
			}
		}
	}

	return shouldTx, err
}

func (t *Tunnel) handleIP(desc *xdp.Desc, frame []byte, ipMap *map[netip.Addr]AssociatedIPs) (bool, error) {
	data := frame[t.Headroom:]

	ipOfs := 14
	ipHdr := data[ipOfs:]
	ipVersion := (ipHdr[0] & 0xf0) >> 4
	switch ipVersion {
	case 4:
		t.stats.ProtoIPv4++
		return t.handleIPv4(desc, frame, ipMap)
	case 6:
		t.stats.ProtoIPv6++
		return false, errors.New("IPv6 from clients is not yet supported")
	default:
		clog.Debug(t.ctx, "dropping packet with invalid IP version", "version", ipVersion)
		t.stats.InvalidIPVersion++
		return false, fmt.Errorf("invalid IP version %d", ipVersion)
	}
}

func (t *Tunnel) handleIPv4(desc *xdp.Desc, frame []byte, ipMap *map[netip.Addr]AssociatedIPs) (bool, error) {
	data := frame[t.Headroom:]

	ipOfs := 14
	ipHdr := data[ipOfs:]

	// Look, if the IP header was somehow not intact, this packet never would have arrived at
	// our doorstep.
	//
	// ...we do, however, just want to check that things are kosher because we're going to need
	// to check bytes beyond this header in a moment. (Note: the minimum length of an IPv4
	// packet is 20 bytes, because the minimum length of the IPv4 header is 20 bytes.)
	if len(ipHdr) < 20 {
		clog.Debug(t.ctx, "dropping short IPv4 packet", "packet_length", len(ipHdr))
		t.stats.ShortPackets++
		return false, nil
	}

	proto := ipHdr[9]
	srcIP := netip.AddrFrom4(*(*[4]byte)(ipHdr[12:16])) // client external IP
	dstIP := netip.AddrFrom4(*(*[4]byte)(ipHdr[16:20])) // our private IP

	v, found := (*ipMap)[dstIP]
	if !found {
		clog.Trace(t.ctx, "no mapping found for dest ip", "ip", dstIP)
		return false, nil
	}

	// Drop any packet that would be larger than the tunnel's MTU after encapsulation.  This
	// seems to be what happens normally instead of the destination host sending back ICMP type
	// 3, code 4 (Fragmentation required, and DF flag set). I assume only routers send that
	// back, and we're explicitly pretending to *not* be a router.
	encapLen := ipv4HeaderLen
	if v.TunnelDest.Is6() {
		encapLen = ipv6HeaderLen
	}
	encapLen += fouHeaderLen

	if len(ipHdr)+encapLen > t.linkMTU {
		clog.Debug(t.ctx, "dropping jumbogram", "packet_length", len(ipHdr))
		t.stats.DroppedJumbograms++
		return false, nil
	}

	if srcIP == v.TunnelDest {
		// The back-end shouldn't be talking to us. If it is, we've probably screwed up
		// somehow and it's either dutifully sending us packets it thinks we want, or it's
		// trying to tell us just how badly we screwed up.
		clog.Debug(t.ctx, "possible packet loop detected, dropping frame")
		t.stats.BackendPackets++
		return false, nil
	}

	switch proto {
	case unix.IPPROTO_ICMP:
		t.stats.ProtoICMP++
		t.logICMP(desc, frame, srcIP)
	case unix.IPPROTO_TCP:
		t.stats.ProtoTCP++
	case unix.IPPROTO_UDP:
		t.stats.ProtoUDP++
	case unix.IPPROTO_SCTP:
		t.stats.ProtoSCTP++
	case unix.IPPROTO_UDPLITE:
		t.stats.ProtoUDPLite++
	default:
		t.stats.ProtoOther++
	}

	// passed all the tests, so it's time to rewrite!

	frameOfs := 0
	if v.TunnelDest.Is4() {
		// Our IPv4 and IPv6 tunnels have different header lengths, so if this is going to
		// be encapsulated in an IPv4 tunnel let's go ahead and move the start of the frame
		// up by the difference.
		frameOfs = ipv6HeaderLen - ipv4HeaderLen
		frame = frame[frameOfs:]
	}

	clog.Debug(t.ctx, "rewriting packet",
		"outer_saddr", v.TunnelSource,
		"outer_daddr", v.TunnelDest,
		"inner_orig_saddr", dstIP,
		"inner_new_saddr", v.EIP)

	if t.stats.TxFrames < ChecksumSampleCount {
		valid := verifyChecksum(ipHdr)
		if !valid {
			t.invalidChecksums++
		}
	} else if t.stats.TxFrames == ChecksumSampleCount {
		invalidRatio := float64(t.invalidChecksums) / float64(ChecksumSampleCount)
		if invalidRatio <= InvalidChecksumThreshold {
			log.Info(t.ctx, "switching to fast checksums", "invalid_checksum_ratio", invalidRatio)
			t.doFastChecksums = true
		} else {
			msg := "invalid checksum ratio too high; cannot use fast checksums"
			log.Error(t.ctx, msg, errors.New(msg), "invalid_checksum_ratio", invalidRatio)
		}
	}

	// If we have an Ethernet header, we need to copy it to the beginning of the frame,
	// at the beginning of our headroom. We need to do this first so that we don't lose
	// the values.

	// destination | source | ethertype
	// --> becomes...
	// source | destination | ethertype

	// Here's the order of operations: first we need to query ARP to see if we have an
	// entry for the back-end IP (which means it's in the same broadcast domain). If
	// there isn't an entry, then we look for the default gateway in ARP and use that
	// instead, because apparently we can't get directly to the back-end ourselves. If,
	// for whatever reason, we can't find the gateway's MAC address in the ARP cache, we
	// fall back to simply reversing the source and destination MACs, on the assumption
	// that the device that sent us the packet *is* a gateway device.
	clog.Trace(t.ctx, "getting MAC address from cache", "ip", v.TunnelDest)
	hwaddr, found := t.arpCache.Get(v.TunnelDest)
	if !found {
		// Try to use the gateway instead.
		if v.TunnelDest.Is4() {
			hwaddr, found = t.arpCache.Get(t.Gateway4)
		} else {
			hwaddr, found = t.arpCache.Get(t.Gateway6)
		}
	}

	if !found {
		// ARP didn't help us out, so just use the old source as the new
		// dest and pretend that will work.
		// XXX: other lb products will drop packets instead.
		clog.Debug(t.ctx, "MAC not found in cache", "ip", v.TunnelDest)
		t.stats.ARPCacheMisses++
		copy(frame[0:6], data[6:12]) // old source -> new destination
	} else {
		// The ARP cache came through for us!
		copy(frame[0:6], hwaddr)
	}

	if t.egressLink == nil {
		copy(frame[6:12], data[0:6]) // old dest -> new source
	} else {
		// We need to use the MAC address of the egress interface instead.
		copy(frame[6:12], t.egressLink.Attrs().HardwareAddr)
	}

	// Set the correct Ethertype
	if v.TunnelDest.Is4() {
		binary.BigEndian.PutUint16(frame[12:14], unix.ETH_P_IP)
	} else {
		binary.BigEndian.PutUint16(frame[12:14], unix.ETH_P_IPV6)
	}

	// fix the destination IP of the (soon-to-be) encapsulated packet to be the EIP, not the private IP.
	copy(ipHdr[16:20], v.EIP.AsSlice())
	chksum := computeIPv4Checksum(ipHdr)
	binary.BigEndian.PutUint16(ipHdr[10:], chksum)

	fragOfs := binary.BigEndian.Uint16(ipHdr[6:8]) & 0x1f
	ipHdrLen := int(ipHdr[0]&0xf) * 4

	// This fixes up the UDP and TCP checksums, but only for initial segments--if the fragment
	// offset is zero, it indicates that the IP payload is the either the full datagram or the
	// first fragment of a multi-fragment datagram. Since the TCP/UDP header exists only in the
	// first fragment, we need to make sure we update that one and no subsequent fragments.
	//
	// Note that SCTP's checksum doesn't cover any fields from the IP header, so we don't have
	// to modify it at all.
	if fragOfs == 0 {
		switch proto {
		case unix.IPPROTO_TCP:
			// The shortest a TCP header can be is 20 bytes.
			if len(ipHdr) < ipHdrLen+20 {
				clog.Debug(t.ctx, "Dropping short TCP segment", "segment_length", len(ipHdr[ipHdrLen:]))
				t.stats.ShortPackets++
				return false, nil
			}

			// Checksum is at byte offset 16 in the TCP header.
			var chksum uint16
			if t.doFastChecksums {
				hc := binary.BigEndian.Uint16(ipHdr[ipHdrLen+16:])
				m := binary.BigEndian.Uint32(dstIP.AsSlice())
				mp := binary.BigEndian.Uint32(v.EIP.AsSlice())
				chksum = fastChecksumRecompute(hc, m, mp)
			} else {
				chksum = computeLayer4Checksum(ipHdr)
			}
			binary.BigEndian.PutUint16(ipHdr[ipHdrLen+16:], uint16(chksum))
		case unix.IPPROTO_UDP:
			// The shortest a UDP packet can be is 8 bytes; i.e., just the header.
			if len(ipHdr) < ipHdrLen+8 {
				clog.Debug(t.ctx, "Dropping short UDP segment", "segment_length", len(ipHdr[ipHdrLen:]))
				t.stats.ShortPackets++
				return false, nil
			}

			// Checksum is at byte offset 6 in the UDP header.
			var chksum uint16
			if t.doFastChecksums {
				hc := binary.BigEndian.Uint16(ipHdr[ipHdrLen+6:])
				m := binary.BigEndian.Uint32(dstIP.AsSlice())
				mp := binary.BigEndian.Uint32(v.EIP.AsSlice())
				chksum = fastChecksumRecompute(hc, m, mp)
			} else {
				chksum = computeLayer4Checksum(ipHdr)
			}
			binary.BigEndian.PutUint16(ipHdr[ipHdrLen+6:], uint16(chksum))
		}
	}

	// the new IP header starts right after the ethernet header.
	t.encapsulateFOU(frame[ipOfs:], v.TunnelSource, v.TunnelDest, t.sourcePort, v.TunnelPort)

	// Fix up the addr and len so that XDP knows about our added headers.
	desc.Addr -= uint64(t.Headroom - frameOfs)
	desc.Len += uint32(t.Headroom - frameOfs)

	return true, nil
}

func (t *Tunnel) logICMP(desc *xdp.Desc, frame []byte, srcIP netip.Addr) {
	ipOfs := 14
	ipLen := int(frame[t.Headroom+ipOfs]&0xf) * 4

	icmp := frame[t.Headroom+ipOfs+ipLen:]

	switch icmp[0] {
	case 3:
		// destination unreachable. This is mostly for debugging.
		switch icmp[1] {
		case 0:
			clog.Debug(t.ctx, "icmp: destination network unreachable", "ip", srcIP)
		case 1:
			clog.Debug(t.ctx, "icmp: destination host unreachable", "ip", srcIP)
		case 2:
			clog.Debug(t.ctx, "icmp: destination protocol unreachable", "ip", srcIP)
		case 3:
			clog.Debug(t.ctx, "icmp: destination port unreachable", "ip", srcIP)
		default:
			clog.Debug(t.ctx, "icmp: destination unreachable", "ip", srcIP, "code", icmp[1])
		}
	case 8:
		clog.Debug(t.ctx, "icmp: echo request", "ip", srcIP)
	case 11:
		switch icmp[1] {
		case 0:
			clog.Debug(t.ctx, "icmp: time to live exceeded", "ip", srcIP)
		case 1:
			clog.Debug(t.ctx, "icmp: fragment reassembly time exceeded", "ip", srcIP)
		}
	default:
		clog.Debug(t.ctx, "icmp: unknown message", "ip", srcIP, "type", icmp[0], "code", icmp[1])
	}
}

func (t *Tunnel) handleARP(frame []byte, addrs []net.IP) (bool, error) {
	arpPkt := frame[14:]

	if len(arpPkt) < 28 { // length of an ARP packet
		clog.Debug(t.ctx, "dropping short ARP packet", "length", frame)
		t.stats.ShortPackets++
		return false, nil
	}

	// HTYPE. Ethernet == 1
	htype := binary.BigEndian.Uint16(arpPkt[0:2])
	if htype != unix.ARPHRD_ETHER {
		// not an Ethernet frame. Wat
		clog.Trace(t.ctx, "arp: unhandled HTYPE", "htype", htype)
		return false, nil
	}

	// PTYPE. IPv4 == 0x0800
	ptype := binary.BigEndian.Uint16(arpPkt[2:4])
	if ptype != unix.ETH_P_IP {
		// not an IPv4 ARP request. IPv6 uses ICMP Neighbor Discovery instead of ARP, so
		// anything non-IPv4 is probably something we don't want to handle.
		// (If this isn't guarded on log.Level(), Go will format the PTYPE as a hex string
		// on every ARP packet before it knows whether it's going to actually print it out.)
		clog.Trace(t.ctx, "arp: unhandled PTYPE", "ptype", fmt.Sprintf("0x%04x", ptype))
		return false, nil
	}

	// HLEN and PLEN. MACs are 6 bytes and IPv4 addresses are 4
	if arpPkt[4] != 6 || arpPkt[5] != 4 {
		// Okay, things are just getting weird.
		clog.Trace(t.ctx, "arp: invalid HLEN or PLEN", "hlen", arpPkt[4], "plen", arpPkt[5])
		return false, nil
	}

	sha := arpPkt[8:14]
	spa := net.IP(arpPkt[14:18])
	tpa := net.IP(arpPkt[24:28])
	oper := binary.BigEndian.Uint16(arpPkt[6:8])

	switch oper {
	case 1:
		clog.Debug(t.ctx, "got arp request", "tpa", tpa, "spa", spa)
	case 2:
		hwaddr := net.HardwareAddr(sha)
		clog.Debug(t.ctx, "got arp reply", "spa", spa, "hwaddr", hwaddr)
		t.arpCache.Set(spa, hwaddr, unix.NUD_REACHABLE)
		return false, nil
	default:
		clog.Trace(t.ctx, "arp: invalid OPER", "oper", oper)
		return false, nil
	}

	mine := false
	for _, addr := range addrs {
		if tpa.Equal(addr) {
			mine = true
			break
		}
	}

	if !mine {
		return false, nil
	}

	clog.Debug(t.ctx, "arp: responding to request for my IP",
		"tpa", tpa, "hwaddr", t.link.Attrs().HardwareAddr)
	// ARP requests and replies are the the same length, so we can simply reuse the original
	// packet in-place and not have to twiddle the desc's Addr or Len.
	binary.BigEndian.PutUint16(arpPkt[6:8], 2) // 2 == reply
	temp := make([]byte, 4)
	copy(temp, arpPkt[24:28])                       // save the original TPA
	copy(arpPkt[18:24], arpPkt[8:14])               // SHA -> THA
	copy(arpPkt[24:28], arpPkt[14:18])              // SPA -> TPA
	copy(arpPkt[14:18], temp)                       // TPA -> SPA
	copy(arpPkt[8:14], t.link.Attrs().HardwareAddr) // interface MAC -> SHA

	// rewrite the Ethernet header
	copy(frame[0:6], frame[6:12])
	copy(frame[6:12], t.link.Attrs().HardwareAddr)

	return true, nil
}

// encapsulateFOU() takes a byte slice representing a packet, with some amount of padding prepended
// to it, and "encapsulates" the original packet in a FoU-over-IPv{4,6} tunnel. The byte slice must
// have enough padding at the beginning of it for the tunnel's IP and UDP header. It modifies the
// packet in-place, using the extra padding to prepend the tunnel headers. See
// encapsulateIPv{4,6}FOU() for more details.
func (t *Tunnel) encapsulateFOU(pkt []byte, srcIp, dstIp netip.Addr, srcPort, dstPort uint16) {
	if dstIp.Is4() {
		t.encapsulateIPv4FOU(pkt, srcIp, dstIp, srcPort, dstPort)
	} else {
		t.encapsulateIPv6FOU(pkt, srcIp, dstIp, srcPort, dstPort)
	}
}

// encapsulateIPv4FOU() takes a byte slice representing a packet, with some amount of padding
// prepended to it, and "encapsulates" the original packet in an FoU-over-IPv4 tunnel. The byte
// slice must have enough padding at the beginning of it for the tunnel's IPv4 and UDP headers. In
// our case, since we don't use any IPv4 options, this means there should be 20+8 bytes of padding
// at the beginning. It modifies the packet in-place, using the extra padding to prepend the tunnel
// headers.
func (t *Tunnel) encapsulateIPv4FOU(pkt []byte, srcIp, dstIp netip.Addr, srcPort, dstPort uint16) {
	// IPv4 header
	pkt[0] = 0x45                                            // Ver: 4, IHL: 5
	pkt[1] = 0x00                                            // DSCP, ECN
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))   // Total Length
	binary.BigEndian.PutUint16(pkt[4:6], uint16(rand.Int())) // Identification
	copy(pkt[6:8], []byte{0, 0})                             // Flags + Fragment Offset
	pkt[8] = 64                                              // Time to Live
	pkt[9] = unix.IPPROTO_UDP                                // Protocol
	copy(pkt[12:16], srcIp.AsSlice())                        // Source IP
	copy(pkt[16:20], dstIp.AsSlice())                        // Destination IP
	// NOTE: update IHL if you add any IP options, and remember to also update the IPv4 offset
	// in handleIPv4(). (See the comment, "Our IPv4 tunnel uses a 20-byte header...")

	ipPayloadLen := len(pkt) - (int((pkt[0] & 0x0f)) * 4)
	chksum := computeIPv4Checksum(pkt[0:ipPayloadLen])
	binary.BigEndian.PutUint16(pkt[10:], chksum)

	// UDP header
	udp := pkt[20:]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)          // Source port
	binary.BigEndian.PutUint16(udp[2:4], dstPort)          // Destination port
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp))) // Length (UDP header + data)

	chksum = fastEncapChecksumCompute(pkt)
	binary.BigEndian.PutUint16(udp[6:8], chksum)
}

// encapsulateIPv6FOU() takes a byte slice representing a packet, with some amount of padding
// prepended to it, and "encapsulates" the original packet in an FoU-over-IPv6 tunnel. The byte
// slice must have enough padding at the beginning of it for the tunnel's IPv6 and UDP headers. In
// our case, since our IPv6 header consists of the 40-byte standard header plus an 8-byte extension
// header, this means there should be 40+8+8 (56) bytes of padding at the beginning. It modifies the
// packet in-place, using the extra padding to prepend the tunnel headers.
func (t *Tunnel) encapsulateIPv6FOU(pkt []byte, srcIp, dstIp netip.Addr, srcPort, dstPort uint16) {
	// IPv6 Header format (from RFC 8200):
	//
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |Version| Traffic Class |           Flow Label                  |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |         Payload Length        |  Next Header  |   Hop Limit   |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                                                               |
	// +                                                               +
	// |                                                               |
	// +                         Source Address                        +
	// |                                                               |
	// +                                                               +
	// |                                                               |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                                                               |
	// +                                                               +
	// |                                                               |
	// +                      Destination Address                      +
	// |                                                               |
	// +                                                               +
	// |                                                               |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	// The flow label should be stable, without being hard-coded. No one should be looking at it
	// (as this is traffic from the front-end cloud to the back-end proxy), but just in case
	// they are, let's make it look like each packet from a unique source and destination belong
	// to the same flow (because...I mean...they do).
	s16 := srcIp.As16()
	d16 := dstIp.As16()
	flowLabel := binary.BigEndian.Uint32(s16[12:])
	flowLabel ^= binary.BigEndian.Uint32(d16[12:])
	flowLabel ^= uint32(srcPort)<<16 + uint32(dstPort)
	flowLabel = 0x60000000 | (flowLabel & 0x000fffff)

	// Since the fixed header length is 40 bytes, we hard-code it below because everything after
	// that is considered part of the payload for length calculation, including any IPv6
	// extension headers.

	binary.BigEndian.PutUint32(pkt[0:4], flowLabel)             // Ver: 6, Traffic Class: 0, Flow Label: ugh
	binary.BigEndian.PutUint16(pkt[4:6], uint16(len(pkt[40:]))) // Payload Length
	pkt[6] = unix.IPPROTO_UDP                                   // Next Header (Protocol)
	pkt[7] = 64                                                 // Hop Limit
	copy(pkt[8:24], s16[:])                                     // Source IP
	copy(pkt[24:40], d16[:])                                    // Destination IP

	// FoU is simply UDP encapsulation.
	// UDP header format (RFC 768):
	//
	// 0               8              16              24              32
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |           Source Port         |       Destination Port        |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |             Length            |            Checksum           |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	udp := pkt[40:]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)          // Source port
	binary.BigEndian.PutUint16(udp[2:4], dstPort)          // Destination port
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp))) // Length (UDP header + data)

	chksum := fastEncapChecksumCompute(pkt)
	binary.BigEndian.PutUint16(udp[6:8], chksum)
}

func frameToHex(pkt []byte) string {
	builder := strings.Builder{}
	for i, b := range pkt {
		builder.WriteString(fmt.Sprintf("%02x ", b))
		if (i+1)%16 == 0 {
			builder.WriteRune('\n')
		} else if (i+1)%8 == 0 {
			builder.WriteRune(' ')
		}
	}
	return builder.String()
}

func (t *Tunnel) startGARPs() context.CancelFunc {
	// In cloud environments, ARP usually doesn't do anything because the cloud provider's
	// network stack maps a VM's IP address(es) to the exact interface on which they're bound
	// and will never send packets anywhere else. However, when we're operating on bare metal
	// without the benefit of a cloud provider doing fancy networking things under the hood,
	// upstream devices need to know that IP-to-MAC mapping. They'll do this by sending ARP
	// requests for the IP address in question, which we will respond to (in `handleARP()`), but
	// it seems like there may also be a race with Linux's networking stack where another
	// interface in the same broadcast domain will respond to the ARP request at the same
	// time. (In Linux, addresses may be _bound_ to a NIC but they're _owned_ by a host, and
	// apparently Linux doesn't care which interface it uses to send packets if there are more
	// than one in the same broadcast domain.) In a cloud environment, no other interface would
	// even see that APR request, but in the real world, things are messier. If Linux sends an
	// ARP reply for our IP address from another interface, the upstream switch will begin
	// sending data to the wrong interface. To add insult to injury, if the upstream device
	// doesn't send any more ARP requests (because it's actually getting return packets from the
	// wrong interface saying "wtf stop sending me junk", which is enough to keep the ARP entry
	// hot), we may not even get the chance to "take back" the address for ourselves. To get
	// around this (really, really specific) problem, we can send gratuitous ARP requests
	// announcing that, in fact, _this interface_ owns the IP address. We do it at a rate that
	// is shorter than the shortest validity period for an ARP cache entry (which, by default on
	// Linux, is from 15 seconds up to 45 seconds).
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		ticker := time.NewTicker(10 * time.Second)

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				clog.Debug(t.ctx, "sending GARPs")
				if err := t.sendGratuitousARPs(); err != nil {
					log.Error(t.ctx, "error sending GARPs", err)
				}
			}
		}
	}()
	return cancel
}

func (t *Tunnel) sendGratuitousARPs() error {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_ALL)
	if err != nil {
		return fmt.Errorf("error opening AF_PACKET socket for arp request: %w", err)
	}
	defer syscall.Close(fd)

	addresses, err := netlink.AddrList(t.link, unix.AF_INET)
	if err != nil {
		return fmt.Errorf("getting address list for %s: %w", t.link.Attrs().Name, err)
	}

	for _, a := range addresses {
		if !a.IP.IsGlobalUnicast() {
			continue
		}

		spa := a.IP.To4()
		sha := t.link.Attrs().HardwareAddr

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
		copy(arp[8:], sha)                       // SHA
		copy(arp[14:], spa[:])                   // SPA
		copy(arp[18:], []byte{0, 0, 0, 0, 0, 0}) // THA set to 0 for gratuitous ARP request
		copy(arp[24:], spa[:])                   // TPA=SPA for gratuitous ARP request

		addr := syscall.SockaddrLinklayer{
			Protocol: syscall.ETH_P_ARP,
			Ifindex:  t.link.Attrs().Index,
			Hatype:   syscall.ARPHRD_ETHER,
		}

		clog.Debug(t.ctx, "sending gratuitous arp request", "spa", a.IP, "sha", sha)
		err = syscall.Sendto(fd, pkt, 0, &addr)
		if err != nil {
			return fmt.Errorf("error sending arp request: %w", err)
		}
	}

	return nil
}
