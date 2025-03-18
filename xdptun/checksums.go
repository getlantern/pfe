package xdptun

import (
	"encoding/binary"

	"golang.org/x/sys/unix"
)

type Unsigned interface {
	uint32 | uint64
}

func fold[U Unsigned](n U) U {
	for n > 0xffff {
		n = (n & 0xffff) + (n >> 16)
	}

	return n
}

func checksum(initial uint64, data []byte) uint64 {
	chksum := uint64(initial)

	var i int
	for len(data)-i >= 4 {
		chksum += uint64(binary.BigEndian.Uint32(data[i:]))
		i += 4
	}
	for len(data)-i >= 2 {
		chksum += uint64(binary.BigEndian.Uint16(data[i:]))
		i += 2
	}
	if len(data)-i == 1 {
		chksum += uint64(data[i]) << 8
	}

	return fold(chksum)
}

// computeIPv4Checksum computes a new checksum for the given IPv4 header and writes it into the
// header.
func computeIPv4Checksum(header []byte) uint16 {
	// zero out the old checksum
	binary.BigEndian.PutUint16(header[10:], 0)

	ihl := int((header[0] & 0xf)) * 4
	chksum := checksum(0, header[:ihl])

	return ^uint16(fold(chksum))
}

func computePseudoHeaderChecksum(ipHdr, l4 []byte) uint16 {
	ipVer := ipHdr[0] >> 4
	if ipVer == 4 {
		return computeIPv4PseudoHeaderChecksum(ipHdr)
	} else if ipVer == 6 {
		return computeIPv6PseudoHeaderChecksum(ipHdr, l4)
	}
	panic("invalid IP version")
}

func computeIPv4PseudoHeaderChecksum(ipHdr []byte) uint16 {
	chksum := checksum(0, ipHdr[12:20]) // src, dst ip
	chksum += uint64(ipHdr[9])          // protocol

	// layer 4 length
	ipHdrLen := uint16((ipHdr[0] & 0xf)) * 4
	chksum += uint64(binary.BigEndian.Uint16(ipHdr[2:4]) - ipHdrLen)

	return uint16(fold(chksum))
}

func ipv6UpperLayerProtocol(ipHdr []byte) uint8 {
	pos := 6 // initial Next Header position in IPv6 header
	proto := ipHdr[pos]
	next := 40 - pos // IPv6 header is 40 bytes long

	// We have to skip over these extension headers, if they exist, to get to the actual
	// upper-layer protocol.
	// XXX: this needs bounds checking.
	for proto == unix.IPPROTO_HOPOPTS || proto == unix.IPPROTO_ROUTING ||
		proto == unix.IPPROTO_FRAGMENT || proto == unix.IPPROTO_DSTOPTS {
		pos += next
		proto = ipHdr[pos]
		next += int(ipHdr[pos+1]) * 8
	}

	return proto
}

func computeIPv6PseudoHeaderChecksum(ipHdr []byte, l4 []byte) uint16 {
	proto := ipv6UpperLayerProtocol(ipHdr)

	chksum := checksum(0, ipHdr[8:40]) // src, dst ip
	chksum += uint64(proto)            // protocol

	// NOTE: instead of using the length of the slice, it'd be better to calculate the
	// length of the payload from the IPv6 "Payload Length" value. (To get the true L4 length,
	// you have to subtract the number of bytes used by extension headers, as those are counted
	// in the Payload Length field.)
	chksum += uint64(len(l4)) // l4 length
	return uint16(fold(chksum))
}

func verifyChecksum(pkt []byte) bool {
	var chksum uint64
	var proto uint8

	ipVer := pkt[0] >> 4

	var ipHdrLen int

	if (ipVer) == 4 {
		proto = pkt[9]
		ipHdrLen = int((pkt[0] & 0xf)) * 4
	} else if (ipVer) == 6 {
		proto = ipv6UpperLayerProtocol(pkt)
		ipHdrLen = ipv6HeaderLen
	} else {
		panic("invalid IP version")
	}

	l4 := pkt[ipHdrLen:]

	if proto != unix.IPPROTO_ICMP {
		chksum += uint64(computePseudoHeaderChecksum(pkt[:ipHdrLen], l4))
	}

	chksum = checksum(chksum, l4)

	return ^uint16(chksum) == 0
}

// computeLayer4Checksum computes the "Internet checksum" for layer 4 protocols (specifically ICMP,
// TCP, and UDP). The Internet checksum is described in RFC 1071. For TCP and UDP, the checksum
// includes a "pseudo-header" made up of the source and destination IPs, the protocol number, and
// the total length of layer 4. See the relevant RFCs for each L4 protocol for more information on
// this pseudo-header. (ICMP does not use this pseudo-header.)
func computeLayer4Checksum(pkt []byte) uint16 {
	// For more details, see:
	// https://blogs.igalia.com/dpino/2018/06/14/fast-checksum-computation/

	var chksum uint64
	var proto uint8

	ipVer := pkt[0] >> 4

	var ipHdrLen int
	var l4Len int

	if (ipVer) == 4 {
		proto = pkt[9]
		ipHdrLen = int((pkt[0] & 0xf)) * 4
		l4Len = int(binary.BigEndian.Uint16(pkt[2:4])) - ipHdrLen
	} else if (ipVer) == 6 {
		// XXX: this is super hacky because we know that the only IPv6 headers we'll see are
		// the ones we construct, and that we do not add any IPv6 options after the IP
		// header. If we did, then the Next Header field wouldn't indicate the layer 4
		// protocol, but the type of the next IPv6 header option and we'd have to iterate
		// down until we found the real layer 4 protocol. (And of course the length of the
		// IP header would be larger, too.)
		proto = ipv6UpperLayerProtocol(pkt)
		ipHdrLen = ipv6HeaderLen
		l4Len = int(binary.BigEndian.Uint16(pkt[4:6]))
	} else {
		panic("invalid IP version")
	}

	l4 := pkt[ipHdrLen : ipHdrLen+l4Len]

	// zero out the old L4 checksum
	if proto == unix.IPPROTO_ICMP {
		copy(l4[2:4], []byte{0, 0})
	} else if proto == unix.IPPROTO_TCP {
		copy(l4[16:], []byte{0, 0})
	} else if proto == unix.IPPROTO_UDP {
		copy(l4[6:], []byte{0, 0})
	}

	// pseudo-header
	if !(proto == unix.IPPROTO_ICMP || proto == unix.IPPROTO_NONE) {
		chksum += uint64(computePseudoHeaderChecksum(pkt[:ipHdrLen], l4))
	}

	chksum = checksum(chksum, l4)

	if chksum == 0 && proto == unix.IPPROTO_UDP {
		return 0xffff
	}

	return ^uint16(chksum)
}

// fastChecksumRecompute performs an incremental update of an existing layer 4 checksum, using the
// algorithm laid out in RFC 1624.
func fastChecksumRecompute(hc uint16, m, mp uint32) uint16 {
	// From https://www.rfc-editor.org/rfc/rfc1624:
	// HC' = ~(C + (-m) + m')
	//     = ~(~HC + ~m + m')

	m = fold(m)
	mp = fold(mp)

	hcp := uint32(^hc) + uint32(^uint16(m)) + uint32(mp)
	return ^uint16(fold(hcp))
}

// fastEncapChecksumCompute takes an IP datagram (i.e., a packet without an Ethernet header) and
// implements a method of computing an encapsulating layer's L4 checksum when the inner packet's L4
// checksum is valid. It is an implementation of the algorithm used in Linux's "local checksum
// offload" feature. See
// https://www.kernel.org/doc/html/latest/networking/checksum-offloads.html#lco-local-checksum-offload
// for more details on the cool math.
//
// This obviously only works if a) the inner packet is IP, and b) the inner layer 4 protocol is TCP
// or UDP. If we detect that either of those conditions are false, we fall back to doing a full
// checksum computation.
func fastEncapChecksumCompute(pkt []byte) uint16 {
	var chksum uint64

	outerIpVer := pkt[0] >> 4
	var outerIpHdrLen int
	var outerL4Proto byte

	if (outerIpVer) == 4 {
		outerL4Proto = pkt[9]
		outerIpHdrLen = int((pkt[0] & 0xf)) * 4
	} else if (outerIpVer) == 6 {
		outerL4Proto = ipv6UpperLayerProtocol(pkt)
		outerIpHdrLen = ipv6HeaderLen
	} else {
		panic("invalid IP version")
	}

	outerL4 := pkt[outerIpHdrLen:]

	var outerL4Len int
	var innerIP []byte
	if outerL4Proto == unix.IPPROTO_TCP {
		outerL4Len = int(outerL4[12]>>4) * 4
		innerIP = outerL4[outerL4Len:]
		copy(outerL4[16:18], []byte{0, 0}) // zero checksum
	} else if outerL4Proto == unix.IPPROTO_UDP {
		outerL4Len = 8
		innerIP = outerL4[8:]
		copy(outerL4[6:8], []byte{0, 0}) // zero checksum
	} else {
		// no fast compute for you
		return computeLayer4Checksum(pkt)
	}

	innerIpVer := innerIP[0] >> 4
	if innerIpVer != 4 {
		// idk what this is but it ain't tunneled IPv4, and that's all we support
		return computeLayer4Checksum(pkt)
	}

	innerL4Proto := innerIP[9]
	innerIpHdrLen := int(innerIP[0]&0xf) * 4
	innerL4 := innerIP[innerIpHdrLen:]

	if !(innerL4Proto == unix.IPPROTO_TCP || innerL4Proto == unix.IPPROTO_UDP) {
		return computeLayer4Checksum(pkt)
	}

	chksum += uint64(computePseudoHeaderChecksum(pkt[:outerIpHdrLen], outerL4)) // outer IP pseudoheader
	chksum = checksum(chksum, outerL4[:outerL4Len])                             // outer L4 header
	chksum = checksum(chksum, innerIP[:innerIpHdrLen])                          // inner IP header
	psc := computePseudoHeaderChecksum(innerIP, innerL4)
	chksum += uint64(^psc) // *complement* of inner IP pseudoheader

	return ^uint16(fold(chksum))
}
