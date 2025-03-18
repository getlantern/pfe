// command pfe exists to forward traffic to proxies in triangle routing setups.

package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Crosse/xdp"
	"github.com/mroth/jitter"
	flag "github.com/spf13/pflag"
	"github.com/vishvananda/netlink"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"golang.org/x/sys/unix"

	clog "github.com/getlantern/lantern-cloud/cmd/pfe/conditional_log"
	"github.com/getlantern/lantern-cloud/cmd/pfe/xdptun"
	"github.com/getlantern/lantern-cloud/log"
	"github.com/getlantern/lantern-cloud/metrics"
	"github.com/getlantern/lantern-cloud/trace"
)

var (
	lastStatsTime time.Time
	prevStats     xdptun.Statistics
	prevXdpStats  xdp.Stats
)

func main() {
	certBundle := flag.String("certs", "", "Path to a certificate bundle to load")
	configTest := flag.BoolP("configtest", "n", false, "Configtest mode. Exits after validating configuration.")
	configFile := flag.StringP("config", "c", "", "Path to the configuration file")
	debug := flag.CountP("debug", "d", "Enable debug output. Specify twice for more verbose output.")
	gw4 := flag.String("gateway4", "", "The default IPv4 gateway to use. If not specified, pfe will try to discover the default route")
	gw6 := flag.String("gateway6", "", "The default IPv6 gateway to use. If not specified, pfe will try to discover the default route")
	help := flag.BoolP("help", "h", false, "Print this usage information")
	iface := flag.StringP("interface", "i", "", "The interface on which to listen")
	ipMapFile := flag.StringP("mapfile", "m", "", "A file with IP mappings")
	xdpMode := flag.String("mode", "auto", "The XDP mode to use. Can be one of: skb, driver, or hw")
	doPcap := flag.Bool("pcap", false, "Write out a PCAP file of all ingress and egress data")
	queue := flag.Int("queue", 0, "NIC queue to use")
	stdoutOnly := flag.Bool("stdout", false, "Log only to stdout instead of to Honeycomb/Google (for testing)")
	egressLink := flag.String("egress", "", "interface on which to send packets")
	flag.Parse()

	if *help {
		flag.Usage()
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	level := (clog.LogLevel)(*debug)
	if level > clog.LevelTrace {
		level = clog.LevelTrace
	}

	if err := log.Init("pfe", "", !*stdoutOnly); err != nil {
		fatal(ctx, "failed to set up logging", err)
	}
	defer log.Flush()

	if *configFile != "" && *iface != "" {
		msg := "cannot specify --config and --interface together"
		fatal(ctx, msg, fmt.Errorf(msg))
	}

	var err error
	var config Config
	if *configFile != "" {
		config, err = readConfig(*configFile)
		if err != nil {
			fatal(ctx, "failed to read config file", err, "config_file", *configFile)
		}
	}
	if config.Interface != "" {
		*iface = config.Interface
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = strings.Split(config.Name, "@")[0]
	}

	if !*stdoutOnly {
		// This gets noisy when watching logs locally
		ctx = log.With(ctx,
			"id", config.Id,
			"host", hostname,
			"name", config.Name,
			"link", *iface,
			"provider", config.Provider,
			"provider_id", config.ProviderId,
			"location", config.ProviderLocation)
	}

	err = metrics.Init(ctx, "pfe",
		"pfe.host", hostname,
		"pfe.name", config.Name,
		"pfe.link", *iface,
		"pfe.provider", config.Provider,
		"pfe.provider.id", config.ProviderId,
		"pfe.provider.location", config.ProviderLocation)
	if err != nil {
		fatal(ctx, "failed to set up metrics reporting", err)
	}
	defer metrics.Flush()

	err = trace.Init(ctx, "pfe")
	if err != nil {
		fatal(ctx, "failed to set up tracing", err)
	}
	defer trace.Flush()

	mode := uint32(0)
	switch *xdpMode {
	case "skb":
		mode |= unix.XDP_FLAGS_SKB_MODE
	case "driver":
		mode |= unix.XDP_FLAGS_DRV_MODE
	case "hw":
		mode |= unix.XDP_FLAGS_HW_MODE
	case "auto":
	default:
		msg := "invalid XDP mode"
		fatal(ctx, msg, fmt.Errorf(msg), "xdp_mode", *xdpMode)
	}

	var link netlink.Link

	if *iface == "" {
		msg := "no interface found in config file or on command line"
		fatal(ctx, msg, errors.New(msg))
	}

	link, err = netlink.LinkByName(*iface)
	if err != nil {
		fatal(ctx, "getting interface", err)
	}

	tunnel, err := xdptun.NewTunnel(ctx, link, *queue, mode)
	if err != nil {
		fatal(ctx, "initializing tunnel", err)
	}

	if *doPcap {
		if err = tunnel.StartPCAPLogging(); err != nil {
			fatal(ctx, "enabling PCAP logging", err)
		}
	}

	if *egressLink != "" {
		l, err := netlink.LinkByName(*egressLink)
		if err != nil {
			fatal(ctx, "getting egress interface: %w", err)
		}
		if err = tunnel.CopyPacketsToInterface(l); err != nil {
			fatal(ctx, "cannot copy packets to interface", err)
		}
		ctx = log.With(ctx, "egress_link", l.Attrs().Name)
	}

	if *gw4 != "" {
		if ip, err := netip.ParseAddr(*gw4); err != nil {
			fatal(ctx, "invalid IPv4 gateway", err, "gateway", *gw4)
		} else {
			tunnel.Gateway4 = ip
		}
	} else {
		err = tunnel.DiscoverGateway4()
		if err != nil {
			fatal(ctx, "failed to discover IPv4 gateway", err)
		}
	}

	if *gw6 != "" {
		if ip, err := netip.ParseAddr(*gw6); err != nil {
			fatal(ctx, "invalid IPv6 gateway", err, "gateway", *gw6)
		} else {
			tunnel.Gateway6 = ip
		}
	} else {
		err = tunnel.DiscoverGateway6()
		if err != nil {
			fatal(ctx, "failed to discover IPv6 gateway", err)
		}
	}

	v6Addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
	if err != nil {
		fatal(ctx, "cannot enumerate IPv6 addresses on interface", err)
	}
	for _, addr := range v6Addrs {
		if addr.IP.IsGlobalUnicast() {
			if a, ok := netip.AddrFromSlice(addr.IP); !ok {
				msg := "failed to convert to an IP address"
				log.Error(ctx, msg, fmt.Errorf(msg), "ip", addr.IP)
				continue
			} else {
				ipv6SourceAddr = a
				break
			}
		}
	}

	if ipv6SourceAddr == netip.IPv6Unspecified() {
		msg := "could not find any IPv6 addresses on interface"
		fatal(ctx, msg, fmt.Errorf(msg))
	}

	if *ipMapFile != "" {
		ipMap, err := updateIPMapFromFile(*ipMapFile)
		if err != nil {
			fatal(ctx, "updating IP mappings", err)
		}
		tunnel.SetIPMap(&ipMap)
	}

	log.Info(ctx, "running config",
		"xdp_mode", *xdpMode,
		"link", link.Attrs().Name,
		"queue", *queue,
		"hwaddr", link.Attrs().HardwareAddr,
		"gateway4", tunnel.Gateway4,
		"gateway6", tunnel.Gateway6,
		"tunnel_saddr", ipv6SourceAddr,
		"egress_link", *egressLink,
	)

	if *configTest {
		log.Info(ctx, "configuration valid.")
		return
	}

	sigtermChan := make(chan os.Signal)
	signal.Notify(sigtermChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigtermChan
		tunnel.Stop()
		cancel()
	}()

	wg := sync.WaitGroup{}

	if *configFile != "" {
		log.Info(ctx, "spawning api sync...")
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := log.With(ctx, "component", "apisync")
			err = setupClient(ctx, &config, *certBundle)
			if err != nil {
				fatal(ctx, "setting up certificate pool", err)
			}

			if ipMap, err := apiSync(ctx, &config, ipv6SourceAddr); err != nil {
				log.Error(ctx, "syncing with api", err)
			} else {
				tunnel.SetIPMap(&ipMap)
			}

			ticker := jitter.NewTicker(apiPollInterval, 0.2)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					log.Info(ctx, "stopping")
					return
				case <-ticker.C:
					if ipMap, err := apiSync(ctx, &config, ipv6SourceAddr); err != nil {
						log.Error(ctx, "syncing with api", err)
					} else {
						tunnel.SetIPMap(&ipMap)
					}
				}
			}
		}()
	}

	if *ipMapFile != "" {
		ctx := log.With(ctx, "ipmap_file", *ipMapFile)
		log.Info(ctx, "will re-read IP mapping file on SIGHUP")
		sighupChan := make(chan os.Signal)
		signal.Notify(sighupChan, syscall.SIGHUP)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case <-sighupChan:
					log.Info(ctx, "updating IP mappings")
					if ipMap, err := updateIPMapFromFile(*ipMapFile); err != nil {
						log.Error(ctx, "updating IP mappings", err)
					} else {
						tunnel.SetIPMap(&ipMap)
					}
				}
			}
		}()
	}

	sigusr1Chan := make(chan os.Signal)
	signal.Notify(sigusr1Chan, syscall.SIGUSR1)
	wg.Add(1)
	go func() {
		interval := time.Second * 5
		if *stdoutOnly {
			interval = time.Minute
		}

		lastStatsReportToConsole := time.Now()

		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case <-sigusr1Chan:
				printStats(ctx, config, tunnel, link, clog.LevelInfo)
			case <-time.After(interval):
				if time.Since(lastStatsReportToConsole) >= time.Minute {
					printStats(ctx, config, tunnel, link, clog.LevelInfo)
					lastStatsReportToConsole = time.Now()
				} else {
					printStats(ctx, config, tunnel, link, clog.LevelDebug)
				}
			}
		}
	}()

	setupMetrics(ctx, tunnel)

	defer tunnel.Close()

	log.Info(ctx, "starting pfe tunnel")
	if err = tunnel.Redirect(); err != nil {
		fatal(ctx, "error processing packets", err)
	}
	log.Info(ctx, "stopping tunnel")
	printStats(ctx, config, tunnel, link, clog.LevelInfo)

	wg.Wait()

	log.Info(ctx, "quitting")
}

func updateIPMapFromFile(file string) (map[netip.Addr]xdptun.AssociatedIPs, error) {
	temp, err := parseIPsFromFile(file)
	if err != nil {
		return nil, fmt.Errorf("IP map not updated: %v\n", err)
	}

	return temp, nil
}

func printStats(ctx context.Context, config Config, t *xdptun.Tunnel, link netlink.Link, lvl clog.LogLevel) {
	mb := float64(1024 * 1024)

	stats, err := t.Stats()
	if err != nil {
		log.Error(ctx, "gathering statistics", err)
		return
	}

	elapsed := time.Since(lastStatsTime).Seconds()
	mbps_rx := float64(stats.RxBytes-prevStats.RxBytes) / elapsed / mb * 8
	pps_rx := float64(stats.RxFrames-prevStats.RxFrames) / elapsed

	mbps_tx := float64(stats.TxBytes-prevStats.TxBytes) / elapsed / mb * 8
	pps_tx := float64(stats.TxFrames-prevStats.TxFrames) / elapsed

	clog.Log(ctx, lvl, "tunnel statistics",
		"uptime_secs", time.Since(stats.Started).Truncate(time.Second).Seconds(),
		"rx_frames", stats.RxFrames,
		"rx_bytes", stats.RxBytes,
		"mbps_rx", truncate(mbps_rx, 4),
		"pps_rx", truncate(pps_rx, 4),
		"mbps_tx", truncate(mbps_tx, 4),
		"pps_tx", truncate(pps_tx, 4),
		"avg_packet_service_ns", truncate(stats.AvgPacketServiceTime, 0),
		"tx_frames", stats.TxFrames,
		"tx_bytes", stats.TxBytes,
		"dropped_frames", stats.DroppedFrames,
		"dropped_bytes", stats.DroppedBytes,
		"runt_frames", stats.RuntFrames,
		"short_packets", stats.ShortPackets,
		"ignored_ethertype", stats.IgnoredEtherType,
		"invalid_ip_version", stats.InvalidIPVersion,
		"packets_from_backend", stats.BackendPackets,
		"dropped_jumbograms", stats.DroppedJumbograms,
		"arp_cache_misses", stats.ARPCacheMisses,
	)

	xdpStats := stats.XDPStats
	clog.Log(ctx, lvl, "xdp statistics",
		"received", xdpStats.Received,
		"transmitted", xdpStats.Transmitted,
		"filled", xdpStats.Filled,
		"completed", xdpStats.Completed)

	kstats := xdpStats.KernelStats
	clog.Log(ctx, lvl, "kernel statistics",
		"rx_dropped", kstats.Rx_dropped,
		"rx_invalid_descs", kstats.Rx_invalid_descs,
		"tx_invalid_descs", kstats.Tx_invalid_descs,
		"rx_ring_full", kstats.Rx_ring_full,
		"rx_fill_ring_empty_descs", kstats.Rx_fill_ring_empty_descs,
		"tx_ring_empty_descs", kstats.Tx_ring_empty_descs)

	prevStats = stats
	prevXdpStats = xdpStats
	lastStatsTime = time.Now()
}

func setupMetrics(ctx context.Context, t *xdptun.Tunnel) {
	metrics.InitObservableCounter(ctx, "pfe.io", func(_ context.Context, m metric.Int64Observer) error {
		stats, err := t.Stats()
		if err != nil {
			log.Error(ctx, "gathering statistics", err)
			return err
		}
		m.Observe(int64(stats.RxBytes), metric.WithAttributes(attribute.String("direction", "receive")))
		m.Observe(int64(stats.TxBytes), metric.WithAttributes(attribute.String("direction", "transmit")))
		return nil
	})

	metrics.InitObservableCounter(ctx, "pfe.frames", func(ctx context.Context, m metric.Int64Observer) error {
		stats, err := t.Stats()
		if err != nil {
			log.Error(ctx, "gathering statistics", err)
			return err
		}
		m.Observe(int64(stats.RxFrames), metric.WithAttributes(attribute.String("direction", "receive")))
		m.Observe(int64(stats.TxFrames), metric.WithAttributes(attribute.String("direction", "transmit")))
		m.Observe(int64(stats.RuntFrames),
			metric.WithAttributes(
				attribute.String("state", "dropped"),
				attribute.String("reason", "runt_frame")))
		m.Observe(int64(stats.ShortPackets),
			metric.WithAttributes(
				attribute.String("state", "dropped"),
				attribute.String("reason", "short_packet")))
		m.Observe(int64(stats.IgnoredEtherType),
			metric.WithAttributes(
				attribute.String("state", "dropped"),
				attribute.String("reason", "ignored_ether_type")))
		m.Observe(int64(stats.InvalidIPVersion),
			metric.WithAttributes(
				attribute.String("state", "dropped"),
				attribute.String("reason", "invalid_ip_version")))
		m.Observe(int64(stats.BackendPackets),
			metric.WithAttributes(
				attribute.String("state", "dropped"),
				attribute.String("reason", "packet_from_backend")))
		m.Observe(int64(stats.DroppedJumbograms),
			metric.WithAttributes(
				attribute.String("state", "dropped"),
				attribute.String("reason", "jumbogram")))
		return nil
	})

	metrics.InitObservableCounter(ctx, "pfe.protocols", func(ctx context.Context, m metric.Int64Observer) error {
		stats, err := t.Stats()
		if err != nil {
			log.Error(ctx, "gathering statistics", err)
			return err
		}
		m.Observe(int64(stats.ProtoIPv4), metric.WithAttributes(attribute.String("protocol", "ipv4")))
		m.Observe(int64(stats.ProtoIPv6), metric.WithAttributes(attribute.String("protocol", "ipv6")))
		m.Observe(int64(stats.ProtoICMP), metric.WithAttributes(attribute.String("protocol", "icmp")))
		m.Observe(int64(stats.ProtoTCP), metric.WithAttributes(attribute.String("protocol", "tcp")))
		m.Observe(int64(stats.ProtoUDP), metric.WithAttributes(attribute.String("protocol", "udp")))
		m.Observe(int64(stats.ProtoSCTP), metric.WithAttributes(attribute.String("protocol", "sctp")))
		m.Observe(int64(stats.ProtoUDPLite), metric.WithAttributes(attribute.String("protocol", "udplite")))
		m.Observe(int64(stats.ProtoOther), metric.WithAttributes(attribute.String("protocol", "other")))
		return nil
	})

	metrics.InitObservableCounter(ctx, "pfe.arp.misses", func(ctx context.Context, m metric.Int64Observer) error {
		stats, err := t.Stats()
		if err != nil {
			log.Error(ctx, "gathering statistics", err)
			return err
		}
		m.Observe(int64(stats.ARPCacheMisses))
		return nil
	})

	metrics.InitObservableCounter(ctx, "pfe.xdp.frames", func(ctx context.Context, m metric.Int64Observer) error {
		stats, err := t.Stats()
		if err != nil {
			log.Error(ctx, "gathering statistics", err)
			return err
		}
		m.Observe(int64(stats.XDPStats.Received), metric.WithAttributes(attribute.String("state", "received")))
		m.Observe(int64(stats.XDPStats.Transmitted), metric.WithAttributes(attribute.String("state", "transmitted")))
		m.Observe(int64(stats.XDPStats.Filled), metric.WithAttributes(attribute.String("state", "filled")))
		m.Observe(int64(stats.XDPStats.Completed), metric.WithAttributes(attribute.String("state", "completed")))
		return nil
	})
}

func truncate(x float64, precision int) float64 {
	ratio := math.Pow(10, float64(precision))
	return math.Round(x*ratio) / ratio
}
