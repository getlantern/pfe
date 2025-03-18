package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/getlantern/lantern-cloud/cmd/pfe/xdptun"
	"github.com/getlantern/lantern-cloud/log"
)

const fouDestPort uint16 = 5555

var (
	apiPollInterval time.Duration = 30 * time.Second

	ipv6SourceAddr netip.Addr = netip.IPv6Unspecified()
)

func readConfig(filename string) (Config, error) {
	contents, err := os.ReadFile(filename)
	if err != nil {
		return Config{}, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	_, err = toml.Decode(string(contents), &config)
	if err != nil {
		return Config{}, fmt.Errorf("failed to parse config: %w", err)
	}

	if config.Id == "" {
		return Config{}, errors.New("id is a a required config field")
	} else if config.Name == "" {
		return Config{}, errors.New("name is a a required config field")
	} else if config.Interface == "" {
		return Config{}, errors.New("interface is a required config field")
	} else if config.Provider == "" {
		return Config{}, errors.New("provider is a required config field")
	} else if config.ProviderLocation == "" {
		return Config{}, errors.New("provider location is a required config field")
	} else if config.ProviderId == "" {
		return Config{}, errors.New("provider id is a required config field")
	}

	log.Info(context.Background(), "read config file",
		"id", config.Id,
		"interface", config.Interface,
		"provider", config.Provider,
		"location", config.ProviderLocation,
		"providerId", config.ProviderId,
	)

	return config, nil
}

func parseIPsFromFile(mapfile string) (map[netip.Addr]xdptun.AssociatedIPs, error) {
	file, err := os.Open(mapfile)
	if err != nil {
		return nil, err
	}

	return parseIPMap(file)
}

func parseIPMap(file io.Reader) (map[netip.Addr]xdptun.AssociatedIPs, error) {
	tempMap := make(map[netip.Addr]xdptun.AssociatedIPs)

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	lineNo := 1
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "#") {
			continue
		}
		if line == "" {
			continue
		}

		ips := strings.Split(line, ",")
		if len(ips) < 4 {
			return nil, fmt.Errorf("line %d is badly formatted: %s", lineNo, line)
		}
		eip, err := netip.ParseAddr(strings.TrimSpace(ips[0]))
		if err != nil {
			return nil, fmt.Errorf(`invalid EIP "%s" on line %d`, ips[0], lineNo)
		}
		privateIP, err := netip.ParseAddr(strings.TrimSpace(ips[1]))
		if err != nil {
			return nil, fmt.Errorf(`invalid private IP "%s" on line %d`, ips[1], lineNo)
		}
		tunnelSrc, err := netip.ParseAddr(strings.TrimSpace(ips[2]))
		if err != nil {
			return nil, fmt.Errorf(`invalid tunnel source IP "%s" on line %d`, ips[2], lineNo)
		}
		tunnelDest, err := netip.ParseAddr(strings.TrimSpace(ips[3]))
		if err != nil {
			return nil, fmt.Errorf(`invalid tunnel destination IP "%s" on line %d`, ips[3], lineNo)
		}
		tunnelPort := fouDestPort
		if len(ips) == 5 {
			port, err := strconv.Atoi(strings.TrimSpace(ips[4]))
			if err != nil || port > math.MaxUint16 {
				return nil, fmt.Errorf(`invalid tunnel destination port "%s" on line %d`, ips[4], lineNo)
			}
			tunnelPort = uint16(port)
		}

		if tunnelSrc.BitLen() != tunnelDest.BitLen() {
			return nil, fmt.Errorf("tunnel source and destination IPs must be the same length on line %d", lineNo)
		}

		key := privateIP
		tempMap[key] = xdptun.AssociatedIPs{
			EIP:          eip,
			TunnelSource: tunnelSrc,
			TunnelDest:   tunnelDest,
			TunnelPort:   tunnelPort,
		}
	}

	return tempMap, nil
}

func fatal(ctx context.Context, title string, err error, fields ...any) {
	log.Error(ctx, title, err, fields)
	log.Flush()
	os.Exit(2)
}
