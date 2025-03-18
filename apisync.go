package main

import (
	"context"
	"fmt"
	"math"
	"net/netip"

	"github.com/getlantern/lantern-cloud/cmd/api/apipb"
	"github.com/getlantern/lantern-cloud/cmd/pfe/xdptun"
	"github.com/getlantern/lantern-cloud/log"
	"github.com/getlantern/lantern-cloud/protoclient"
)

type Config struct {
	Id               string `toml:"pfe_id"`
	Name             string `toml:"pfe_name"`
	Interface        string `toml:"interface"`
	Provider         string `toml:"provider"`
	ProviderLocation string `toml:"provider_location"`
	ProviderId       string `toml:"provider_id"`
	APIHost          string `toml:"api_host"`
}

var apiClient *protoclient.Client

func setupClient(ctx context.Context, config *Config, certBundle string) error {
	apiHost := DefaultAPIHost
	if config.APIHost != "" {
		log.Info(ctx, "overriding API host", "host", config.APIHost)
		apiHost = config.APIHost
	}

	client, err := protoclient.NewWithCertPool("https://"+apiHost, certBundle, false)
	if err != nil {
		return fmt.Errorf("failed to create protoclient: %w", err)
	}
	apiClient = client
	return nil
}

const DefaultAPIHost = "api.lantr.net"

func apiSync(ctx context.Context, config *Config, ipv6SourceAddr netip.Addr) (map[netip.Addr]xdptun.AssociatedIPs, error) {
	req := apipb.PFESyncRequest{
		Id:               config.Id,
		Name:             config.Name,
		ProviderName:     config.Provider,
		ProviderLocation: config.ProviderLocation,
		ProviderId:       config.ProviderId,
	}
	var resp apipb.PFESyncResponse

	log.Info(ctx, "attempting to contact API")
	err := apiClient.Post(ctx, "/proxy/pfe/sync", &req, &resp)
	if err != nil {
		return nil, fmt.Errorf("error calling API sync endpoint: %w", err)
	}

	tempMap := make(map[netip.Addr]xdptun.AssociatedIPs)

	log.Info(ctx, "parsing API response")
	for _, route := range resp.Routes {
		eip, err := netip.ParseAddr(route.PublicAddress)
		if err != nil {
			msg := "invalid EIP in API response"
			log.Error(ctx, msg, fmt.Errorf(msg), "ip", route.PublicAddress)
			continue
		}
		privateIp, err := netip.ParseAddr(route.PrivateAddress)
		if err != nil {
			msg := "invalid private IP in API response"
			log.Error(ctx, msg, fmt.Errorf(msg), "ip", route.PrivateAddress)
			continue
		}

		tunnelDest, err := netip.ParseAddr(route.ForwardingAddress)
		if err != nil {
			msg := "invalid tunnel destination IP in API response"
			log.Error(ctx, msg, fmt.Errorf(msg), "ip", route.ForwardingAddress)
			continue
		}

		tunnelSrc := eip
		if tunnelDest.Is6() {
			if ipv6SourceAddr.IsUnspecified() {
				msg := "no valid IPv6 tunnel source address for route"
				log.Error(ctx, msg, fmt.Errorf(msg), "destination_ip", route.ForwardingAddress)
			} else {
				tunnelSrc = ipv6SourceAddr
			}
		} else {
			tunnelSrc = eip
		}

		if route.ForwardingPort > math.MaxUint16 {
			msg := "invalid port in API response"
			log.Error(ctx, msg, fmt.Errorf(msg), "port", route.ForwardingPort)
			continue
		}

		if tunnelSrc.BitLen() != tunnelDest.BitLen() {
			msg := "tunnel source and destination IPs must be the same length"
			log.Error(ctx, msg, fmt.Errorf(msg), "src_ip", tunnelSrc, "dest_ip", tunnelDest)
			continue
		}

		tempMap[privateIp] = xdptun.AssociatedIPs{
			EIP:          eip,
			TunnelSource: tunnelSrc,
			TunnelDest:   tunnelDest,
			TunnelPort:   uint16(route.ForwardingPort),
		}
	}

	log.Info(ctx, "got routes from API", "count", len(tempMap))
	return tempMap, nil
}
