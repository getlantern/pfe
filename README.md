# `pfe`, the proxy front-end

`pfe` is an XDP-based program that rewrites, encapsulates, and sends incoming packets to another
machine to enable "triangle routing" or direct server return.

From [haproxy.com][haproxy-dsr]:

> In DSR mode, the load-balancer routes packets to the backends without changing anything in it but
> the destination MAC address.  The backends process the requests and answer directly to the
> clients, without passing through the load-balancer.
>
> The backends must have the service IP configured on a loopback to be able to accept the requests.

The idea with our DSR setup is that a client sends a packet to front-end server A, which sends it to
back-end server B _without rewriting the original source or destination IP addresses_. Server B gets
the packet via its tunnel interface, handles it in whatever way it should, and then sends the reply
back directly to the client (instead of sending it server A) because that's the source IP address it
saw in the original request packet. (This is one example of DSR; in many setups the back-end servers
respond to the VIP so the load balancer doesn't have to tunnel traffic to it; it just updates the
destination MAC address on packets and sends it on.)

In our situation, the details play out like this:

1. A client sends a packet to a front-end proxy running `pfe`.
1. Through the magic of The Cloud, the packet has its destination IP address rewritten from the
   public IP (an EIP) to a private IP. In most scenarios, this doesn't matter. In this scenario, it
   matters a lot and we need to undo that.
1. `pfe` receives the packet and, after doing a few rudimentary checks, does the following:
   - rewrites the destination IP to be the public IP again
   - encapsulates the original packet in an [FoU][fou] or GRE tunnel. For IPv4 tunnels, the source
     IP of the tunnel is most likely the private IP (which will NAT back to the EIP when egressing
     the cloud provider's network), and the destination IP is a back-end proxy. For IPv6 tunnels,
     the source is probably the host or container's public IPv6 address.
   - sends the packet back out the NIC

   We have to rewrite the destination IP address in the original packet header because this is what
   the back-end proxy will spoof when sending replies to the client.
1. The back-end proxy will handle the client's request, and send the response back directly to the
   client (this requires the cloud provider to disable [BCP38][bcp38] filtering so that we can spoof
   the return packet's source address to look like it came from the original front-end box).

## Running `pfe`

`pfe` will, by necessity, take over any interface you give it. If you give it the management NIC, be
prepared to find its console to kill `pfe` or reboot it. You should only run `pfe` on secondary
NICs. You have been warned.

You must specify the interface on which `pfe` should listen by using a config file (`--config`) or
the `--iface` argument. (When using a config file, it will supercede a manually-set interface given
on the command line.)

Currently, `pfe` only listens on a single NIC queue (0, by default, but you can change that with the
`--queue` option). To ensure all packets come in on a single queue, you can do one of a couple of
things. The easiest method is to set the number of queues to 1, like so:

```
# ethtool -L eth1 combined 1
```

The other option is to steer packets to a single queue using `ethtool -N`, but the first option is
better for our case (and is supported on the NICs we use).

`pfe` has three levels of logging, accessible with the `-d` flag. Specify it multiple times to raise
the logging level. By default, it is not very chatty. Aside from startup and shutdown messages, it
will print statistics every minute (or on-demand if you send a SIGUSR1 to the process). Specifying
`-d` enables some more verbose logging, including the rewrite decision and some ARP
information. `-dd` enables lower-level debug output `-ddd` will print out hex dumps of every packet.

If you only want to process the configuration data, but not actually run the packet processing loop,
use `--configtest`. Among other things, this will tell you if the command line arguments are
correct, the IP map file is well-formed, whether it found the specified interface, and which IPs it
discovered on the interface.

By default, the program uses SKB mode when creating the AF_XDP socket. You can use the `--mode`
argument to specify a different mode (one of "skb", "driver", or "hw"), if you know that it is
supported. (If the mode you pick isn't supported by the driver or hardware, `pfe` will print an
error and exit.)

Finally, `pfe` supports both [FoU][fou] and GRE as the encapsulation protocol.  You can change this
via the `--tunnel` option (one of "fou" or "gre").  FoU is the default. Use the `--tunnel-port`
argument to specify the destination port for FoU encapsulation (5555 is the default).

## Specifying Routes

The program needs a list of (EIP, Private IP, Tunnel Source, Tunnel Destination, Tunnel Port) tuples
to know how to rewrite packets and where to send them. There are two ways to get this information:
via a "map file", or via the lantern-cloud API.

### Specifying Routes via Map File

When using `--mapfile`, the list of tuples comes from a pseudo-CSV file. An example of this file:

```
# EIP,   Private IP, Tunnel Source,          Tunnel Destination,     Tunnel Port
1.2.3.4, 10.0.0.1,   10.0.0.1,               5.6.7.8,                5555
1.2.3.5, 10.0.0.2,   10.0.0.2,               8.9.10.11,              4321
3.3.3.3, 10.0.0.3,   fd8f:f639:8080:39bc::1, fd8f:f639:8080:39bc::2, 5555
```

Lines beginning with `#` are ignored, as are empty lines. The IP order on each row is important. See
the first comment above for the order. For example, the first line above will rewrite `10.0.0.1` in
the original packet with `1.2.3.4`, and then encapsulate it in a tunnel with source 10.0.0.1 and
destination `5.6.7.8` (remember that the cloud will NAT the private address used as the tunnel
source back to the public address; we don't have to do that ourselves). If you do not specify a port
in the file, the default will be 5555.

Sending a SIGHUP to the `pfe` process will force it to reload its IP mapping from disk. Routes are
loaded atomically; that is, the old route list and the new list are swapped wholesale, not
one-at-a-time.

### Specifying Routes via the lantern-cloud API

`pfe` will sync every thirty seconds (give or take) with the lantern-cloud API when you specify the
`--config <file>` argument. The file is a TOML file in the format:

```
pfe_id = "d32879b4-88b5-5317-afd9-6739e10bd40b"
interface = "vnic0"
provider = "alicloud"
provider_location = "eu-central-1"
provider_id = "eni-gw8blhu5tzonadeansdv"
```

lantern-cloud will automatically create this file during provisioning, so this is only
informational.

The API should send routes back in its response, which are then loaded `pfe` just as if they had
been specified in a map file. (The API also uses this request/response as a way to gauge liveness of
`pfe` nodes.)

If you need to run `pfe` against the API but without the benefit of our certificate being in the
root CA list, you can use the `--certs` option to specify the path to a certificate bundle to add to
the existing root CAs.

## Command-Line Usage

```
Usage of ./pfe:
      --certs string       Path to a certificate bundle to load
  -c, --config string      Path to the configuration file
  -n, --configtest         Configtest mode. Exits after validating configuration.
  -d, --debug count        Enable debug output. Specify twice for more verbose output.
      --gateway4 string    The default IPv4 gateway to use. If not specified, pfe will try to discover the default route
      --gateway6 string    The default IPv6 gateway to use. If not specified, pfe will try to discover the default route
  -h, --help               Print this usage information
  -i, --interface string   The interface on which to listen
  -m, --mapfile string     A file with IP mappings
      --mode string        The XDP mode to use. Can be one of: skb, driver, or hw (default "skb")
      --queue int          NIC queue to use
      --tunnel string      The type of tunnel. Can be one of: fou, gre (default "fou")
```

## Future Work / Rough Edges

* When `pfe` starts up, it will discover the default IPv4 and IPv6 gateways (or you can specify them
  on the command line), and it consults the system's ARP cache to translate IPs to MACs. If it finds
  a MAC in the cache for an IP address, it will use that MAC as the destination MAC in the Ethernet
  header. If the IP does not exist in the ARP cache, it will then look up the MAC for the default
  gateway and use that. Finally, if the system ARP cache has no entry for the default gateway, `pfe`
  will fall back to simple MAC reversal. Because of this, it is feasible to run a test of `pfe` with
  three machines (client, `pfe`, backend) all in the same broadcast domain.

* When `pfe` starts up on an interface, that interface becomes a black hole; everything gets
  forwarded to the back-end proxy. (You don't really want anything responding to clients at this
  stage, anyway; that's for the back-end to do.) Unfortunately, this means that most broadcast
  traffic gets ignored, even if it shouldn't be. `pfe` will respond to IPv4 ARP requests, but in the
  future it might be nice (and possibly mandatory) if it could respond to [IPv6 Neighbor
  Discovery][nd] and some other intra-subnet multicast/broadcast traffic to be a nicer network
  citizen.

[haproxy-dsr]: https://www.haproxy.com/blog/layer-4-load-balancing-direct-server-return-mode/
[bcp38]: http://www.bcp38.info/index.php/Main_Page
[fou]: https://lwn.net/Articles/614348/
[nd]: https://www.rfc-editor.org/rfc/rfc2461
