# Scanner package map

The scanner is intentionally split at protocol and operating-system boundaries
so a failed discovery signal can be followed without reading unrelated packet
code. The runtime path is:

```text
Scanner.Scan
  ├─ network authorization and CIDR bounds       network.go
  ├─ concurrent all-address port sweep           ports.go
  │   ├─ TCP ports 1-65535                       tcp.go
  │   └─ UDP ports 1-65535                       udp.go
  ├─ neighbor table and MAC aliases              neighbor*.go + alias.go
  ├─ concurrent identity sources                 identity.go
  │   ├─ current machine                         local.go
  │   ├─ SSDP and device-description XML         ssdp.go
  │   └─ mDNS/DNS-SD                             mdns.go + dns.go
  └─ reverse DNS and name finalization           identity.go
```

`scanner.go` is only the coordinator. Protocol packet construction and parsing
belong in the protocol file, and platform-specific
system access belongs in a build-tagged `*_linux.go` or `*_other.go` file.

The main extension points are `NeighborSource` and `IdentitySource`. Source
implementations should return errors normally; the coordinator treats
independent naming and neighbor failures as best effort while cancellation still
stops the scan. Linux reads `/proc/net/arp`; the default neighbor source is empty
on other platforms until a native implementation is added.

Identity fields follow deterministic precedence. A MAC alias fills identity
first, configured identity sources fill only missing fields in source order,
and reverse DNS is the final hostname fallback. The production order is local
host identity, SSDP, then mDNS/DNS-SD.

Every usable address in the authorized CIDR is included in both full port
ranges, so a device can be discovered through a service outside a small
well-known-port list. TCP and UDP run concurrently with one bounded worker pool
per transport. Workers atomically claim indices from the address/port product,
avoiding both a serialized job producer and construction of the Cartesian
product in memory. Naming sources run concurrently with the transport sweeps.

TCP reports successful connections. UDP sends an empty datagram and reports
only ports that reply; a timeout is `open|filtered` in port-scanning terms and
is deliberately omitted from `OpenUDPPorts` rather than represented as known
open. Cancellation closes in-flight UDP connections and stops both worker
pools.

The package intentionally does not include background scan jobs, per-source
diagnostics, NetBIOS/NBNS, gateway-page scraping, ICMP, service fingerprinting,
or banner collection. Neighbor and identity sources remain complementary to
the port sweep. Add a discovery signal only in its own protocol file and keep
the coordinator small.

Parser fuzz targets are grouped in `protocol_fuzz_test.go`; focused example
tests remain next to their protocol implementation.
