# Scanner package map

The scanner is intentionally split at protocol and operating-system boundaries
so a failed discovery signal can be followed without reading unrelated packet
code. The runtime path is:

```text
Scanner.Scan
  ├─ network authorization and CIDR bounds       network.go
  ├─ bounded connect probes                      tcp.go
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

The package intentionally does not include background scan jobs, per-source
diagnostics, NetBIOS/NBNS, gateway-page scraping, ICMP, or broad TCP port lists.
Add a discovery signal only in its own protocol file and keep the coordinator
small.

Parser fuzz targets are grouped in `protocol_fuzz_test.go`; focused example
tests remain next to their protocol implementation.
