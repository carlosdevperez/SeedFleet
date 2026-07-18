# Scanner package map

The scanner is split at protocol and operating-system boundaries so a failed
signal can be followed without reading unrelated network code. Discovery and
port inspection are deliberately separate capabilities:

```text
Scanner.Scan
  ├─ network authorization and CIDR bounds       network.go
  ├─ bounded TCP discovery and neighbor priming  tcp.go
  ├─ neighbor table and MAC aliases              neighbor*.go + alias.go
  ├─ concurrent identity sources                 identity.go
  │   ├─ current machine                         local.go
  │   ├─ SSDP and device-description XML         ssdp.go
  │   └─ mDNS/DNS-SD                             mdns.go + dns.go
  └─ reverse DNS and name finalization           identity.go

Scanner.InspectTCP
  ├─ explicit services/common/full-tcp profile   ports.go
  ├─ address-fair adaptive scheduling            ports.go
  └─ TCP connect and refusal classification      tcp.go
```

`scanner.go` remains the discovery coordinator. Protocol packet construction
and parsing belong in the protocol file, and platform-specific system access
belongs in a build-tagged `*_linux.go` or `*_other.go` file.

The main discovery extension points are `NeighborSource` and `IdentitySource`.
Source implementations return errors normally; the coordinator treats
independent naming and neighbor failures as best effort while cancellation
still stops the scan. Linux reads `/proc/net/arp`; the default neighbor source
is empty on other platforms until a native implementation is added.

Identity fields have deterministic precedence. A MAC alias fills identity
first, configured identity sources fill only missing fields in source order,
and reverse DNS is the final hostname fallback. Production source order is the
local host, SSDP, then mDNS/DNS-SD.

Every usable address receives only the small configured TCP discovery set. The
512-worker pass primes the neighbor cache, which is read immediately afterward.
Naming sources run concurrently, reverse DNS uses up to 128 workers, and SSDP
description fetching shares one HTTP transport across up to 64 workers.

Explicit TCP inspection accepts only an address selected by `fleet.Provider`
from inventory. The `services` profile checks a focused set, `common` checks
ports 1-1024 plus higher fleet services, and `full-tcp` is an explicit 1-65535
operation. The scheduler walks addresses round-robin, processes bounded batches,
and ramps from 128 to at most 1,024 workers. A sharp timeout-rate increase or
local descriptor/socket exhaustion halves the pool. Dialers are reused, open
ports are sorted, and cancellation stops each batch.

There is no generic UDP port sweep. mDNS and SSDP send valid protocol requests;
future UDP sources should do the same in their own protocol files. Empty UDP
datagrams are both slow and too ambiguous to support useful inventory.

The package intentionally does not include background scan jobs, public
per-source diagnostics, NetBIOS/NBNS, gateway-page scraping, ICMP, service
fingerprinting, or banner collection. Internal stage observations and scheduler
benchmarks support tuning without expanding the public API.

Parser fuzz targets are grouped in `protocol_fuzz_test.go`; focused examples
remain next to their protocol implementation.
