# SeedFleet

SeedFleet discovers devices on a local IPv4 network and keeps an inventory in
memory or SQLite. It is the small discovery foundation for a future fleet
management system.

Only scan networks that you own or are authorized to inspect.

## Running

```sh
go run ./cmd/seedfleet
```

The server listens on `127.0.0.1:8080` by default. A scan is synchronous and
only one may run at a time. A complete all-port scan can take several minutes
or longer depending on the requested CIDR size and how many probes are silently
dropped:

```sh
curl -X POST http://127.0.0.1:8080/scans \
  -H 'Content-Type: application/json' \
  -d '{"network":"192.168.1.0/24"}'
```

List the accumulated inventory:

```sh
curl http://127.0.0.1:8080/devices
```

Health checks are available at `GET /health`.

Inventory is kept in memory by default. To retain it across restarts, supply a
SQLite file:

```sh
go run ./cmd/seedfleet --database ./seedfleet.db
```

Omit `--database` to switch back to the in-memory implementation. Both stores
implement the same provider-owned interface and use the same device refresh
rules.

## API

The API is intentionally small:

| Method and path | Behavior |
| --- | --- |
| `POST /scans` | Validates the CIDR, performs discovery, stores the observations, and returns the observed device collection with `200 OK` |
| `GET /devices` | Returns the accumulated inventory |
| `GET /health` | Returns `{"status":"ok"}` |

Scan requests require `Content-Type: application/json`. Unknown JSON fields and
multiple JSON values are rejected. An invalid or unauthorized network returns
`400 Bad Request`; a second scan while one is running returns `409 Conflict`.
There are no background scan jobs or inventory query language at this stage.
Every device representation includes an opaque `id` that remains stable when a
known MAC address moves to another IP address.

Canceling the HTTP request cancels outstanding discovery and port probes.

Device responses expose open TCP ports in the existing `openPorts` array and
open UDP ports in `openUdpPorts`:

```json
{
  "id": "dev_0123456789abcdef0123456789abcdef",
  "ip": "192.168.1.20",
  "openPorts": [22, 443],
  "openUdpPorts": [53, 5353]
}
```

## Discovery

SeedFleet combines a complete port sweep with complementary discovery signals:

- TCP connect probes on ports 1 through 65,535 for every usable address;
- UDP datagram probes on ports 1 through 65,535 for every usable address;
- the Linux IPv4 neighbor table when available;
- local host identity;
- reverse DNS;
- mDNS/DNS-SD;
- SSDP device descriptions; and
- optional MAC-address aliases.

Successful TCP connections and explicit connection refusals both prove that a
host is reachable. On Linux, the port attempts populate the neighbor cache and
the scanner then reads complete entries from `/proc/net/arp`. This also finds
quiet devices that drop every port probe.

TCP and UDP use separate bounded worker pools and run concurrently. Workers
atomically claim jobs from the address/port range instead of serializing behind
a single producer, and only positive observations are retained. The complete
target matrix is therefore covered without allocating it in memory.

A successful TCP connection is reported as open. UDP has no generic handshake,
so SeedFleet sends an empty datagram to each UDP port and reports a port as open
only if the endpoint replies. A silent UDP probe is inherently ambiguous—it may
be open with an application that ignores the empty payload, or a firewall may
have filtered it—so silence is not mislabeled as an open port. The sweep does
not perform application banner or version detection.

There is no universal unauthenticated protocol for device names. Aliases keep
names stable for devices that advertise identity intermittently:

```json
{
  "aa:bb:cc:dd:ee:ff": {
    "name": "Office printer",
    "hostname": "printer.local",
    "manufacturer": "Example Corp"
  }
}
```

The default file is `device-aliases.json`. Replace or disable it with:

```sh
go run ./cmd/seedfleet --aliases /path/to/aliases.json
go run ./cmd/seedfleet --aliases ''
```

## Scan safety

Networks are limited to 4,096 IPv4 addresses. By default, a requested CIDR must
fit completely inside a network on an active local interface. An allowlist can
narrow that boundary:

```sh
go run ./cmd/seedfleet --allow-network 192.168.1.0/24
```

Routed networks require an explicit allowlist and opt-in:

```sh
go run ./cmd/seedfleet \
  --allow-network 10.20.0.0/16 \
  --allow-routed-networks
```

An all-port sweep produces substantial network traffic. Scan only networks you
own or are authorized to inspect, and start with a narrow CIDR when possible.

## Project layout

The layout follows the capability-oriented pattern used by
[kubernetes-sigs/kind](https://github.com/kubernetes-sigs/kind):

```text
main.go                         go-install entrypoint
cmd/seedfleet/                  executable and application entrypoint
pkg/cmd/seedfleet/              server command and HTTP transport
pkg/fleet/                      public discovery/inventory provider
pkg/fleet/devices/              public device types and merge rules
pkg/fleet/internal/inventory/   private memory and SQLite stores
pkg/fleet/internal/scanner/     private network discovery implementation
```

The public entry point for future fleet features is `pkg/fleet.Provider`.
Implementation packages are protected by Go's `internal` import rule. See
[docs/architecture.md](docs/architecture.md) and the
[scanner map](pkg/fleet/internal/scanner/README.md) for the detailed call path.

## Development

```sh
make build
make test
make race
make verify
```

The default in-memory inventory is lost when the process stops. Use
`--database` when persistence is needed.
