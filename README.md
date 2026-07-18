# SeedFleet

SeedFleet discovers devices on a local IPv4 network, keeps an inventory in
memory or SQLite, and can bootstrap Docker Engine on a Linux host over SSH. It
is the small discovery foundation for a future fleet management system.

Only scan networks and administer hosts that you own or are authorized to
manage.

## Running

```sh
go run ./cmd/seedfleet
```

The server listens on `127.0.0.1:8080` by default. Network discovery is
synchronous and only one discovery scan may run at a time. Discovery uses a
small bounded probe set plus local-network identity signals; exhaustive port
inspection is a separate device operation and never delays this request:

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
| `POST /devices/{id}/port-inspections` | Inspects TCP services on one inventoried device using an explicit profile |
| `POST /deployments/docker` | Installs or verifies Docker Engine on one Linux host over SSH and returns the result with `200 OK` |
| `GET /devices` | Returns the accumulated inventory |
| `GET /health` | Returns `{"status":"ok"}` |

Scan requests require `Content-Type: application/json`. Unknown JSON fields and
multiple JSON values are rejected. An invalid or unauthorized network returns
`400 Bad Request`; a second scan while one is running returns `409 Conflict`.
There are no background scan jobs or inventory query language at this stage.
Every device representation includes an opaque `id` that remains stable when a
known MAC address moves to another IP address.

Canceling an HTTP request cancels its outstanding discovery or port probes.

Device responses expose TCP ports found by the bounded discovery pass in
`openPorts`. `openUdpPorts` remains in the representation for compatibility,
but SeedFleet no longer labels ports from generic empty UDP datagrams:

```json
{
  "id": "dev_0123456789abcdef0123456789abcdef",
  "ip": "192.168.1.20",
  "openPorts": [22, 443],
  "openUdpPorts": []
}
```

## Targeted TCP inspection

Port inspection requires a durable device ID returned by `POST /scans` or
`GET /devices`. It never expands a CIDR into an all-address, all-port matrix.
The default `services` profile checks a small fleet-oriented set:

```sh
curl -X POST \
  http://127.0.0.1:8080/devices/dev_0123456789abcdef0123456789abcdef/port-inspections \
  -H 'Content-Type: application/json' \
  -d '{"profile":"services"}'
```

Available profiles are:

- `services`: 23 fleet-oriented TCP services;
- `common`: ports 1-1024 plus relevant higher service ports; and
- `full-tcp`: every TCP port, explicitly requested for one known device.

Completed results are cached for five minutes. Use `{"profile":"common",
"refresh":true}` to bypass a completed cache entry. Identical concurrent
requests share the same network operation. Responses report the number of
ports probed, peak worker concurrency, duration, reachability, timestamp, and
whether the result came from cache.

The TCP inspection pool starts at 128 workers and ramps as high as 1,024 while
the timeout rate remains stable. It backs off when increasing timeouts or local
socket-resource errors indicate pressure. A full TCP inspection can still be
slow when a target silently filters connections; client cancellation stops it.

## Remote Docker deployment

The first deployment mechanism deliberately reuses the local OpenSSH client.
SeedFleet does not accept or store passwords: authentication, host aliases,
keys, agents, ports, jump hosts, and host-key verification remain in the
account's existing SSH configuration.

Before using the endpoint, make sure this succeeds non-interactively and that
the host key has already been accepted:

```sh
ssh -o BatchMode=yes operator@node-1.local true
```

The remote host must run Linux, have internet access plus `curl` or `wget`, and
allow either a root login or passwordless `sudo`. Start a synchronous
deployment with:

```sh
curl -X POST http://127.0.0.1:8080/deployments/docker \
  -H 'Content-Type: application/json' \
  -d '{"host":"node-1.local","user":"operator"}'
```

`user` and `port` are optional. Omitting them lets the SSH configuration choose
the values. A successful response reports whether Docker was installed or was
already present:

```json
{
  "host": "node-1.local",
  "user": "operator",
  "status": "installed",
  "version": "Docker version 28.0.1, build 1234567"
}
```

SeedFleet streams an embedded POSIX shell script to the host. It downloads
Docker's [official convenience installer](https://docs.docker.com/engine/install/ubuntu/#install-using-the-convenience-script),
starts the daemon when necessary, and verifies it with `docker info`. Repeating
the request does not rerun the convenience installer when the `docker` command
is already present. Only one Docker deployment runs at a time, and each HTTP
request has a ten-minute timeout.

This initial mechanism is for development and early fleet bootstrapping.
Docker itself recommends the convenience installer only for testing and
development. It always installs the current stable release and does not yet
provide version pinning, installer checksum pinning, target allowlists,
deployment history, or background progress. Keep the unauthenticated SeedFleet
API on its default loopback address while using this endpoint.

## Discovery

SeedFleet combines bounded reachability probes with complementary discovery
signals:

- TCP reachability on ports 22, 80, 443, 445, and 3389;
- the Linux IPv4 neighbor table when available;
- local host identity;
- reverse DNS;
- mDNS/DNS-SD;
- SSDP device descriptions; and
- optional MAC-address aliases.

Successful TCP connections and explicit connection refusals both prove that a
host is reachable. The 512-worker bounded pass also populates the Linux neighbor
cache, which SeedFleet reads immediately through `/proc/net/arp`. This finds
many quiet local devices that drop every configured TCP connection. Identity
sources run concurrently, reverse DNS uses up to 128 workers, and SSDP device
descriptions share a connection pool with up to 64 workers.

UDP discovery is protocol-aware: mDNS/DNS-SD and SSDP construct valid protocol
messages. SeedFleet does not send empty datagrams to every UDP port because
silence cannot distinguish an open service from a firewall and most services
ignore invalid payloads. New UDP discovery belongs in a focused protocol file.

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

Full TCP inspection produces substantial traffic even though it targets only
one inventoried device. Inspect only devices you own or are authorized to
inspect.

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
pkg/fleet/internal/dockerinstaller/ private SSH Docker bootstrap implementation
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
make bench
```

The default in-memory inventory is lost when the process stops. Use
`--database` when persistence is needed.
