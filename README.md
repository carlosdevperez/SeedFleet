# SeedFleet

SeedFleet discovers devices on a local IPv4 network, keeps a process-local
inventory, and can bootstrap Docker Engine on a Linux host over SSH. It is the
small discovery foundation for a future fleet management system.

Only scan networks and administer hosts that you own or are authorized to
manage.

## Running

```sh
go run ./cmd/seedfleet
```

The server listens on `127.0.0.1:8080` by default. A scan is synchronous and
only one may run at a time:

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

## API

The API is intentionally small:

| Method and path | Behavior |
| --- | --- |
| `POST /scans` | Validates the CIDR, performs discovery, stores the observations, and returns the observed device collection with `200 OK` |
| `POST /deployments/docker` | Installs or verifies Docker Engine on one Linux host over SSH and returns the result with `200 OK` |
| `GET /devices` | Returns the accumulated in-memory inventory |
| `GET /health` | Returns `{"status":"ok"}` |

Scan requests require `Content-Type: application/json`. Unknown JSON fields and
multiple JSON values are rejected. An invalid or unauthorized network returns
`400 Bad Request`; a second scan while one is running returns `409 Conflict`.
There are no background scan jobs or inventory query language at this stage.

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

SeedFleet combines a small set of complementary signals:

- bounded TCP connect probes on ports 22, 80, 443, 445, and 3389;
- the Linux IPv4 neighbor table when available;
- local host identity;
- reverse DNS;
- mDNS/DNS-SD;
- SSDP device descriptions; and
- optional MAC-address aliases.

Successful TCP connections and explicit connection refusals both prove that a
host is reachable. On Linux, TCP attempts populate the neighbor cache and the
scanner then reads complete entries from `/proc/net/arp`. This also finds many
quiet devices that drop all configured TCP probes.

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

## Project layout

The layout follows the capability-oriented pattern used by
[kubernetes-sigs/kind](https://github.com/kubernetes-sigs/kind):

```text
main.go                         go-install entrypoint
cmd/seedfleet/                  executable and application entrypoint
pkg/cmd/seedfleet/              server command and HTTP transport
pkg/fleet/                      public discovery/inventory provider
pkg/fleet/devices/              public device types and merge rules
pkg/fleet/internal/inventory/   private in-memory store
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
```

The inventory is intentionally in memory and is lost when the process stops.
