# SeedFleet architecture

SeedFleet is organized by capability rather than by generic architecture layer.
This mirrors the pattern used by `kind`: a small public provider package owns
the supported operations and delegates implementation details to packages that
Go prevents external callers from importing.

## Call path

```text
main.go / cmd/seedfleet
          │
          ▼
cmd/seedfleet/app.Main
          │
          ▼
pkg/cmd/seedfleet.Run ───── HTTP request/response handling
          │
          ▼
pkg/fleet.Provider ──────── fleet operation orchestration
       │             │                 │
       ▼             ▼                 ▼
internal/scanner  internal/inventory  internal/dockerinstaller
       │             │
       └──────┬──────┘
              ▼
      pkg/fleet/devices
```

## Package responsibilities

### `cmd/seedfleet`

Both the repository root and `cmd/seedfleet` are thin executable stubs. They
delegate to `cmd/seedfleet/app.Main`, matching `kind`'s entrypoint pattern. The
app package owns process signals and exit behavior, leaving the server command
callable from Go.

### `pkg/cmd/seedfleet`

This package parses server flags, composes the fleet provider, configures HTTP
timeouts, and translates between JSON and public fleet types. HTTP-specific
status codes and strict request decoding stay here.

### `pkg/fleet`

`Provider` is the public API and the extension point for fleet management. It
exposes four operations:

- `Scan`, which allows one active scan and stores successful observations;
- `List`, which returns the current inventory;
- `InstallDocker`, which allows one active deployment and synchronously
  bootstraps Docker Engine on a Linux host over SSH; and
- `Close`, which releases the configured inventory.

Provider options configure aliases, network authorization, and optional SQLite
persistence without exposing implementation types.

### `pkg/fleet/devices`

This package defines public device data, its durable opaque ID, and the rules
for combining same-scan observations and refreshing historical inventory
identity. Stores reconcile a known MAC address before its IP so the ID survives
DHCP address changes. `OpenPorts` retains the established TCP-port
representation, while `OpenUDPPorts` records UDP ports that responded to a
probe. Both collections represent the latest scan.

### `pkg/fleet/internal`

The scanner, memory and SQLite inventories, and Docker installer are private
implementation packages. `Provider` owns a narrow inventory interface
containing only `Save`, `List`, and `Close`, so tests and implementations can be
swapped without exposing storage through the public API. The Go toolchain
enforces this boundary, replacing the previous custom import-graph test.

The scanner keeps protocol implementations isolated because packet parsing and
platform-specific system access are independently debugged. Its local README
maps the coordinator to each protocol file. The Docker installer is isolated
from discovery and embeds the small POSIX shell program streamed through the
user's local OpenSSH client.

The scanner runs complete TCP and UDP port ranges concurrently for every usable
address in the authorized CIDR while identity protocols gather complementary
observations. It reads neighbors after the sweep so Linux has a chance to
populate its cache. `Provider` still owns scan serialization and commits only
the completed observation batch to inventory.

## Deliberate simplifications

The current boundaries are intentionally smaller than the previous layered
design:

- Scans are synchronous. Background jobs, progress state, and polling endpoints
  should be added only when a real caller needs them.
- Inventory exposes `List` rather than a general query language. Filtering can
  be introduced with a concrete fleet-management use case.
- The memory store remains the default. `ProviderWithSQLiteInventory` selects
  persistence, and the server exposes that choice as `--database`.
- Optional discovery sources are best effort. Their failures do not expand the
  public API into a diagnostics framework.
- Docker deployment is synchronous and uses the official convenience installer
  as an explicit early-stage tradeoff. Durable jobs, per-distribution package
  plans, version pinning, and deployment history can follow concrete needs.
- NetBIOS and gateway-page scraping are not part of discovery. New signals
  should provide enough value to justify their network traffic and maintenance
  cost.

These are product decisions, not missing layers to recreate preemptively.

## Extension rules

- Add a fleet operation to `Provider` before exposing it over HTTP.
- Put public data used by callers under `pkg/fleet` or a focused subpackage.
- Put provider-only implementations under `pkg/fleet/internal`.
- Keep JSON tags and HTTP errors in `pkg/cmd/seedfleet`.
- Keep protocol packet handling inside the matching scanner file.
- Prefer a focused package over a generic `service`, `adapter`, or `utils`
  package.

Keep storage interfaces narrow and owned by their consumer. Extend the durable
identity model before adding identity signals beyond MAC address and IP fallback.
