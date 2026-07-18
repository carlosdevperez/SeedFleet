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
pkg/fleet.Provider ──────── scan serialization and inventory orchestration
       │             │
       ▼             ▼
internal/scanner  internal/inventory
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
currently exposes two operations:

- `Scan`, which allows one active scan and stores successful observations; and
- `List`, which returns the current inventory.

Provider options configure aliases and network authorization without exposing
scanner implementation types.

### `pkg/fleet/devices`

This package defines public device data and the rules for combining same-scan
observations and refreshing historical inventory identity.

### `pkg/fleet/internal`

The scanner and memory inventory are private implementation packages. The Go
toolchain enforces this boundary, replacing the previous custom import-graph
test.

The scanner keeps protocol implementations isolated because packet parsing and
platform-specific system access are independently debugged. Its local README
maps the coordinator to each protocol file.

## Deliberate simplifications

The current boundaries are intentionally smaller than the previous layered
design:

- Scans are synchronous. Background jobs, progress state, and polling endpoints
  should be added only when a real caller needs them.
- Inventory exposes `List` rather than a general query language. Filtering can
  be introduced with a concrete fleet-management use case.
- The memory store is selected inside `Provider`; there is no public repository
  abstraction while only one implementation exists.
- Optional discovery sources are best effort. Their failures do not expand the
  public API into a diagnostics framework.
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

Before adding persistence or enrollment, define a durable device identity that
does not rely only on an IP address. If a second inventory implementation or a
second transport becomes necessary, introduce a narrow interface at its
consumer and extract only the capability that now has multiple implementations.
