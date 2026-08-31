# landscape-rill

> A multi-leg edge node: a **single-TUN, userspace router/gateway** built in Rust.

`landscape-rill` is the routing core of the landscape workspace. One edge node connects to
multiple overlay networks at the same time ("legs"), and forwarding decisions are made by a
**userspace route policy engine** — no kernel WireGuard, no multi-TUN model.

## Features

- **mesh leg** — self-built overlay network: self-written control plane (coordinator) + 34B-frame data plane
- **ts2021 leg** (P2) — tailscale-compatible control protocol; headscale transition → self-hosted server; official client apps join as leaf clients via WireGuard
- **dn42 leg** (P2) — boringtun + Rust eBGP-lite
- **Route policy engine** — LPM + source priority (`LAN > mesh > dn42 > tailnet`) + fallback
- **tun0 = LAN side; WAN NAT fallback** — mesh exit transparent (no NAT)
- **I/O-free core** (`rill-core`) — pure logic, wasm32/embedded ready with zero refactor

## Status

P0 done (official Tailscale apps join end-to-end via headscale, REQ-033), P1 mesh skeleton
mostly landed (REQ-022~REQ-032, 121+ unit tests, docker e2e, IPv6 dual-stack), P2 access legs
in progress.

## Architecture

```
┌──────────────────── landscape-rill edge node ────────────────────┐
│  ts2021 client leg (self-written, configurable URL)                │
│    ├─► self-hosted control server (headscale → self-hosted) ◄── official apps  │
│    ├─► official tailnet (backup exit)                            │
│    └─ WireGuard (boringtun) ⇄ official client nodes; subnet router broadcast │
│  mesh leg (self-written control plane + 34B frame data plane) ⇄ mesh nodes     │
│  dn42 leg (boringtun + Rust eBGP-lite) ⇄ dn42 peers               │
│  route policy engine (LPM + priority + fallback)                  │
│  tun0 = LAN side; WAN NAT fallback                                │
└───────────────────────────────────────────────────────────────────┘
```

## Workspace layout

```
landscape-rill/                  # cargo workspace
├── rill-proto/                  # protobuf schema + generated code (publish: landscape-rill-proto)
├── rill-core/                   # ★ I/O-free pure logic (crypto / frame / handshake / route / control)
├── rill-coord/                  # coordinator role (coordinator.rs + Ed25519 signer.rs)
├── rill-mesh/                   # mesh leg (control TLS + data UDP + framing)
├── rill-node/                   # node role glue (config / tun / packet / runtime)
├── rilld/                       # lrill binary (CLI entry)
├── e2e/                         # container verification (docker compose + assertions)
└── docs/                        # requirement → design → tests doc system
```

## Build & test

```bash
# release binary (shared by e2e and deployment)
./scripts/build.sh

# mesh e2e: CA/certs → configs → containers → mesh ping assertions (IPv4 + IPv6)
./e2e/run_e2e.sh
```

## Documentation

Docs follow a requirement-driven evolution system: `docs/requirements/` (why/when) →
`docs/design/` (authoritative behavior) → `docs/tests/` (acceptance) → `e2e/ci` (evidence).

- Start here: [docs/CONTEXT.md](docs/CONTEXT.md) — terminology, trust model, roadmap
- Docs center: [docs/README.md](docs/README.md) — reading route + three maps
- Design (short-name registry, e.g. `FRAME_HEADER §2.6`): [docs/design/README.md](docs/design/README.md)
- Chinese version of this file: [README.zh.md](README.zh.md)

## Roadmap

| Phase | Content |
|---|---|
| P0 | headscale + derper deployment, official app joins end-to-end — **done (REQ-033)** |
| P1 | mesh skeleton: crates + mesh leg (single coordinator + 34B frame) — **mostly done** |
| v1.5 | Path Service (control plane): Path* message family, fast switch, path lifecycle |
| P2 | access legs: ts2021 client leg + dn42 leg (eBGP-lite) |
| P3 | convergence: route engine polish, exit semantics, self-hosted ts2021 server, Raft |
| P4 | performance & federation: XDP fast path, unified DNS, federation v2, path_id data plane |

## License

LGPL-3.0-only — see [LICENSE](LICENSE).
