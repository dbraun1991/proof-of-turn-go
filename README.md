# proof-of-turn-go

A [Proof-of-Turn](https://arxiv.org/pdf/2304.07384v1) consensus node written in Go.
Ordered, signed block production with round-robin turn slots, missed-turn recovery via majority vote, and an HTTP API for game clients.

Built as the backend for [dicepyre](https://github.com/dbraun1991/dicepyre) but intentionally game-agnostic — any client that can POST a move and consume SSE events can sit on top of it.

## Prerequisites

- Go 1.22+
- Docker (integration tests only)

## Quick start

Every node needs a persistent keypair. It is generated on first run:

```sh
# Terminal 1 — host (leads turn 0)
go run . --keyfile a.key --listen :7000 --expect 1

# Terminal 2 — joining node (leads turn 1)
go run . --keyfile b.key --listen :7001 --join localhost:7000
```

For three or more nodes each joiner must advertise a dialable address:

```sh
go run . --keyfile a.key --listen :7000 --expect 2
go run . --keyfile b.key --listen :7001 --advertise-addr localhost:7001 --join localhost:7000
go run . --keyfile c.key --listen :7002 --advertise-addr localhost:7002 --join localhost:7000
```

## Flags

| Flag | Default | Description |
|---|---|---|
| `--keyfile` | `node.key` | Keypair file — created on first run if absent |
| `--listen` | `:7000` | TCP address for block-traffic connections |
| `--advertise-addr` | `127.0.0.1:<port>` | Dialable address for peers (required for Docker / multi-machine) |
| `--join` | — | Host address to dial (omit to host the session) |
| `--expect` | `1` | Number of peers to wait for before starting (host only) |
| `--turn-duration` | `30s` | Length of each Leading Node's active window |
| `--transition-duration` | `5s` | Handover buffer between turns |
| `--api-addr` | `:8080` | HTTP API listen address |

## HTTP API

| Method | Route | Description |
|---|---|---|
| `POST` | `/move` | Submit a game move: `{"moveType","from","to"}` |
| `POST` | `/finalize` | End the current turn early (no-op if not leading) |
| `GET` | `/events` | SSE stream — one JSON event per state transition |
| `GET` | `/status` | Current state snapshot including this node's player identity |
| `GET` | `/chain` | Full block chain as a JSON array |

All responses include `Access-Control-Allow-Origin: *`.

### SSE event shape

```json
{"state":"leading","slot":0,"leaderId":"<hex>"}
```

States: `waiting`, `leading`, `transition`.

## Architecture

```
crypto      — Ed25519 key generation, signing, node ID derivation
block       — five PoT block types: genesis, game_move, transition, vote, finalizing
blockchain  — append-only validated chain with longest-chain replacement
session     — bootstrap handshake (Hello + SessionInfo)
network     — TCP peer transport, broadcast pool, full-mesh wiring
consensus   — Proof-of-Turn state machine (TurnManager)
api         — HTTP API backed by the consensus layer
main        — wires all packages; handles bootstrap, mesh, and chain sync
```

## Tests

```sh
# Unit tests (all packages)
go test ./...

# Integration tests (requires Docker — builds the node image on first run)
go test -tags integration -v -timeout 10m ./integration/...
```

## Block types

| Type | Purpose |
|---|---|
| `genesis` | Chain anchor, created by the session host |
| `game_move` | Single player action during the Leading Node's turn |
| `transition` | Turn handover — co-signed by outgoing and incoming Leading Node |
| `vote` | Missed-turn vote cast when the Leading Node fails to transition |
| `finalizing` | Early turn end requested by the Leading Node |

## Open TODOs

- **auth** — no authentication on the HTTP API; any client can submit moves
- **sync-resilience** — chain sync only tries the bootstrap host on rejoin
- **commit-reveal** — move randomness seed is computable before submission
