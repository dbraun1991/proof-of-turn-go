# Agent guidance for proof-of-turn-go

## Module

Go module name is `pot-node`. All internal imports use this prefix:
`pot-node/block`, `pot-node/consensus`, etc.

## Package responsibilities

- `crypto` — primitives only; no protocol logic
- `block` — block construction and validation; no network or consensus concerns
- `blockchain` — chain storage and validation; no block construction
- `session` — bootstrap handshake only; runs once before consensus starts
- `network` — transport only; knows nothing about block semantics
- `consensus` — all state machine logic lives in `TurnManager.run()` — single goroutine, no locks on state fields
- `api` — thin HTTP adapter over consensus; no game logic
- `main` — wiring only; no business logic

## Key invariants

- `TurnManager.run()` is the sole goroutine accessing state fields — do not add mutexes to those fields
- Vote blocks are ephemeral (not appended to the chain) — see `TODO(on-chain-votes)` in `emitVoteBlock`
- `block.MoveSeed` is deterministic from the previous block hash — see `TODO(commit-reveal)`
- The HTTP API stamps the node's own `NodeID` as `PlayerID` on every move — clients do not supply it
- `session.Info.Validate()` enforces all cryptographic invariants on bootstrap; call it before starting consensus

## Testing patterns

- Unit tests use accelerated durations: `testTurn = 80ms`, `testTransition = 30ms`
- Two-node tests use `setupTwoNodes` which wires routing goroutines between two TurnManagers
- Missed-turn tests use `setupMissedTurnRig` (3 nodes, A offline, B↔C routed)
- `net.Pipe` is only used where synchronous write failure is needed; all other transport tests use real TCP via `tcpPair`
- Integration tests require Docker and run with `-tags integration`

## What to avoid

- Do not add game-specific logic (board state, dice rules) — this layer is game-agnostic
- Do not append vote blocks to the chain without addressing the fork divergence problem first
- Do not shorten `DefaultTransitionDuration` in production code — it is a thesis protocol constant
- Do not change the `TurnManager` event channel to a broadcast channel; the `api.Server.Run` goroutine is the sole consumer and fans out to SSE clients
