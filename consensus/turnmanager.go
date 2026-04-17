// Package consensus implements the Proof-of-Turn state machine.
//
// Full protocol specification: https://arxiv.org/pdf/2304.07384v1
//
// # State diagram
//
//	                    turn timer fires
//	┌──────────┐ ──────────────────────────► ┌────────────┐
//	│ LEADING  │                             │ TRANSITION │ ── transition timer fires ──► WAITING or LEADING
//	└──────────┘ ◄─────────────────────────── └────────────┘              (next slot decides)
//	     ▲              (if next slot is ours)
//	     │
//	     └── forced handover (vote threshold reached) ◄── WAITING: watchdog fires, votes exchanged
//
// WAITING: a different node holds the turn slot. This node validates incoming
// blocks, queues moves for later, and runs a watchdog timer. If the watchdog
// expires without a Transition block arriving the node emits a Vote block and
// begins the missed-turn recovery path.
//
// LEADING: this node is the current Leading Node (LN). It is the only node
// allowed to create and broadcast blocks. O(1) block creation — an Ed25519
// signature is the entire proof of authority.
//
// TRANSITION: the fixed buffer between turn slots. No blocks are produced by
// anyone. All nodes wait synchronously before the next LN begins. The 5-second
// constant prevents race conditions between outgoing and incoming Leading Nodes
// and must not be shortened in production.
//
// # Communication model
//
// The state machine runs a single goroutine via Run. Callers interact through
// two inputs (SubmitMove, ReceiveBlock) and two output channels (OutBlocks,
// Events). All internal state is accessed exclusively from that goroutine —
// no locks are needed for the state fields.
//
// # Transition block handshake (normal handover)
//
// When the Leading Node's turn expires, it emits a half-signed Transition block
// (signed by the outgoing LN only) and enters TRANSITION. Upon receipt, the
// designated incoming LN adds its co-signature and rebroadcasts. All other
// nodes receive the fully co-signed block and start their own transition timers.
// Both signatures cover identical hash bytes — the co-signer's identity is
// intentionally excluded from the hash so it can be computed before the
// co-signer is known (see block.computeHash).
//
// # Missed-turn recovery (vote path)
//
// Every waiting node arms a watchdog timer for TurnDuration + TransitionDuration.
// If no Transition block arrives before the watchdog fires, the node emits a
// signed Vote block naming the absent leader and broadcasts it to all peers.
//
// Vote blocks are counted in memory (not appended to the chain — see the TODO
// in emitVoteBlock). When a strict majority of nodes — threshold (N+1)/2 — have
// voted for the same missed leader, all nodes that reached the threshold
// immediately advance to the next slot without a transition window. This skips
// the absent node and installs the next peer as the new Leading Node.
//
// Note: with N=2, the threshold is 2 — a single waiting node can never reach
// majority alone. Missed-turn recovery requires at least 3 nodes.
package consensus

import (
	"context"
	"crypto/ed25519"
	"sync"
	"time"

	"pot-node/block"
	"pot-node/blockchain"
	"pot-node/crypto"
)

// DefaultTurnDuration is the default length of each Leading Node's active window.
// The Elixir prototype used 30 seconds; tune this to the game's desired pace.
const DefaultTurnDuration = 30 * time.Second

// DefaultTransitionDuration is the 5-second buffer between turn slots specified
// by the thesis. It prevents race conditions during handover and must not be
// shortened in production. Exposed as a field in Config only for accelerated tests.
const DefaultTransitionDuration = 5 * time.Second

// TurnState describes a node's position in the current turn cycle.
type TurnState int

const (
	// StateWaiting: a different node holds the turn slot.
	// This node validates incoming blocks and queues its own moves.
	StateWaiting TurnState = iota

	// StateLeading: this node is the current Leading Node.
	// It is the only node permitted to create and broadcast blocks.
	StateLeading

	// StateTransition: the buffer between turn slots.
	// No blocks are produced; all nodes wait for the incoming LN to begin.
	StateTransition
)

func (s TurnState) String() string {
	switch s {
	case StateWaiting:
		return "waiting"
	case StateLeading:
		return "leading"
	case StateTransition:
		return "transition"
	default:
		return "unknown"
	}
}

// Event is emitted on the Events channel whenever the turn state changes.
type Event struct {
	State    TurnState // this node's new state
	LeaderID string    // node ID of the current Leading Node
	Slot     int       // index of the current leader in the peer list
}

// Config holds the static configuration for a TurnManager.
// All fields are set once at construction and never mutated.
type Config struct {
	// NodeID is this node's identifier, matching crypto.NodeID(KeyPair.Public).
	NodeID  string
	KeyPair crypto.KeyPair

	// Peers is the ordered list of all node IDs in the session, including this
	// node. Turn order follows this list in a round-robin cycle that repeats for
	// the lifetime of the session. Position in this list determines when a node
	// leads; the list must be identical on every node.
	Peers    []string
	PeerKeys map[string]ed25519.PublicKey // node ID → public key, used to verify incoming blocks

	// TurnDuration is how long each Leading Node holds its slot.
	// Defaults to DefaultTurnDuration if zero.
	TurnDuration time.Duration

	// TransitionDuration is the buffer between turns.
	// Defaults to DefaultTransitionDuration (5s) if zero.
	// Override only in tests — production must use the 5-second thesis constant.
	TransitionDuration time.Duration
}

// TurnManager implements the Proof-of-Turn consensus state machine.
// See the package documentation for the state diagram and communication model.
type TurnManager struct {
	cfg   Config
	chain *blockchain.Chain

	// These fields are accessed exclusively from within the Run goroutine.
	// No synchronisation is needed — the select loop serialises all access.
	state   TurnState
	slot    int // index of the current leader in cfg.Peers
	pending []block.GameMoveData

	// Missed-turn vote tracking. Reset on every slot advance.
	votes         map[string]struct{} // voter IDs for the current slot's missed-turn event
	votedThisSlot bool                // true once this node has emitted a vote this slot

	// Input channels — written by callers, read by the Run goroutine.
	moves    chan block.GameMoveData
	inBlock  chan *block.Block
	finalize chan struct{}

	// Output channels — written by the Run goroutine, read by callers.
	outBlock chan *block.Block
	events   chan Event

	once sync.Once // ensures Run is only called once
}

// New creates a TurnManager. chain must already contain a genesis block.
// Call Run to start the state machine.
func New(cfg Config, chain *blockchain.Chain) *TurnManager {
	if cfg.TurnDuration == 0 {
		cfg.TurnDuration = DefaultTurnDuration
	}
	if cfg.TransitionDuration == 0 {
		cfg.TransitionDuration = DefaultTransitionDuration
	}
	return &TurnManager{
		cfg:      cfg,
		chain:    chain,
		votes:    make(map[string]struct{}),
		moves:    make(chan block.GameMoveData, 64),
		inBlock:  make(chan *block.Block, 64),
		finalize: make(chan struct{}, 1),
		outBlock: make(chan *block.Block, 64),
		events:   make(chan Event, 16),
	}
}

// OutBlocks returns the channel on which the manager emits blocks to broadcast
// to all peers. The caller is responsible for draining this channel continuously;
// a full buffer causes blocks to be silently dropped.
func (tm *TurnManager) OutBlocks() <-chan *block.Block {
	return tm.outBlock
}

// Events returns the channel on which the manager emits state change
// notifications. The caller is responsible for draining this channel.
func (tm *TurnManager) Events() <-chan Event {
	return tm.events
}

// SubmitMove queues a game move for this node's player.
//
// If this node is currently leading, a GameMoveBlock is created and broadcast
// immediately. Otherwise the move is held in a pending queue and flushed — in
// submission order — when this node next becomes the Leading Node.
//
// Non-blocking: silently drops the move if the internal buffer is full.
func (tm *TurnManager) SubmitMove(move block.GameMoveData) {
	select {
	case tm.moves <- move:
	default:
	}
}

// FinalizeTurn signals the Leading Node to end its turn immediately, without
// waiting for the turn timer to expire. A FinalizingBlock is broadcast to all
// peers, then the normal transition handshake begins as if the timer had fired.
//
// Non-blocking and a no-op if this node is not currently leading or the buffer
// is already full.
func (tm *TurnManager) FinalizeTurn() {
	select {
	case tm.finalize <- struct{}{}:
	default:
	}
}

// ReceiveBlock delivers a block received from a peer to the state machine for
// validation and processing.
//
// Non-blocking: silently drops the block if the internal buffer is full.
func (tm *TurnManager) ReceiveBlock(b *block.Block) {
	select {
	case tm.inBlock <- b:
	default:
	}
}

// Run starts the state machine and blocks until ctx is cancelled.
// Must only be called once per TurnManager; subsequent calls are no-ops.
func (tm *TurnManager) Run(ctx context.Context) {
	tm.once.Do(func() { tm.run(ctx) })
}

// slotFromChain determines the current turn slot by replaying the chain.
// Each completed Transition block advances the slot by one. Returns 0 for a
// fresh chain. This lets a rejoining node resume at the correct slot after
// catching up via chain sync.
func (tm *TurnManager) slotFromChain() int {
	slot := 0
	for _, b := range tm.chain.Blocks() {
		if b.Type == block.BlockTypeTransition {
			slot = (slot + 1) % len(tm.cfg.Peers)
		}
	}
	return slot
}

func (tm *TurnManager) run(ctx context.Context) {
	// Derive the starting slot from the chain so a rejoining node with a synced
	// chain resumes at the correct position rather than always starting at 0.
	tm.slot = tm.slotFromChain()

	// turnTimer fires when the Leading Node's active window expires.
	// Only armed while this node is leading.
	turnTimer := time.NewTimer(tm.cfg.TurnDuration)

	// watchdogC fires when the expected turn+transition window has elapsed
	// without a Transition block arriving. Only armed while this node is waiting.
	// A nil channel is never selected — idiomatic Go for "disabled branch".
	var watchdogC <-chan time.Time

	// transitionC fires after the transition window. Nil when not in transition.
	var transitionC <-chan time.Time

	if tm.isLeader() {
		tm.enterLeading()
	} else {
		tm.enterWaiting()
		turnTimer.Stop()
		watchdogC = time.After(tm.cfg.TurnDuration + tm.cfg.TransitionDuration)
	}
	defer turnTimer.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case move := <-tm.moves:
			if tm.state == StateLeading {
				tm.emitMoveBlock(move)
			} else {
				tm.pending = append(tm.pending, move)
			}

		case b := <-tm.inBlock:
			transition, forced := tm.handleIncoming(b)
			if transition {
				// A valid Transition block arrived — arm the transition timer and
				// cancel the watchdog (the leader did not miss its turn).
				transitionC = time.After(tm.cfg.TransitionDuration)
				watchdogC = nil
			}
			if forced {
				// Vote threshold reached — slot already advanced inside handleIncoming.
				transitionC = nil
				watchdogC = nil
				if tm.isLeader() {
					tm.enterLeading()
					turnTimer.Reset(tm.cfg.TurnDuration)
				} else {
					tm.enterWaiting()
					watchdogC = time.After(tm.cfg.TurnDuration + tm.cfg.TransitionDuration)
				}
			}

		case <-tm.finalize:
			// Frontend requested early turn end. Broadcast a Finalizing block so
			// all peers record the early termination, then proceed with the normal
			// transition handshake — identical to the turn-timer path.
			if tm.state == StateLeading {
				tm.emitFinalizingBlock()
				turnTimer.Stop()
				tm.endTurn()
				transitionC = time.After(tm.cfg.TransitionDuration)
			}

		case <-turnTimer.C:
			// Our turn slot has expired. Emit a half-signed Transition block and
			// enter the transition window. The incoming LN will co-sign it on receipt.
			tm.endTurn()
			transitionC = time.After(tm.cfg.TransitionDuration)

		case <-transitionC:
			transitionC = nil
			tm.advanceSlot()
			if tm.isLeader() {
				tm.enterLeading()
				turnTimer.Reset(tm.cfg.TurnDuration)
			} else {
				tm.enterWaiting()
				watchdogC = time.After(tm.cfg.TurnDuration + tm.cfg.TransitionDuration)
			}

		case <-watchdogC:
			// The expected leader did not transition within its window.
			// Emit a vote block and check whether we've reached the threshold.
			watchdogC = nil
			if tm.state == StateWaiting && !tm.votedThisSlot {
				if tm.emitVoteBlock(tm.cfg.Peers[tm.slot]) {
					// Our vote pushed the count over the threshold.
					transitionC = nil
					tm.advanceSlot()
					if tm.isLeader() {
						tm.enterLeading()
						turnTimer.Reset(tm.cfg.TurnDuration)
					} else {
						tm.enterWaiting()
						watchdogC = time.After(tm.cfg.TurnDuration + tm.cfg.TransitionDuration)
					}
				}
			}
		}
	}
}

// enterLeading sets state to StateLeading, emits an event, and flushes pending moves.
// Pending moves are submitted in FIFO order so game state remains deterministic.
func (tm *TurnManager) enterLeading() {
	tm.state = StateLeading
	tm.emitEvent()
	tm.flushPending()
}

// enterWaiting sets state to StateWaiting and emits an event.
func (tm *TurnManager) enterWaiting() {
	tm.state = StateWaiting
	tm.emitEvent()
}

// enterTransition sets state to StateTransition and emits an event.
func (tm *TurnManager) enterTransition() {
	tm.state = StateTransition
	tm.emitEvent()
}

// endTurn creates a half-signed Transition block naming the next LN, broadcasts
// it, and enters the transition window. The block is not appended to this node's
// chain until the incoming LN returns it with their co-signature.
func (tm *TurnManager) endTurn() {
	nextSlot := (tm.slot + 1) % len(tm.cfg.Peers)
	toID := tm.cfg.Peers[nextSlot]
	b, err := block.NewTransitionBlock(tm.chain.Latest(), tm.cfg.NodeID, toID, tm.cfg.KeyPair.Private)
	if err != nil {
		return
	}
	tm.broadcast(b)
	tm.enterTransition()
}

// handleIncoming validates and processes a block received from a peer.
//
//   - transitionStarted: caller should arm the transition timer
//   - forcedHandover: vote threshold was reached; slot already advanced, caller
//     should update turn/watchdog timers to match the new state
func (tm *TurnManager) handleIncoming(b *block.Block) (transitionStarted, forcedHandover bool) {
	switch b.Type {
	case block.BlockTypeVote:
		if tm.tallyVote(b) {
			tm.advanceSlot()
			return false, true
		}
		return false, false

	case block.BlockTypeTransition:
		return tm.handleTransition(b), false

	default:
		// Normal block: validate and append. Invalid blocks are silently dropped.
		_ = tm.chain.Append(b, tm.cfg.PeerKeys)
		return false, false
	}
}

// handleTransition processes an incoming Transition block (half- or fully-signed).
// Returns true if a transition window just started on this node.
func (tm *TurnManager) handleTransition(b *block.Block) (transitionStarted bool) {
	var data block.TransitionData
	if err := b.DecodeData(&data); err != nil {
		return false
	}

	if b.CoSignerID == "" {
		// Half-signed Transition block from the outgoing LN.
		// If we are the designated incoming LN, add our co-signature and rebroadcast.
		// Nodes not addressed here ignore this block and wait for the co-signed version.
		if data.To != tm.cfg.NodeID {
			return false
		}
		if err := block.AddCoSignature(b, tm.cfg.NodeID, tm.cfg.KeyPair.Private); err != nil {
			return false
		}
		if err := tm.chain.Append(b, tm.cfg.PeerKeys); err != nil {
			return false
		}
		tm.broadcast(b)
		tm.enterTransition()
		return true
	}

	// Fully co-signed Transition block.
	if err := tm.chain.Append(b, tm.cfg.PeerKeys); err != nil {
		return false
	}
	if tm.state != StateTransition {
		// This node observed the handover as a bystander (neither the outgoing
		// nor the incoming LN). Enter transition and arm the timer.
		tm.enterTransition()
		return true
	}
	// The outgoing LN is already in StateTransition (its own timer is running).
	// Appending the now-complete block to its chain is enough; no new timer needed.
	return false
}

// voteThreshold returns the minimum number of votes required to force a handover.
// With N nodes, any strict majority can override a missing leader.
// Note: with N=2, threshold=2 — a single waiting node can never reach majority alone,
// so missed-turn recovery requires at least 3 nodes.
func (tm *TurnManager) voteThreshold() int {
	return (len(tm.cfg.Peers) + 1) / 2
}

// tallyVote validates an incoming Vote block and adds it to the running count.
// Returns true when the vote threshold is reached and a forced handover should occur.
func (tm *TurnManager) tallyVote(b *block.Block) bool {
	var data block.VoteData
	if err := b.DecodeData(&data); err != nil {
		return false
	}
	if data.MissedNode != tm.cfg.Peers[tm.slot] {
		return false // vote targets a different slot — ignore
	}
	if err := b.VerifySignatures(tm.cfg.PeerKeys); err != nil {
		return false
	}
	tm.votes[data.VoterID] = struct{}{}
	return len(tm.votes) >= tm.voteThreshold()
}

// emitVoteBlock broadcasts a Vote block naming missedNodeID as the absent leader.
// The node's own vote is counted immediately (before the broadcast reaches peers).
// Returns true if that count already meets the threshold — caller handles handover.
//
// TODO(on-chain-votes): Vote blocks are currently ephemeral (not appended to the
// chain) to avoid fork divergence when multiple nodes vote simultaneously. A proper
// implementation would use an ordered, chain-anchored vote log.
func (tm *TurnManager) emitVoteBlock(missedNodeID string) bool {
	b, err := block.NewVoteBlock(tm.chain.Latest(), tm.cfg.NodeID, block.VoteData{
		MissedNode: missedNodeID,
		VoterID:    tm.cfg.NodeID,
	}, tm.cfg.KeyPair.Private)
	if err != nil {
		return false
	}
	tm.votes[tm.cfg.NodeID] = struct{}{} // count own vote before broadcast completes
	tm.votedThisSlot = true
	tm.broadcast(b)
	return len(tm.votes) >= tm.voteThreshold()
}

// emitMoveBlock creates a GameMoveBlock for move, appends it to the local chain,
// and broadcasts it. Called only while this node is the Leading Node.
func (tm *TurnManager) emitMoveBlock(move block.GameMoveData) {
	move.Seed = block.MoveSeed(tm.chain.Latest())
	b, err := block.NewGameMoveBlock(tm.chain.Latest(), tm.cfg.NodeID, move, tm.cfg.KeyPair.Private)
	if err != nil {
		return
	}
	if err := tm.chain.Append(b, nil); err != nil {
		return
	}
	tm.broadcast(b)
}

// emitFinalizingBlock creates a FinalizingBlock, appends it to the local chain,
// and broadcasts it to all peers. Called only when this node is the Leading Node
// and a FinalizeTurn request was received.
func (tm *TurnManager) emitFinalizingBlock() {
	b, err := block.NewFinalizingBlock(tm.chain.Latest(), tm.cfg.NodeID, tm.cfg.KeyPair.Private)
	if err != nil {
		return
	}
	if err := tm.chain.Append(b, nil); err != nil {
		return
	}
	tm.broadcast(b)
}

// flushPending submits each queued move as a block, in FIFO order, then clears
// the queue. Called immediately on entering StateLeading.
func (tm *TurnManager) flushPending() {
	for _, move := range tm.pending {
		tm.emitMoveBlock(move)
	}
	tm.pending = nil
}

func (tm *TurnManager) advanceSlot() {
	tm.slot = (tm.slot + 1) % len(tm.cfg.Peers)
	tm.votes = make(map[string]struct{})
	tm.votedThisSlot = false
}

func (tm *TurnManager) isLeader() bool {
	return tm.cfg.Peers[tm.slot] == tm.cfg.NodeID
}

func (tm *TurnManager) broadcast(b *block.Block) {
	select {
	case tm.outBlock <- b:
	default:
	}
}

func (tm *TurnManager) emitEvent() {
	select {
	case tm.events <- Event{State: tm.state, LeaderID: tm.cfg.Peers[tm.slot], Slot: tm.slot}:
	default:
	}
}
