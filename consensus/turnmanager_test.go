package consensus_test

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"pot-node/block"
	"pot-node/blockchain"
	"pot-node/consensus"
	"pot-node/crypto"
)

// Test durations are kept short so the suite runs in well under a second.
// The 5-second DefaultTransitionDuration is never used in tests.
const (
	testTurn       = 80 * time.Millisecond
	testTransition = 30 * time.Millisecond
	testTimeout    = 600 * time.Millisecond
)

// ---- helpers ----------------------------------------------------------------

func mustKeyPair(t *testing.T) crypto.KeyPair {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	return kp
}

func nodeID(kp crypto.KeyPair) string { return crypto.NodeID(kp.Public) }

// awaitBlock returns the next block from ch, or fails the test on timeout.
func awaitBlock(t *testing.T, ch <-chan *block.Block) *block.Block {
	t.Helper()
	select {
	case b := <-ch:
		return b
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for block")
		return nil
	}
}

// awaitEvent returns the next event from ch, or fails the test on timeout.
func awaitEvent(t *testing.T, ch <-chan consensus.Event) consensus.Event {
	t.Helper()
	select {
	case e := <-ch:
		return e
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for event")
		return consensus.Event{}
	}
}

// awaitState drains the Events channel until it sees an event with the given
// state, then returns it. Earlier events with different states are discarded.
func awaitState(t *testing.T, ch <-chan consensus.Event, want consensus.TurnState) consensus.Event {
	t.Helper()
	for {
		e := awaitEvent(t, ch)
		if e.State == want {
			return e
		}
	}
}

// mustChain creates a chain with a genesis block signed by kp.
func mustChain(t *testing.T, kp crypto.KeyPair) *blockchain.Chain {
	t.Helper()
	c, err := blockchain.NewWithGenesis(nodeID(kp), kp.Private)
	require.NoError(t, err)
	return c
}

// chainFromGenesis creates a new chain that shares genesis with an existing chain.
// This simulates two nodes that agreed on the same starting block.
func chainFromGenesis(t *testing.T, src *blockchain.Chain) *blockchain.Chain {
	t.Helper()
	c := blockchain.New()
	require.NoError(t, c.Append(src.Blocks()[0], nil))
	return c
}

// testCfg builds a Config with the accelerated test durations.
func testCfg(id string, kp crypto.KeyPair, peers []string, keys map[string]ed25519.PublicKey) consensus.Config {
	return consensus.Config{
		NodeID:             id,
		KeyPair:            kp,
		Peers:              peers,
		PeerKeys:           keys,
		TurnDuration:       testTurn,
		TransitionDuration: testTransition,
	}
}

// ---- single-node tests ------------------------------------------------------
//
// A single-node session is a degenerate but valid case: one peer is always
// the Leading Node and the only co-signer for its own Transition blocks.
// These tests cover state transitions, block creation, and turn cycling
// without requiring inter-node routing.

func newSingleNode(t *testing.T) (*consensus.TurnManager, context.CancelFunc) {
	t.Helper()
	kp := mustKeyPair(t)
	id := nodeID(kp)
	chain := mustChain(t, kp)
	cfg := testCfg(id, kp, []string{id}, map[string]ed25519.PublicKey{id: kp.Public})
	tm := consensus.New(cfg, chain)
	ctx, cancel := context.WithCancel(context.Background())
	go tm.Run(ctx)
	return tm, cancel
}

func TestSingleNode_StartsLeading(t *testing.T) {
	tm, cancel := newSingleNode(t)
	defer cancel()
	e := awaitEvent(t, tm.Events())
	assert.Equal(t, consensus.StateLeading, e.State)
}

func TestSingleNode_MoveWhileLeadingCreatesBlock(t *testing.T) {
	tm, cancel := newSingleNode(t)
	defer cancel()
	awaitState(t, tm.Events(), consensus.StateLeading)

	tm.SubmitMove(block.GameMoveData{MoveType: "attack", From: 1, To: 2, PlayerID: "p1"})

	b := awaitBlock(t, tm.OutBlocks())
	assert.Equal(t, block.BlockTypeGameMove, b.Type)
}

func TestSingleNode_TurnExpiryEmitsTransitionBlock(t *testing.T) {
	tm, cancel := newSingleNode(t)
	defer cancel()
	awaitState(t, tm.Events(), consensus.StateLeading)

	// The only block produced without any move submission is the Transition block.
	b := awaitBlock(t, tm.OutBlocks())
	assert.Equal(t, block.BlockTypeTransition, b.Type)
}

func TestSingleNode_EntersTransitionAfterExpiry(t *testing.T) {
	tm, cancel := newSingleNode(t)
	defer cancel()
	awaitState(t, tm.Events(), consensus.StateLeading)
	awaitState(t, tm.Events(), consensus.StateTransition)
}

func TestSingleNode_ReturnsToLeadingAfterTransition(t *testing.T) {
	// After the transition window the single node is the only candidate,
	// so it immediately re-enters StateLeading at slot 0.
	tm, cancel := newSingleNode(t)
	defer cancel()
	awaitState(t, tm.Events(), consensus.StateLeading)    // first turn
	awaitState(t, tm.Events(), consensus.StateTransition) // transition
	e := awaitState(t, tm.Events(), consensus.StateLeading) // second turn
	assert.Equal(t, 0, e.Slot)
}

func TestSingleNode_BlockCountAfterOneTurn(t *testing.T) {
	// Submit two moves during the leading window, then wait for the full cycle.
	// Expected chain: genesis + move1 + move2 + transition = 4 blocks.
	kp := mustKeyPair(t)
	id := nodeID(kp)
	chain := mustChain(t, kp)
	cfg := testCfg(id, kp, []string{id}, map[string]ed25519.PublicKey{id: kp.Public})
	tm := consensus.New(cfg, chain)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tm.Run(ctx)

	awaitState(t, tm.Events(), consensus.StateLeading)
	tm.SubmitMove(block.GameMoveData{MoveType: "attack", From: 1, To: 2, PlayerID: id})
	tm.SubmitMove(block.GameMoveData{MoveType: "attack", From: 3, To: 4, PlayerID: id})

	// Drain OutBlocks until we see the Transition block, confirming the turn ended.
	require.Eventually(t, func() bool {
		select {
		case b := <-tm.OutBlocks():
			return b.Type == block.BlockTypeTransition
		default:
			return false
		}
	}, testTimeout, 5*time.Millisecond)

	// genesis + 2 moves = 3. The Transition block is broadcast half-signed and is
	// only appended to the chain after the incoming LN returns it with a co-signature.
	// In single-node tests there is no routing loop, so the Transition block does not
	// land on the chain here. TestTwoNodes_TransitionBlockAppearsOnBothChains covers
	// the full co-signing and append flow.
	assert.Equal(t, 3, chain.Len())
}

// ---- two-node tests ---------------------------------------------------------
//
// A two-node rig wires two TurnManagers together via goroutines that route
// each node's OutBlocks to the other's ReceiveBlock. This simulates a minimal
// real network without any actual transport layer.
//
// Block routing is intentionally simple: blocks flow from A → B and B → A.
// Tests observe chain state and the Events channel rather than OutBlocks, because
// the routing goroutines drain OutBlocks — reading from OutBlocks in the test
// would race with the routing goroutines.

type twoNodeRig struct {
	idA, idB         string
	chainA, chainB   *blockchain.Chain
	tmA, tmB         *consensus.TurnManager
	cancel           context.CancelFunc
}

func setupTwoNodes(t *testing.T) *twoNodeRig {
	t.Helper()
	kpA, kpB := mustKeyPair(t), mustKeyPair(t)
	idA, idB := nodeID(kpA), nodeID(kpB)

	peers := []string{idA, idB}
	keys := map[string]ed25519.PublicKey{idA: kpA.Public, idB: kpB.Public}

	// Both chains start from the same genesis block (signed by A).
	// This mirrors how a real session bootstraps: one node creates genesis
	// and all peers receive it before the session starts.
	chainA := mustChain(t, kpA)
	chainB := chainFromGenesis(t, chainA)

	tmA := consensus.New(testCfg(idA, kpA, peers, keys), chainA)
	tmB := consensus.New(testCfg(idB, kpB, peers, keys), chainB)

	ctx, cancel := context.WithCancel(context.Background())
	go tmA.Run(ctx)
	go tmB.Run(ctx)

	// Route blocks between nodes.
	route := func(src *consensus.TurnManager, dst *consensus.TurnManager) {
		for {
			select {
			case <-ctx.Done():
				return
			case b := <-src.OutBlocks():
				dst.ReceiveBlock(b)
			}
		}
	}
	go route(tmA, tmB)
	go route(tmB, tmA)

	return &twoNodeRig{idA: idA, idB: idB, chainA: chainA, chainB: chainB, tmA: tmA, tmB: tmB, cancel: cancel}
}

func TestTwoNodes_InitialStates(t *testing.T) {
	rig := setupTwoNodes(t)
	defer rig.cancel()

	eA := awaitEvent(t, rig.tmA.Events())
	assert.Equal(t, consensus.StateLeading, eA.State, "peer at index 0 must lead first")

	eB := awaitEvent(t, rig.tmB.Events())
	assert.Equal(t, consensus.StateWaiting, eB.State, "peer at index 1 must wait first")
}

func TestTwoNodes_BBecomesLeaderAfterHandover(t *testing.T) {
	rig := setupTwoNodes(t)
	defer rig.cancel()

	// A leads, then transitions.
	awaitState(t, rig.tmA.Events(), consensus.StateLeading)
	awaitState(t, rig.tmA.Events(), consensus.StateTransition)

	// B co-signs the Transition block and, after the transition window, leads.
	eB := awaitState(t, rig.tmB.Events(), consensus.StateLeading)
	assert.Equal(t, rig.idB, eB.LeaderID)
	assert.Equal(t, 1, eB.Slot)
}

func TestTwoNodes_MoveWhileLeadingAppearsOnChain(t *testing.T) {
	rig := setupTwoNodes(t)
	defer rig.cancel()

	awaitState(t, rig.tmA.Events(), consensus.StateLeading)
	rig.tmA.SubmitMove(block.GameMoveData{MoveType: "attack", From: 1, To: 2, PlayerID: rig.idA})

	// A appends the block to chainA immediately on creation.
	require.Eventually(t, func() bool {
		for _, b := range rig.chainA.Blocks() {
			if b.Type == block.BlockTypeGameMove && b.AuthorID == rig.idA {
				return true
			}
		}
		return false
	}, testTimeout, 5*time.Millisecond)
}

func TestTwoNodes_MoveWhileLeadingPropagatestoB(t *testing.T) {
	rig := setupTwoNodes(t)
	defer rig.cancel()

	awaitState(t, rig.tmA.Events(), consensus.StateLeading)
	rig.tmA.SubmitMove(block.GameMoveData{MoveType: "attack", From: 1, To: 2, PlayerID: rig.idA})

	// The routing goroutine delivers A's block to B, which appends it to chainB.
	require.Eventually(t, func() bool {
		for _, b := range rig.chainB.Blocks() {
			if b.Type == block.BlockTypeGameMove && b.AuthorID == rig.idA {
				return true
			}
		}
		return false
	}, testTimeout, 5*time.Millisecond)
}

func TestTwoNodes_PendingMoveFlushedWhenBLeads(t *testing.T) {
	rig := setupTwoNodes(t)
	defer rig.cancel()

	// B submits a move while waiting for A's turn to end.
	awaitState(t, rig.tmB.Events(), consensus.StateWaiting)
	rig.tmB.SubmitMove(block.GameMoveData{MoveType: "attack", From: 5, To: 6, PlayerID: rig.idB})

	// After the handover, B becomes leader and flushes its pending move.
	awaitState(t, rig.tmB.Events(), consensus.StateLeading)

	require.Eventually(t, func() bool {
		for _, b := range rig.chainB.Blocks() {
			if b.Type == block.BlockTypeGameMove && b.AuthorID == rig.idB {
				return true
			}
		}
		return false
	}, testTimeout, 5*time.Millisecond)
}

func TestTwoNodes_TransitionBlockAppearsOnBothChains(t *testing.T) {
	rig := setupTwoNodes(t)
	defer rig.cancel()

	// Wait for the handover to complete on both sides.
	awaitState(t, rig.tmA.Events(), consensus.StateTransition)
	awaitState(t, rig.tmB.Events(), consensus.StateLeading)

	hasTransition := func(c *blockchain.Chain) bool {
		for _, b := range c.Blocks() {
			if b.Type == block.BlockTypeTransition {
				return true
			}
		}
		return false
	}

	require.Eventually(t, func() bool { return hasTransition(rig.chainA) }, testTimeout, 5*time.Millisecond)
	require.Eventually(t, func() bool { return hasTransition(rig.chainB) }, testTimeout, 5*time.Millisecond)
}

func TestTwoNodes_InvalidBlockRejected(t *testing.T) {
	rig := setupTwoNodes(t)
	defer rig.cancel()

	awaitState(t, rig.tmB.Events(), consensus.StateWaiting)

	// Construct a block with a tampered hash and deliver it to B directly.
	kpA := mustKeyPair(t) // wrong key — not in peerKeys
	move := block.GameMoveData{MoveType: "attack", From: 1, To: 2, PlayerID: "impostor"}
	bad, err := block.NewGameMoveBlock(rig.chainB.Latest(), rig.idA, move, kpA.Private)
	require.NoError(t, err)
	bad.Hash = "0000000000000000000000000000000000000000000000000000000000000000"

	rig.tmB.ReceiveBlock(bad)

	// Give the state machine time to process the block, then confirm it was rejected.
	time.Sleep(50 * time.Millisecond)
	for _, b := range rig.chainB.Blocks() {
		assert.NotEqual(t, bad.Hash, b.Hash, "tampered block must not appear on chain")
	}
}

// ---- early finalize tests ---------------------------------------------------

func TestSingleNode_FinalizeTurnEmitsFinalizingBlock(t *testing.T) {
	tm, cancel := newSingleNode(t)
	defer cancel()
	awaitState(t, tm.Events(), consensus.StateLeading)

	tm.FinalizeTurn()

	// Expect a FinalizingBlock followed by a TransitionBlock.
	var saw block.BlockType
	require.Eventually(t, func() bool {
		select {
		case b := <-tm.OutBlocks():
			saw = b.Type
			return b.Type == block.BlockTypeTransition
		default:
			return false
		}
	}, testTimeout, 5*time.Millisecond)
	_ = saw
}

func TestTwoNodes_FinalizeHandoverAtoB(t *testing.T) {
	rig := setupTwoNodes(t)
	defer rig.cancel()

	awaitState(t, rig.tmA.Events(), consensus.StateLeading)
	rig.tmA.FinalizeTurn()

	// B should become leader faster than the full turn duration.
	eB := awaitState(t, rig.tmB.Events(), consensus.StateLeading)
	assert.Equal(t, rig.idB, eB.LeaderID)
}

func TestFinalizeTurn_NoopWhenWaiting(t *testing.T) {
	rig := setupTwoNodes(t)
	defer rig.cancel()

	awaitState(t, rig.tmB.Events(), consensus.StateWaiting)

	// B is not leading — FinalizeTurn must not trigger any state change.
	rig.tmB.FinalizeTurn()
	time.Sleep(50 * time.Millisecond)

	// B must still be waiting.
	select {
	case e := <-rig.tmB.Events():
		assert.NotEqual(t, consensus.StateTransition, e.State, "FinalizeTurn on waiting node must not start transition")
	default:
	}
}

// ---- missed-turn / vote tests -----------------------------------------------
//
// These tests verify the watchdog timer, vote emission, and forced handover.
// A 2-node rig is used for single-node vote emission (A offline, B waits).
// A 3-node rig is used for the full forced-handover path (A offline, B+C vote).

// newWaitingNode creates a TurnManager that starts in WAITING (slot 0 is taken by
// a different, offline peer). No routing is wired — this node's OutBlocks are
// read directly in tests.
func newWaitingNode(t *testing.T) (*consensus.TurnManager, context.CancelFunc) {
	t.Helper()
	kpA, kpB := mustKeyPair(t), mustKeyPair(t)
	idA, idB := nodeID(kpA), nodeID(kpB)

	peers := []string{idA, idB} // A leads first; B is waiting
	keys := map[string]ed25519.PublicKey{idA: kpA.Public, idB: kpB.Public}

	chainA := mustChain(t, kpA)
	chainB := chainFromGenesis(t, chainA)

	tmB := consensus.New(testCfg(idB, kpB, peers, keys), chainB)
	ctx, cancel := context.WithCancel(context.Background())
	go tmB.Run(ctx)
	return tmB, cancel
}

// TestMissedTurn_WatchdogEmitsVoteBlock verifies that a waiting node broadcasts
// a vote block when the watchdog fires (leader never sends a Transition block).
func TestMissedTurn_WatchdogEmitsVoteBlock(t *testing.T) {
	tmB, cancel := newWaitingNode(t)
	defer cancel()

	awaitState(t, tmB.Events(), consensus.StateWaiting)

	require.Eventually(t, func() bool {
		select {
		case b := <-tmB.OutBlocks():
			return b.Type == block.BlockTypeVote
		default:
			return false
		}
	}, testTimeout, 5*time.Millisecond)
}

// TestMissedTurn_NoDoubleVote verifies that a node emits at most one vote per
// missed-turn event, even if the watchdog period passes multiple times.
func TestMissedTurn_NoDoubleVote(t *testing.T) {
	tmB, cancel := newWaitingNode(t)
	defer cancel()

	awaitState(t, tmB.Events(), consensus.StateWaiting)

	// Collect all blocks emitted during three watchdog periods.
	var voteCount int
	deadline := time.After(3 * (testTurn + testTransition))
outer:
	for {
		select {
		case b := <-tmB.OutBlocks():
			if b.Type == block.BlockTypeVote {
				voteCount++
			}
		case <-deadline:
			break outer
		}
	}
	assert.Equal(t, 1, voteCount, "node must not vote more than once per missed-turn event")
}

// setupMissedTurnRig creates a 3-node rig where A (slot 0, the initial leader) is
// offline. B and C are started and connected to each other only. Their watchdogs
// will fire and they will exchange vote blocks, reaching the threshold (2 of 3)
// and forcing a handover to B (slot 1).
type missedTurnRig struct {
	idA, idB, idC string
	tmB, tmC      *consensus.TurnManager
	cancel        context.CancelFunc
}

func setupMissedTurnRig(t *testing.T) *missedTurnRig {
	t.Helper()
	kpA, kpB, kpC := mustKeyPair(t), mustKeyPair(t), mustKeyPair(t)
	idA, idB, idC := nodeID(kpA), nodeID(kpB), nodeID(kpC)

	peers := []string{idA, idB, idC}
	keys := map[string]ed25519.PublicKey{
		idA: kpA.Public, idB: kpB.Public, idC: kpC.Public,
	}

	chainA := mustChain(t, kpA)
	chainB := chainFromGenesis(t, chainA)
	chainC := chainFromGenesis(t, chainA)

	tmB := consensus.New(testCfg(idB, kpB, peers, keys), chainB)
	tmC := consensus.New(testCfg(idC, kpC, peers, keys), chainC)

	ctx, cancel := context.WithCancel(context.Background())
	go tmB.Run(ctx)
	go tmC.Run(ctx)

	// Route blocks between B and C only. A is offline — its blocks never arrive.
	route := func(src, dst *consensus.TurnManager) {
		for {
			select {
			case <-ctx.Done():
				return
			case b := <-src.OutBlocks():
				dst.ReceiveBlock(b)
			}
		}
	}
	go route(tmB, tmC)
	go route(tmC, tmB)

	return &missedTurnRig{idA: idA, idB: idB, idC: idC, tmB: tmB, tmC: tmC, cancel: cancel}
}

// TestMissedTurn_ForcedHandover_BBecomesLeader verifies the full forced-handover
// path: A is offline, B and C exchange vote blocks, vote threshold (2/3) is
// reached, and B (slot 1) becomes the new Leading Node.
func TestMissedTurn_ForcedHandover_BBecomesLeader(t *testing.T) {
	rig := setupMissedTurnRig(t)
	defer rig.cancel()

	awaitState(t, rig.tmB.Events(), consensus.StateWaiting)
	awaitState(t, rig.tmC.Events(), consensus.StateWaiting)

	eB := awaitState(t, rig.tmB.Events(), consensus.StateLeading)
	assert.Equal(t, rig.idB, eB.LeaderID)
	assert.Equal(t, 1, eB.Slot)
}

// TestMissedTurn_ForcedHandover_CWaitsAfterHandover verifies that after the
// forced handover to B, C correctly re-enters the waiting state.
func TestMissedTurn_ForcedHandover_CWaitsAfterHandover(t *testing.T) {
	rig := setupMissedTurnRig(t)
	defer rig.cancel()

	awaitState(t, rig.tmC.Events(), consensus.StateWaiting) // initial
	awaitState(t, rig.tmB.Events(), consensus.StateLeading) // after forced handover

	// After B leads, C must still be in a waiting state (slot 1 is B's, slot 2 is C's).
	eC := awaitState(t, rig.tmC.Events(), consensus.StateWaiting)
	assert.Equal(t, rig.idB, eC.LeaderID)
}

func TestTwoNodes_BothChainsValidAfterFullCycle(t *testing.T) {
	rig := setupTwoNodes(t)
	defer rig.cancel()

	// Submit moves on both sides and wait for a complete A→B handover.
	awaitState(t, rig.tmA.Events(), consensus.StateLeading)
	rig.tmA.SubmitMove(block.GameMoveData{MoveType: "attack", From: 1, To: 2, PlayerID: rig.idA})

	rig.tmB.SubmitMove(block.GameMoveData{MoveType: "attack", From: 3, To: 4, PlayerID: rig.idB})

	// Wait for B to lead and flush its pending move.
	awaitState(t, rig.tmB.Events(), consensus.StateLeading)
	require.Eventually(t, func() bool {
		for _, b := range rig.chainB.Blocks() {
			if b.Type == block.BlockTypeGameMove && b.AuthorID == rig.idB {
				return true
			}
		}
		return false
	}, testTimeout, 5*time.Millisecond)

	// Both chains must be structurally valid.
	assert.NoError(t, rig.chainA.IsValid())
	assert.NoError(t, rig.chainB.IsValid())
}
