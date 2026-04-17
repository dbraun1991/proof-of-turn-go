package api_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"pot-node/api"
	"pot-node/block"
	"pot-node/consensus"
	"pot-node/crypto"
)

// ---- stubs ------------------------------------------------------------------

type stubChain struct {
	blocks []*block.Block
}

func (c *stubChain) Blocks() []*block.Block { return c.blocks }

func mustGenesisChain(t *testing.T) *stubChain {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	id := crypto.NodeID(kp.Public)
	b, err := block.NewGenesisBlock(id, kp.Private)
	require.NoError(t, err)
	return &stubChain{blocks: []*block.Block{b}}
}

type stubMover struct {
	moves  []block.GameMoveData
	events chan consensus.Event
}

func newStubMover() *stubMover {
	return &stubMover{events: make(chan consensus.Event, 16)}
}

func (s *stubMover) SubmitMove(m block.GameMoveData) { s.moves = append(s.moves, m) }
func (s *stubMover) FinalizeTurn()                   {}
func (s *stubMover) Events() <-chan consensus.Event  { return s.events }

// ---- POST /move -------------------------------------------------------------

func TestHandleMove_Success(t *testing.T) {
	stub := newStubMover()
	srv := api.New(stub, "test-node", &stubChain{})

	// playerId is intentionally absent — the server stamps its own nodeID.
	body := `{"moveType":"attack","from":3,"to":7}`
	req := httptest.NewRequest(http.MethodPost, "/move", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	require.Len(t, stub.moves, 1)
	assert.Equal(t, "attack", stub.moves[0].MoveType)
	assert.Equal(t, 3, stub.moves[0].From)
	assert.Equal(t, 7, stub.moves[0].To)
	assert.Equal(t, "test-node", stub.moves[0].PlayerID, "server must stamp its own nodeID as PlayerID")
}

func TestHandleMove_BadJSON(t *testing.T) {
	srv := api.New(newStubMover(), "test-node", &stubChain{})

	req := httptest.NewRequest(http.MethodPost, "/move", strings.NewReader("not json"))
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleMove_EmptyBody(t *testing.T) {
	srv := api.New(newStubMover(), "test-node", &stubChain{})

	req := httptest.NewRequest(http.MethodPost, "/move", bytes.NewReader(nil))
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ---- CORS -------------------------------------------------------------------

func TestCORS_HeadersPresentOnResponse(t *testing.T) {
	srv := api.New(newStubMover(), "test-node", &stubChain{})

	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Contains(t, w.Header().Get("Access-Control-Allow-Methods"), "POST")
	assert.Contains(t, w.Header().Get("Access-Control-Allow-Methods"), "GET")
}

func TestCORS_PreflightReturns204(t *testing.T) {
	srv := api.New(newStubMover(), "test-node", &stubChain{})

	req := httptest.NewRequest(http.MethodOptions, "/move", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "POST")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
}

// ---- POST /finalize ---------------------------------------------------------

func TestHandleFinalize_Returns204(t *testing.T) {
	srv := api.New(newStubMover(), "test-node", &stubChain{})

	req := httptest.NewRequest(http.MethodPost, "/finalize", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
}

// ---- GET /status ------------------------------------------------------------

func TestHandleStatus_ZeroState(t *testing.T) {
	// No events fired yet — server returns the zero-value state.
	srv := api.New(newStubMover(), "test-node", &stubChain{})

	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "waiting", resp["state"])
	assert.Equal(t, "test-node", resp["nodeId"], "status must expose the node's player identity")
}

func TestHandleStatus_AfterEvent(t *testing.T) {
	stub := newStubMover()
	srv := api.New(stub, "test-node", &stubChain{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Run(ctx)

	stub.events <- consensus.Event{State: consensus.StateLeading, Slot: 1, LeaderID: "aabbccdd1234"}

	require.Eventually(t, func() bool {
		req := httptest.NewRequest(http.MethodGet, "/status", nil)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		var resp map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			return false
		}
		return resp["state"] == "leading"
	}, time.Second, 5*time.Millisecond)
}

// ---- GET /chain -------------------------------------------------------------

func TestHandleChain_EmptyChain(t *testing.T) {
	srv := api.New(newStubMover(), "test-node", &stubChain{})

	req := httptest.NewRequest(http.MethodGet, "/chain", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var blocks []any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &blocks))
	assert.Empty(t, blocks)
}

func TestHandleChain_ReturnsBlocks(t *testing.T) {
	chain := mustGenesisChain(t)
	srv := api.New(newStubMover(), "test-node", chain)

	req := httptest.NewRequest(http.MethodGet, "/chain", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var blocks []map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &blocks))
	require.Len(t, blocks, 1)
	assert.Equal(t, "genesis", blocks[0]["type"])
	assert.Equal(t, float64(0), blocks[0]["index"])
}

// ---- GET /events (SSE) ------------------------------------------------------

// TestHandleEvents_InitialStateOnConnect verifies that the current state is
// pushed immediately when a client connects, without waiting for a transition.
func TestHandleEvents_InitialStateOnConnect(t *testing.T) {
	stub := newStubMover()
	srv := api.New(stub, "test-node", &stubChain{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Run(ctx)

	// Deliver one event so last state is known.
	stub.events <- consensus.Event{State: consensus.StateWaiting, Slot: 0, LeaderID: "peer0"}
	time.Sleep(20 * time.Millisecond) // let Run consume it

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/events")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))

	line := readSSEDataLine(t, resp)
	assert.Contains(t, line, `"state":"waiting"`)
	assert.Contains(t, line, `"leaderId":"peer0"`)
}

// TestHandleEvents_StreamsTransition verifies that a new consensus event
// arrives over the SSE stream after the initial snapshot.
func TestHandleEvents_StreamsTransition(t *testing.T) {
	stub := newStubMover()
	srv := api.New(stub, "test-node", &stubChain{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Run(ctx)

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/events")
	require.NoError(t, err)
	defer resp.Body.Close()

	// Consume the initial snapshot.
	readSSEDataLine(t, resp)

	// Trigger a state change.
	stub.events <- consensus.Event{State: consensus.StateLeading, Slot: 0, LeaderID: "leader1"}

	line := readSSEDataLine(t, resp)
	assert.Contains(t, line, `"state":"leading"`)
	assert.Contains(t, line, `"leaderId":"leader1"`)
}

// readSSEDataLine reads lines from an SSE response body until it finds one
// starting with "data: ", then returns the full line. Fails the test if
// no such line arrives within one second.
func readSSEDataLine(t *testing.T, resp *http.Response) string {
	t.Helper()
	lines := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "data: ") {
				lines <- line
				return
			}
		}
	}()
	select {
	case line := <-lines:
		return line
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for SSE data line")
		return ""
	}
}
