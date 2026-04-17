// Package api exposes the consensus layer over HTTP.
//
// Routes:
//
//	POST /move      — submit a game move (queued if this node is not currently leading)
//	POST /finalize  — end the current turn early; no-op if not leading
//	GET  /events    — SSE stream of consensus state changes
//	GET  /status    — current state snapshot including this node's player identity
//	GET  /chain     — full block chain as a JSON array (for state replay and sync)
//
// # Player identity
//
// Each node's player ID is its consensus NodeID (SHA-256 of its Ed25519 public
// key). POST /move does not accept a playerId from the client — the server
// stamps its own NodeID onto every move so a client can only ever act as the
// node they are connected to.
//
// GET /status returns a "nodeId" field so the frontend knows which player it
// controls without any extra round-trip.
//
// # CORS
//
// All responses include Access-Control-Allow-Origin: * so any browser origin
// can reach the node during development. Preflight OPTIONS requests are handled
// automatically. Restrict the allowed origin once authentication is in place.
//
// TODO(auth): There is currently no authentication between the game frontend
// and this HTTP API. Any client that can reach the endpoint can submit moves
// on behalf of this node's player. A production deployment should add a
// shared secret, bearer token, or mutual TLS before exposing the API beyond
// localhost.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"

	"pot-node/block"
	"pot-node/consensus"
)

// Mover is the minimal interface the Server needs from the consensus layer.
// *consensus.TurnManager satisfies this interface.
type Mover interface {
	SubmitMove(block.GameMoveData)
	FinalizeTurn()
	Events() <-chan consensus.Event
}

// ChainReader is the minimal interface the Server needs to serve the chain.
// *blockchain.Chain satisfies this interface.
type ChainReader interface {
	Blocks() []*block.Block
}

// Server exposes consensus state over HTTP.
type Server struct {
	tm     Mover
	nodeID string     // this node's player identity, stamped onto every move
	chain  ChainReader

	mu     sync.RWMutex
	last   consensus.Event
	subs   map[int]chan consensus.Event
	nextID int
}

// New creates a Server backed by tm. nodeID is the consensus NodeID of this
// node — it is stamped onto every submitted move as the player identity.
// chain is used to serve GET /chain for frontends and rejoining peers.
func New(tm Mover, nodeID string, chain ChainReader) *Server {
	return &Server{
		tm:     tm,
		nodeID: nodeID,
		chain:  chain,
		subs:   make(map[int]chan consensus.Event),
	}
}

// Handler returns the HTTP mux wrapped in CORS middleware.
// All responses carry Access-Control-Allow-Origin: * so any browser origin
// can reach the node. Restrict the origin once authentication is in place
// (see the TODO(auth) in the package doc).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /move", s.handleMove)
	mux.HandleFunc("POST /finalize", s.handleFinalize)
	mux.HandleFunc("GET /events", s.handleEvents)
	mux.HandleFunc("GET /status", s.handleStatus)
	mux.HandleFunc("GET /chain", s.handleChain)
	return withCORS(mux)
}

// withCORS wraps h with permissive CORS headers and handles OPTIONS preflight
// requests so browsers can call the API from any origin.
func withCORS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// Run fans events from the Mover to all SSE subscribers and logs each state
// transition. It is the sole consumer of tm.Events() — replaces the separate
// logEvents goroutine in main. Blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-s.tm.Events():
			log.Printf("state=%-10s  slot=%d  leader=%.12s", e.State, e.Slot, e.LeaderID)
			s.mu.Lock()
			s.last = e
			for _, ch := range s.subs {
				select {
				case ch <- e:
				default:
				}
			}
			s.mu.Unlock()
		}
	}
}

// unsubscribe removes a subscriber by ID.
func (s *Server) unsubscribe(id int) {
	s.mu.Lock()
	delete(s.subs, id)
	s.mu.Unlock()
}

// moveRequest is the JSON body for POST /move.
// PlayerID is not accepted from the client — the server stamps its own NodeID.
type moveRequest struct {
	MoveType string `json:"moveType"`
	From     int    `json:"from"`
	To       int    `json:"to"`
}

func (s *Server) handleMove(w http.ResponseWriter, r *http.Request) {
	var req moveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	s.tm.SubmitMove(block.GameMoveData{
		MoveType: req.MoveType,
		From:     req.From,
		To:       req.To,
		PlayerID: s.nodeID, // identity is the node's own consensus ID, not client-supplied
	})
	w.WriteHeader(http.StatusNoContent)
}

// statusResponse is the JSON body for GET /status and each SSE data line.
type statusResponse struct {
	State    string `json:"state"`
	Slot     int    `json:"slot"`
	LeaderID string `json:"leaderId"`
	NodeID   string `json:"nodeId,omitempty"` // only set on GET /status, not on SSE events
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	last := s.last
	s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(statusResponse{ //nolint:errcheck
		State:    last.State.String(),
		Slot:     last.Slot,
		LeaderID: last.LeaderID,
		NodeID:   s.nodeID,
	})
}

// handleEvents streams consensus events as SSE.
// The current state is pushed immediately on connect; subsequent events arrive
// as state transitions occur.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// Atomically capture the current state snapshot and register for future events
	// so no transition can be missed between the two operations.
	s.mu.Lock()
	last := s.last
	id := s.nextID
	s.nextID++
	ch := make(chan consensus.Event, 8)
	s.subs[id] = ch
	s.mu.Unlock()
	defer s.unsubscribe(id)

	writeSSEEvent(w, last)
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case e := <-ch:
			writeSSEEvent(w, e)
			flusher.Flush()
		}
	}
}

// handleFinalize signals the Leading Node to end its turn early.
// A no-op if this node is not currently leading — safe to call unconditionally.
func (s *Server) handleFinalize(w http.ResponseWriter, r *http.Request) {
	s.tm.FinalizeTurn()
	w.WriteHeader(http.StatusNoContent)
}

// handleChain returns the full block chain as a JSON array.
// Frontends use this to replay game state on load; rejoining nodes use it to
// catch up before starting consensus.
func (s *Server) handleChain(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.chain.Blocks()) //nolint:errcheck
}

func writeSSEEvent(w http.ResponseWriter, e consensus.Event) {
	data, _ := json.Marshal(statusResponse{
		State:    e.State.String(),
		Slot:     e.Slot,
		LeaderID: e.LeaderID,
	})
	fmt.Fprintf(w, "data: %s\n\n", data) //nolint:errcheck
}
