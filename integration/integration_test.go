//go:build integration

// Package integration contains end-to-end tests that run real pot-node
// binaries inside Docker containers connected over an isolated network.
//
// These tests require Docker and are excluded from the default test suite.
// Run them explicitly:
//
//	go test -tags integration -v -timeout 10m ./integration/...
//
// The Docker image is built from ../Dockerfile on first run and cached for
// subsequent runs via KeepImage — expect ~60s on first run, ~5s after that.
package integration_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcnetwork "github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
)

// testTurn and testTransition are shorter than the production constants so the
// full A→B handover completes in a few seconds inside containers.
// See consensus.DefaultTurnDuration for the production values.
const (
	testTurn       = "2s"
	testTransition = "500ms"
	testTimeout    = 45 * time.Second

	// buildTimeout covers Docker image build time on the first run.
	// Subsequent runs use the cached image and need only a few seconds.
	buildTimeout = 5 * time.Minute
)

// potNodeImage builds the pot-node binary from the project Dockerfile.
// KeepImage caches the result across runs in the same Docker daemon session
// so the Go compile step only happens once.
var potNodeImage = testcontainers.FromDockerfile{
	Context:    "..",
	Dockerfile: "Dockerfile",
	KeepImage:  true,
}

// ---- log collection ---------------------------------------------------------

// logCollector implements testcontainers.LogConsumer and accumulates all log
// lines emitted by a container. Thread-safe.
type logCollector struct {
	mu    sync.RWMutex
	lines []string
}

func (c *logCollector) Accept(l testcontainers.Log) {
	c.mu.Lock()
	c.lines = append(c.lines, string(l.Content))
	c.mu.Unlock()
}

// Eventually asserts that a log line containing substr appears within
// testTimeout, polling every 200 ms.
func (c *logCollector) Eventually(t *testing.T, substr string) {
	t.Helper()
	require.Eventually(t, func() bool {
		c.mu.RLock()
		defer c.mu.RUnlock()
		for _, line := range c.lines {
			if strings.Contains(line, substr) {
				return true
			}
		}
		return false
	}, testTimeout, 200*time.Millisecond, "log line %q never appeared", substr)
}

// ---- helpers ----------------------------------------------------------------

// newNetwork creates an isolated Docker bridge network that is removed when t
// ends. Returns the network name.
func newNetwork(t *testing.T) string {
	t.Helper()
	net, err := tcnetwork.New(context.Background())
	require.NoError(t, err, "create Docker network")
	t.Cleanup(func() { net.Remove(context.Background()) }) //nolint:errcheck
	return net.Name
}

// startNode builds (or reuses the cached) pot-node image, starts a container
// attached to netName with the given alias, and waits until waitForLog appears
// in stdout. The container is automatically terminated when t ends.
//
// logs, if non-nil, receives all stdout/stderr lines via the LogConsumer API.
func startNode(t *testing.T, netName, alias, waitForLog string, cmd []string, logs *logCollector) testcontainers.Container {
	t.Helper()

	req := testcontainers.ContainerRequest{
		FromDockerfile: potNodeImage,
		Cmd:            cmd,
		Networks:       []string{netName},
		NetworkAliases: map[string][]string{netName: {alias}},
		// WithStartupTimeout covers the Docker image build on first run.
		WaitingFor: wait.ForLog(waitForLog).WithStartupTimeout(buildTimeout),
	}
	if logs != nil {
		req.LogConsumerCfg = &testcontainers.LogConsumerConfig{
			Consumers: []testcontainers.LogConsumer{logs},
		}
	}

	c, err := testcontainers.GenericContainer(context.Background(), testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err, "start container %q", alias)
	t.Cleanup(func() { c.Terminate(context.Background()) }) //nolint:errcheck
	return c
}

// ---- tests ------------------------------------------------------------------

// TestSingleNode_Leads verifies that a solo node (--expect 0) immediately
// creates a session with itself and enters the leading state.
func TestSingleNode_Leads(t *testing.T) {
	netName := newNetwork(t)
	logs := &logCollector{}

	startNode(t, netName, "solo", "session ready", []string{
		"--keyfile", "/tmp/node.key",
		"--listen", ":7000",
		"--expect", "0",
		"--turn-duration", testTurn,
		"--transition-duration", testTransition,
	}, logs)

	logs.Eventually(t, "state=leading")
}

// TestTwoNodes_Bootstrap verifies that both nodes complete the handshake and
// log "session ready" — confirming they share the same genesis block.
func TestTwoNodes_Bootstrap(t *testing.T) {
	netName := newNetwork(t)
	hostLogs := &logCollector{}
	joinerLogs := &logCollector{}

	startNode(t, netName, "host", "hosting session on", []string{
		"--keyfile", "/tmp/node.key",
		"--listen", ":7000",
		"--expect", "1",
		"--turn-duration", testTurn,
		"--transition-duration", testTransition,
	}, hostLogs)

	startNode(t, netName, "joiner", "session ready", []string{
		"--keyfile", "/tmp/node.key",
		"--listen", ":7001",
		"--join", "host:7000",
		"--turn-duration", testTurn,
		"--transition-duration", testTransition,
	}, joinerLogs)

	hostLogs.Eventually(t, "session ready")
	joinerLogs.Eventually(t, "session ready")
}

// TestThreeNodes_FullHandover verifies that three nodes form a full mesh and
// complete two consecutive handovers: A leads turn 0, B leads turn 1, C leads
// turn 2. This exercises the peer-to-peer dialing that supplements the
// host↔joiner bootstrap connections.
//
// Node start order matters: A must be up first (--expect 2). B and C start
// with wait.ForLog("node id:") so startNode returns immediately — before the
// host has sent SessionInfo — allowing both to connect to the host in parallel.
// The actual bootstrap completion is confirmed via logs.Eventually.
func TestThreeNodes_FullHandover(t *testing.T) {
	netName := newNetwork(t)
	aLogs := &logCollector{}
	bLogs := &logCollector{}
	cLogs := &logCollector{}

	// A starts first and waits for two peers.
	startNode(t, netName, "nodeA", "hosting session on", []string{
		"--keyfile", "/tmp/node.key",
		"--listen", ":7000",
		"--advertise-addr", "nodeA:7000",
		"--expect", "2",
		"--turn-duration", testTurn,
		"--transition-duration", testTransition,
	}, aLogs)

	// B and C are started with a minimal WaitingFor ("node id:") so startNode
	// returns as soon as the container is alive — without blocking until
	// SessionInfo arrives (which requires both B and C to be connected first).
	startNode(t, netName, "nodeB", "node id:", []string{
		"--keyfile", "/tmp/node.key",
		"--listen", ":7001",
		"--advertise-addr", "nodeB:7001",
		"--join", "nodeA:7000",
		"--turn-duration", testTurn,
		"--transition-duration", testTransition,
	}, bLogs)

	startNode(t, netName, "nodeC", "node id:", []string{
		"--keyfile", "/tmp/node.key",
		"--listen", ":7002",
		"--advertise-addr", "nodeC:7002",
		"--join", "nodeA:7000",
		"--turn-duration", testTurn,
		"--transition-duration", testTransition,
	}, cLogs)

	// All three must complete bootstrap before assertions begin.
	aLogs.Eventually(t, "session ready")
	bLogs.Eventually(t, "session ready")
	cLogs.Eventually(t, "session ready")

	// Turn 0: A leads.
	aLogs.Eventually(t, "state=leading")

	// Turn 1: B leads after A→B handover. Requires the Transition block to
	// reach B, which depends on the full mesh (C→B and A→B connections).
	bLogs.Eventually(t, "state=leading")

	// Turn 2: C leads after B→C handover.
	cLogs.Eventually(t, "state=leading")
}

// TestTwoNodes_HandoverAtoB verifies the full A→B turn handover:
//   - Node A (host) leads turn 0; node B (joiner) waits.
//   - After A's turn expires, A enters the transition window.
//   - B co-signs the Transition block and becomes the Leading Node for turn 1.
func TestTwoNodes_HandoverAtoB(t *testing.T) {
	netName := newNetwork(t)
	hostLogs := &logCollector{}
	joinerLogs := &logCollector{}

	startNode(t, netName, "host", "hosting session on", []string{
		"--keyfile", "/tmp/node.key",
		"--listen", ":7000",
		"--expect", "1",
		"--turn-duration", testTurn,
		"--transition-duration", testTransition,
	}, hostLogs)

	startNode(t, netName, "joiner", "session ready", []string{
		"--keyfile", "/tmp/node.key",
		"--listen", ":7001",
		"--join", "host:7000",
		"--turn-duration", testTurn,
		"--transition-duration", testTransition,
	}, joinerLogs)

	// Turn 0: A leads, B waits.
	hostLogs.Eventually(t, "state=leading")
	joinerLogs.Eventually(t, "state=waiting")

	// Handover: A's timer fires, it emits a half-signed Transition block.
	hostLogs.Eventually(t, "state=transition")

	// Turn 1: B co-signs the Transition block and takes the leading slot.
	joinerLogs.Eventually(t, "state=leading")
}
