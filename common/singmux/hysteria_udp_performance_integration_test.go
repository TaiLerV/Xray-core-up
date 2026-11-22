//go:build integration && stress && performance

package singmux_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	// hysteriaUDPPerformanceRevision is the server before IPv6 UDP addresses
	// were parsed from the message bytes: the Hysteria 2.14.0 quic-go bump
	// alone.
	hysteriaUDPPerformanceRevision = "7795bd6c1a1679f8d8b88363856753282786b62a"
	hysteriaUDPPerformanceLabel    = "hysteria-udp-baseline"

	// hysteriaUDPLoadPackets is the packets of one sample;
	// XRAY_HYSTERIA_UDP_PACKETS overrides it.
	hysteriaUDPLoadPackets = 200000
	hysteriaUDPLoadPayload = 64
	// hysteriaUDPLoadWindow bounds the datagrams in flight, so the load is a
	// closed loop that measures throughput instead of queue drops.
	hysteriaUDPLoadWindow = 32
	// hysteriaUDPLoadDeadline bounds one sample: at about 80,000 packets per
	// second the default sample takes under three seconds.
	hysteriaUDPLoadDeadline = 2 * time.Minute
)

// TestHysteriaUDPPerformanceAgainstBaseline sends small UDP packets through an
// Xray Hysteria client to a baseline and a candidate Xray Hysteria server, in
// alternating rounds, and compares delivered packets per second and server CPU
// time per packet. Set XRAY_HYSTERIA_UDP_BASELINE to compare another revision.
func TestHysteriaUDPPerformanceAgainstBaseline(t *testing.T) {
	if testing.Short() {
		t.Skip("Hysteria UDP performance comparison")
	}
	workDir := t.TempDir()
	xrayRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	// Both servers carry the release tags whatever GOFLAGS says: the tags
	// given to go test do not reach the go build commands the test runs.
	releaseBuild := []string{"-trimpath", "-buildvcs=false", "-tags", "http2legacy"}
	candidateBinary := buildE2EBinary(t, "XRAY_E2E_BIN", filepath.Join(workDir, "xray-candidate"), xrayRoot, "./main", releaseBuild...)
	revision := hysteriaUDPPerformanceRevision
	if override := os.Getenv("XRAY_HYSTERIA_UDP_BASELINE"); override != "" {
		revision = override
	}
	baselineBinary := buildXrayRevision(t, workDir, hysteriaUDPPerformanceLabel, revision, "-tags", "http2legacy")
	binaries := e2eBinaries{xray: candidateBinary}
	certificate, privateKey := generateCertificate(t, workDir)
	tcpEcho := startTCPEcho(t).(*net.TCPAddr)
	ipv4Echo := startUDPEcho(t).(*net.UDPAddr)
	ipv6Echoes := startUDPEchoIPv6(t, 16)

	packets := hysteriaUDPLoadPackets
	if override := os.Getenv("XRAY_HYSTERIA_UDP_PACKETS"); override != "" {
		if packets, err = strconv.Atoi(override); err != nil || packets <= 0 {
			t.Fatalf("XRAY_HYSTERIA_UDP_PACKETS=%q is not a positive packet count", override)
		}
	}

	baseline := startHysteriaPerformanceTopology(t, workDir, binaries, baselineBinary, certificate, privateKey, tcpEcho, "baseline")
	candidate := startHysteriaPerformanceTopology(t, workDir, binaries, candidateBinary, certificate, privateKey, tcpEcho, "candidate")

	// The builds above leave the host busy for a while; a full-size load on
	// both paths settles it before any mode is measured.
	runHysteriaUDPLoad(t, baseline, []*net.UDPAddr{ipv4Echo}, packets)
	runHysteriaUDPLoad(t, candidate, []*net.UDPAddr{ipv4Echo}, packets)

	modes := []struct {
		name    string
		targets []*net.UDPAddr
	}{
		{name: "ipv4", targets: []*net.UDPAddr{ipv4Echo}},
		{name: "ipv6-one", targets: ipv6Echoes[:1]},
		{name: "ipv6-four", targets: ipv6Echoes[:4]},
		{name: "ipv6-sixteen", targets: ipv6Echoes},
	}
	for _, mode := range modes {
		t.Run(mode.name, func(t *testing.T) {
			// Warm both paths up outside the timed rounds.
			warmup := max(packets/4, 1)
			runHysteriaUDPLoad(t, baseline, mode.targets, warmup)
			runHysteriaUDPLoad(t, candidate, mode.targets, warmup)

			var baselineSamples, candidateSamples []hysteriaUDPLoadResult
			for round := range performanceRounds {
				measureBaseline := func() {
					baselineSamples = append(baselineSamples, runHysteriaUDPLoad(t, baseline, mode.targets, packets))
				}
				measureCandidate := func() {
					candidateSamples = append(candidateSamples, runHysteriaUDPLoad(t, candidate, mode.targets, packets))
				}
				if round%2 == 0 {
					measureBaseline()
					measureCandidate()
				} else {
					measureCandidate()
					measureBaseline()
				}
			}
			reportHysteriaUDPLoad(t, mode.name, baselineSamples, candidateSamples)
		})
	}
}

type hysteriaUDPLoadResult struct {
	sent, received int
	elapsed        time.Duration
	serverCPU      time.Duration
}

func (r hysteriaUDPLoadResult) packetsPerSecond() float64 {
	return float64(r.received) / r.elapsed.Seconds()
}

func (r hysteriaUDPLoadResult) serverCPUPerPacket() (float64, error) {
	if r.serverCPU <= 0 || r.received <= 0 {
		return 0, fmt.Errorf("invalid CPU sample: %v for %d received packets", r.serverCPU, r.received)
	}
	return float64(r.serverCPU.Nanoseconds()) / float64(r.received), nil
}

func startHysteriaPerformanceTopology(t *testing.T, workDir string, binaries e2eBinaries, serverBinary, certificate, privateKey string, tcpEcho *net.TCPAddr, name string) *stressTopology {
	t.Helper()
	serverPort := freeUDPPort(t)
	socksPort := freeTCPPort(t)
	scenarioDir := filepath.Join(workDir, "hysteria-udp-performance-"+name)
	if err := os.MkdirAll(scenarioDir, 0o700); err != nil {
		t.Fatal(err)
	}
	certificate = copyScenarioFile(t, certificate, filepath.Join(scenarioDir, "server.crt"))
	privateKey = copyScenarioFile(t, privateKey, filepath.Join(scenarioDir, "server.key"))
	quiet := func(config []byte) []byte {
		return bytes.ReplaceAll(config, []byte(`"loglevel": "warning"`), []byte(`"loglevel": "warning", "access": "none"`))
	}
	serverPath := filepath.Join(scenarioDir, "server.json")
	writeConfig(t, serverPath, quiet(xrayHysteriaServerConfig(t, serverPort, certificate, privateKey, false)))
	serverArgs := []string{"run", "-config", serverPath}
	server := startE2EProcess(t, serverBinary, serverArgs...)

	clientBinary, clientArgs, clientConfig := hysteriaClientConfig(t, binaries, "xray", serverPort, socksPort, certificate, false)
	clientPath := filepath.Join(scenarioDir, "client.json")
	clientArgs = replaceConfigPath(clientArgs, clientPath)
	writeConfig(t, clientPath, quiet(clientConfig))
	client := startReadyE2EClient(t, "xray", clientBinary, clientArgs, socksPort)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("%s server logs:\n%s", name, server.logs.String())
			t.Logf("%s client logs:\n%s", name, client.logs.String())
		}
	})
	waitSOCKSTCPForwarding(t, client, socksPort, tcpEcho)
	return &stressTopology{serverBinary: serverBinary, serverArgs: serverArgs, serverPort: serverPort, client: client, server: server, socksPort: socksPort}
}

// runHysteriaUDPLoad sends packets through one SOCKS UDP association, cycling
// through targets, with at most hysteriaUDPLoadWindow packets awaiting a reply.
// Each reply frees one slot. A lost reply never frees its slot, so losses
// shrink the window; when no slot frees within 200 ms the next packet goes out
// anyway, and its reply restores one slot. A run with losses therefore
// measures a smaller window and includes the stalls in its elapsed time, which
// is why reportHysteriaUDPLoad fails a mode that loses more than 1%.
func runHysteriaUDPLoad(t *testing.T, topology *stressTopology, targets []*net.UDPAddr, packets int) hysteriaUDPLoadResult {
	t.Helper()
	association := openSOCKSUDPAssociation(t, topology.socksPort)
	defer association.udp.Close()
	defer association.control.Close()

	datagrams := make([][]byte, len(targets))
	for index, target := range targets {
		datagrams[index] = append(appendSOCKSUDPAddress([]byte{0, 0, 0}, target), make([]byte, hysteriaUDPLoadPayload)...)
	}
	tokens := make(chan struct{}, hysteriaUDPLoadWindow)
	for range hysteriaUDPLoadWindow {
		tokens <- struct{}{}
	}
	seen := make([]bool, packets)
	var sent, received atomic.Int64
	var receiveErr error
	var lastReceive atomic.Int64
	receiverDone := make(chan struct{})
	// Closing the socket ends the receiver on every exit path, t.Fatal
	// included; it is joined before the function returns.
	defer func() {
		_ = association.udp.Close()
		<-receiverDone
	}()
	go func() {
		defer close(receiverDone)
		buffer := make([]byte, 2048)
		relay := association.relay.AddrPort()
		for received.Load() < int64(packets) {
			if err := association.udp.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				receiveErr = err
				return
			}
			n, peer, err := association.udp.ReadFromUDPAddrPort(buffer)
			if err != nil {
				if !errors.Is(err, os.ErrDeadlineExceeded) {
					receiveErr = err
				}
				return
			}
			if peer.Port() != relay.Port() || peer.Addr().Unmap() != relay.Addr().Unmap() || !recordHysteriaReply(buffer[:n], targets, seen, int(sent.Load())) {
				continue
			}
			received.Add(1)
			lastReceive.Store(time.Now().UnixNano())
			select {
			case tokens <- struct{}{}:
			default:
			}
		}
	}()

	cpuBefore := processCPUTime(t, topology.server.command.Process.Pid)
	started := time.Now()
	deadline := started.Add(hysteriaUDPLoadDeadline)
	stall := time.NewTimer(time.Hour)
	defer stall.Stop()
	stopped := func(index int) {
		t.Helper()
		if receiveErr != nil {
			t.Fatalf("read UDP replies after %d sent packets: %v", index, receiveErr)
		}
		t.Fatalf("UDP replies stopped after %d of %d sent packets (%d received)", index, packets, received.Load())
	}
	for index := range packets {
		// Checked before every packet: replies that keep arriving just under
		// the stall timeout would otherwise never reach the deadline.
		if time.Now().After(deadline) {
			t.Fatalf("UDP sample exceeded %s after %d of %d packets (%d received)", hysteriaUDPLoadDeadline, index, packets, received.Load())
		}
		select {
		case <-tokens:
		case <-receiverDone:
			stopped(index)
		default:
			stall.Reset(200 * time.Millisecond)
			select {
			case <-tokens:
			case <-stall.C:
			case <-receiverDone:
				stopped(index)
			}
		}
		datagram := datagrams[index%len(datagrams)]
		binary.BigEndian.PutUint64(datagram[len(datagram)-hysteriaUDPLoadPayload:], uint64(index))
		sent.Store(int64(index + 1))
		if _, err := association.udp.WriteToUDP(datagram, association.relay); err != nil {
			t.Fatalf("send packet %d: %v", index, err)
		}
	}
	select {
	case <-receiverDone:
	case <-time.After(time.Until(deadline) + 2*time.Second):
		t.Fatalf("UDP sample exceeded %s waiting for replies (%d of %d received)", hysteriaUDPLoadDeadline, received.Load(), packets)
	}
	if receiveErr != nil {
		t.Fatalf("read UDP replies: %v", receiveErr)
	}
	cpuAfter := processCPUTime(t, topology.server.command.Process.Pid)
	result := hysteriaUDPLoadResult{
		sent:      packets,
		received:  int(received.Load()),
		elapsed:   time.Unix(0, lastReceive.Load()).Sub(started),
		serverCPU: cpuAfter - cpuBefore,
	}
	if result.received == 0 || result.elapsed <= 0 {
		t.Fatalf("no UDP replies through the Hysteria path (%d sent)", packets)
	}
	if runtime.GOOS == "linux" && result.serverCPU <= 0 {
		t.Fatalf("server CPU clock failed to advance: %v to %v", cpuBefore, cpuAfter)
	}
	return result
}

// recordHysteriaReply accepts one complete echo for each packet sent.
func recordHysteriaReply(packet []byte, targets []*net.UDPAddr, seen []bool, sent int) bool {
	source, payload, err := parseSOCKSUDPSource(packet)
	if err != nil || len(payload) != hysteriaUDPLoadPayload || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return false
	}
	sequence := binary.BigEndian.Uint64(payload)
	if sequence >= uint64(sent) || seen[sequence] {
		return false
	}
	want := targets[int(sequence)%len(targets)].AddrPort()
	var padding [hysteriaUDPLoadPayload - 8]byte
	if source != netip.AddrPortFrom(want.Addr().Unmap(), want.Port()) || !bytes.Equal(payload[8:], padding[:]) {
		return false
	}
	seen[sequence] = true
	return true
}

func medianFloat(samples []float64) float64 {
	sorted := slices.Clone(samples)
	slices.Sort(sorted)
	return sorted[len(sorted)/2]
}

func reportHysteriaUDPLoad(t *testing.T, mode string, baseline, candidate []hysteriaUDPLoadResult) {
	t.Helper()
	summarize := func(samples []hysteriaUDPLoadResult) (pps, cpu []float64, lost int) {
		for _, sample := range samples {
			pps = append(pps, sample.packetsPerSecond())
			if runtime.GOOS == "linux" {
				value, err := sample.serverCPUPerPacket()
				if err != nil {
					t.Fatal(err)
				}
				cpu = append(cpu, value)
			}
			lost += sample.sent - sample.received
		}
		return pps, cpu, lost
	}
	baselinePPS, baselineCPU, baselineLost := summarize(baseline)
	candidatePPS, candidateCPU, candidateLost := summarize(candidate)
	format := func(values []float64) string {
		parts := make([]string, len(values))
		for index, value := range values {
			parts[index] = strconv.FormatFloat(value, 'f', 0, 64)
		}
		return strings.Join(parts, " ")
	}
	ppsRatio := medianFloat(candidatePPS) / medianFloat(baselinePPS)
	t.Logf("%s pps baseline=[%s] candidate=[%s] ratio=%.3f; lost baseline=%d candidate=%d", mode, format(baselinePPS), format(candidatePPS), ppsRatio, baselineLost, candidateLost)
	var cpuRatio float64
	if runtime.GOOS == "linux" {
		cpuRatio = medianFloat(candidateCPU) / medianFloat(baselineCPU)
		t.Logf("%s server CPU ns/packet baseline=[%s] candidate=[%s] ratio=%.3f", mode, format(baselineCPU), format(candidateCPU), cpuRatio)
	}
	total := 0
	for _, sample := range baseline {
		total += sample.sent
	}
	if baselineLost*100 > total || candidateLost*100 > total {
		t.Errorf("%s lost more than 1%% of packets (baseline %d, candidate %d of %d): the load measures drops, not throughput", mode, baselineLost, candidateLost, total)
	}
	if runtime.GOOS != "linux" || os.Getenv("XRAY_NATIVE_LINUX_RELEASE") != "1" {
		t.Log("diagnostics only; set XRAY_NATIVE_LINUX_RELEASE=1 on a native Linux host to enforce the 10% regression budget")
		return
	}
	if ppsRatio < 0.90 {
		t.Errorf("%s candidate pps regression %.1f%% exceeds 10%%", mode, (1-ppsRatio)*100)
	}
	if cpuRatio > 1.10 {
		t.Errorf("%s candidate server CPU per packet regression %.1f%% exceeds 10%%", mode, (cpuRatio-1)*100)
	}
}

func TestHysteriaLoadCountsDistinctEchoes(t *testing.T) {
	targets := []*net.UDPAddr{{IP: net.IPv4(127, 0, 0, 1), Port: 53}, {IP: net.IPv6loopback, Port: 54}}
	seen := make([]bool, 3)
	reply := func(sequence uint64, target int) []byte {
		header := appendSOCKSUDPAddress([]byte{0, 0, 0}, targets[target])
		payload := make([]byte, hysteriaUDPLoadPayload)
		binary.BigEndian.PutUint64(payload, sequence)
		return append(header, payload...)
	}
	corrupt := reply(0, 0)
	corrupt[len(corrupt)-1] = 1
	for _, tc := range []struct {
		name string
		wire []byte
		want bool
	}{
		{"truncated", []byte{0, 0}, false},
		{"wrong target", reply(1, 0), false},
		{"corrupted payload", corrupt, false},
		{"unsent", reply(2, 0), false},
		{"out of order", reply(1, 1), true},
		{"duplicate", reply(1, 1), false},
		{"first", reply(0, 0), true},
	} {
		if got := recordHysteriaReply(tc.wire, targets, seen, 2); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestHysteriaCPUPerPacketRequiresMeasurement(t *testing.T) {
	for _, cpu := range []time.Duration{-time.Second, 0, 1} {
		result := hysteriaUDPLoadResult{received: 2, serverCPU: cpu}
		value, err := result.serverCPUPerPacket()
		if (err == nil) != (cpu > 0) || cpu > 0 && value != 0.5 {
			t.Errorf("CPU %v: got %v ns/packet, %v", cpu, value, err)
		}
	}
}
