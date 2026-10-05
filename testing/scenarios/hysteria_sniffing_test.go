package scenarios

import (
	"bytes"
	"encoding/json"
	"fmt"
	stdnet "net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/testing/servers/udp"
)

// quicClientDatagrams reads client Initial datagrams captured by the Hysteria
// project; see common/protocol/quic/testdata/PROVENANCE.md.
func quicClientDatagrams(t *testing.T, prefix string, n int) [][]byte {
	t.Helper()
	datagrams := make([][]byte, n)
	for i := range datagrams {
		path := filepath.Join("..", "..", "common", "protocol", "quic", "testdata", fmt.Sprintf("%s-%d.bin", prefix, i))
		datagram, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		datagrams[i] = datagram
	}
	return datagrams
}

// datagramRecorder is a UDP destination that records each datagram it receives.
type datagramRecorder struct {
	conn     *stdnet.UDPConn
	received chan []byte
}

func startDatagramRecorder(t *testing.T) *datagramRecorder {
	t.Helper()
	conn, err := stdnet.ListenUDP("udp", &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	recorder := &datagramRecorder{conn: conn, received: make(chan []byte, 64)}
	go func() {
		defer close(recorder.received)
		for {
			datagram := make([]byte, 2048)
			n, _, err := conn.ReadFromUDP(datagram)
			if err != nil {
				return
			}
			recorder.received <- datagram[:n]
		}
	}()
	t.Cleanup(func() { _ = conn.Close() })
	return recorder
}

func (r *datagramRecorder) port() int {
	return r.conn.LocalAddr().(*stdnet.UDPAddr).Port
}

// startHysteriaSniffingTunnel starts an Xray client and an Xray Hysteria server
// that sniffs QUIC. The client forwards UDP from the returned port to direct
// through the server, which sends flows whose sniffed server name ends in
// .sniff.test to sniffed instead.
func startHysteriaSniffingTunnel(t *testing.T) (clientPort int, direct, sniffed *datagramRecorder) {
	t.Helper()
	direct = startDatagramRecorder(t)
	sniffed = startDatagramRecorder(t)

	certificate, certificateHash := cert.MustGenerate(nil, cert.CommonName("localhost"), cert.DNSNames("localhost"))
	certificatePEM, keyPEM := certificate.ToPEM()
	pemLines := func(block []byte) string {
		return string(common.Must2(json.Marshal(strings.Split(strings.TrimSpace(string(block)), "\n"))))
	}

	serverPort := udp.PickPort()
	clientPort = int(udp.PickPort())
	const auth = "quic-sniffing"
	serverConfig := buildJSONConfig(t, fmt.Sprintf(`{
		"log": {"loglevel": "warning"},
		"inbounds": [{
			"listen": "127.0.0.1", "port": %d, "protocol": "hysteria",
			"settings": {"version": 2, "clients": [{"auth": %q, "email": "sniffing@example.test"}]},
			"streamSettings": {"network": "hysteria", "security": "tls",
				"tlsSettings": {"alpn": ["h3"], "certificates": [{"certificate": %s, "key": %s}]},
				"hysteriaSettings": {"version": 2}},
			"sniffing": {"enabled": true, "destOverride": ["quic"], "routeOnly": true}
		}],
		"outbounds": [
			{"tag": "direct", "protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}},
			{"tag": "sniffed", "protocol": "freedom", "settings": {"redirect": "127.0.0.1:%d", "finalRules": [{"action": "allow"}]}}
		],
		"routing": {"rules": [{"domain": ["regexp:\\.sniff\\.test$"], "outboundTag": "sniffed"}]}
	}`, serverPort, auth, pemLines(certificatePEM), pemLines(keyPEM), sniffed.port()))
	clientConfig := buildJSONConfig(t, fmt.Sprintf(`{
		"log": {"loglevel": "warning"},
		"inbounds": [{
			"listen": "127.0.0.1", "port": %d, "protocol": "dokodemo-door",
			"settings": {"address": "127.0.0.1", "port": %d, "network": "udp"}
		}],
		"outbounds": [{
			"protocol": "hysteria",
			"settings": {"version": 2, "address": "127.0.0.1", "port": %d},
			"streamSettings": {"network": "hysteria", "security": "tls",
				"tlsSettings": {"alpn": ["h3"], "serverName": "localhost", "pinnedPeerCertSha256": "%x"},
				"hysteriaSettings": {"version": 2, "auth": %q}}
		}]
	}`, clientPort, direct.port(), serverPort, certificateHash, auth))

	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	common.Must(err)
	t.Cleanup(func() { CloseAllServers(servers) })
	return clientPort, direct, sniffed
}

// Hysteria 2.13.0 made sniffing find the server name of QUIC clients whose
// ClientHello spans several datagrams, so that domain rules apply to them.
// Through an Xray Hysteria server with QUIC sniffing, each client's first
// flight must be routed by its sniffed server name, and reach the destination
// unmodified.
func TestHysteriaRoutesQUICBySniffedServerName(t *testing.T) {
	for _, flow := range []struct {
		name, prefix string
		datagrams    int
	}{
		{"Chrome 153", "quic-chrome153", 2},
		{"Firefox 153 ESR", "quic-firefox153esr", 2},
		{"curl 8.14 with OpenSSL 3.5", "quic-curl8.14-openssl3.5", 2},
		{"quiche", "quic-quiche", 3},
		{"ngtcp2 1.11", "quic-ngtcp2-1.11", 1},
		{"aioquic 1.2", "quic-aioquic1.2", 1},
	} {
		t.Run(flow.name, func(t *testing.T) {
			datagrams := quicClientDatagrams(t, flow.prefix, flow.datagrams)
			clientPort, direct, sniffed := startHysteriaSniffingTunnel(t)
			conn, err := stdnet.DialUDP("udp", nil, &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: clientPort})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			for _, datagram := range datagrams {
				if _, err := conn.Write(datagram); err != nil {
					t.Fatal(err)
				}
			}

			// Hysteria relays UDP in unreliable QUIC datagrams, which may also
			// arrive out of order, so a lost datagram is told apart from one
			// that was modified or routed without the sniffed server name.
			var viaSniffed, viaDirect [][]byte
			deadline := time.After(10 * time.Second)
		receive:
			for len(viaSniffed)+len(viaDirect) < len(datagrams) {
				select {
				case got := <-sniffed.received:
					viaSniffed = append(viaSniffed, got)
				case got := <-direct.received:
					viaDirect = append(viaDirect, got)
				case <-deadline:
					break receive
				}
			}
			for _, got := range slices.Concat(viaSniffed, viaDirect) {
				if !slices.ContainsFunc(datagrams, func(sent []byte) bool { return bytes.Equal(got, sent) }) {
					t.Errorf("a %d-byte datagram reached a destination modified", len(got))
				}
			}
			for i, sent := range datagrams {
				isSent := func(got []byte) bool { return bytes.Equal(got, sent) }
				switch {
				case slices.ContainsFunc(viaDirect, isSent):
					t.Errorf("datagram %d was routed without its sniffed server name", i)
				case !slices.ContainsFunc(viaSniffed, isSent):
					t.Errorf("datagram %d did not arrive within 10s; it may have been lost in transit", i)
				}
			}
		})
	}
}
