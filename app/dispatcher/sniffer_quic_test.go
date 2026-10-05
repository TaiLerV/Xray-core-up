package dispatcher

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

// quicCorpus holds client Initial datagrams captured by the Hysteria project;
// see its PROVENANCE.md.
var quicCorpus = filepath.Join("..", "..", "common", "protocol", "quic", "testdata")

func readQUICDatagrams(t *testing.T, prefix string, n int) [][]byte {
	t.Helper()
	datagrams := make([][]byte, n)
	for i := range datagrams {
		datagram, err := os.ReadFile(filepath.Join(quicCorpus, fmt.Sprintf("%s-%d.bin", prefix, i)))
		if err != nil {
			t.Fatal(err)
		}
		datagrams[i] = datagram
	}
	return datagrams
}

// datagramTimeoutReader yields one datagram per read, in its own buffer, as a
// UDP inbound link does.
type datagramTimeoutReader struct {
	datagrams [][]byte
}

func (r *datagramTimeoutReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if len(r.datagrams) == 0 {
		return nil, io.EOF
	}
	b := buf.New()
	if _, err := b.Write(r.datagrams[0]); err != nil {
		b.Release()
		return nil, err
	}
	r.datagrams = r.datagrams[1:]
	return buf.MultiBuffer{b}, nil
}

func (r *datagramTimeoutReader) ReadMultiBufferTimeout(time.Duration) (buf.MultiBuffer, error) {
	if len(r.datagrams) == 0 {
		return nil, buf.ErrReadTimeout
	}
	return r.ReadMultiBuffer()
}

// cachedReader.Cache lends its only cached buffer to the sniffers instead of
// copying it, so no default sniffer may write to its payload.
func TestDefaultSniffersLeaveBorrowedPayloadIntact(t *testing.T) {
	payloads := map[string][]byte{
		"tls":                tlsClientHello(),
		"http":               []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		"bittorrent":         vPeerHandshake(),
		"utp":                vUTPSYN(),
		"dht":                vDHTGetPeers(),
		"udp tracker":        vUDPTrackerConnect(),
		"quic one datagram":  readQUICDatagrams(t, "quic-ngtcp2-1.11", 1)[0],
		"quic first of many": readQUICDatagrams(t, "quic-chrome153", 1)[0],
	}
	ctx := snifferContext()
	for index, sniffer := range defaultProtocolSniffers {
		for name, payload := range payloads {
			borrowed := bytes.Clone(payload)
			_, _ = sniffer.protocolSniffer(ctx, borrowed)
			if !bytes.Equal(borrowed, payload) {
				t.Errorf("default sniffer %d modified the %s payload", index, name)
			}
		}
	}
}

// The cached reader lends its only buffer to the sniffers, and the dispatcher
// forwards the cached datagrams once sniffing ends. Sniffing a QUIC ClientHello
// must therefore leave every datagram byte-identical, including when the
// ClientHello spans datagrams that are cached one at a time.
func TestSniffQUICFromCachedDatagramsKeepsThemIntact(t *testing.T) {
	tests := []struct {
		name      string
		datagrams [][]byte
		domain    string
	}{
		{"ClientHello in one datagram", readQUICDatagrams(t, "quic-ngtcp2-1.11", 1), "ngtcp2.sniff.test"},
		{"ClientHello across datagrams", readQUICDatagrams(t, "quic-chrome153", 2), "chrome.sniff.test"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			received := make([][]byte, len(tt.datagrams))
			for i, datagram := range tt.datagrams {
				received[i] = bytes.Clone(datagram)
			}
			reader := newCachedReader(&datagramTimeoutReader{datagrams: received})
			ctx := snifferContext()

			result, err := sniff(ctx, reader, false, net.Network_UDP, newSniffer(ctx))
			if err != nil {
				t.Errorf("sniff() error = %v, want QUIC with %q", err, tt.domain)
			} else if result.Protocol() != "quic" || result.Domain() != tt.domain {
				t.Errorf("sniff() = %s %q, want quic %q", result.Protocol(), result.Domain(), tt.domain)
			}

			forwarded, err := reader.ReadMultiBuffer()
			if err != nil {
				t.Fatal(err)
			}
			defer buf.ReleaseMulti(forwarded)
			if len(forwarded) != len(tt.datagrams) {
				t.Fatalf("forwarded %d buffers, want one per datagram (%d)", len(forwarded), len(tt.datagrams))
			}
			for i, b := range forwarded {
				if !bytes.Equal(b.Bytes(), tt.datagrams[i]) {
					t.Errorf("forwarded datagram %d differs from the one received", i)
				}
			}
		})
	}
}
