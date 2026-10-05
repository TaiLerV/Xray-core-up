package quic

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/apernet/quic-go/quicvarint"
	"github.com/xtls/xray-core/common/protocol"
)

// quicClientHello returns the ClientHello a crypto/tls QUIC client sends for
// serverName.
func quicClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	conn := tls.QUICClient(&tls.QUICConfig{TLSConfig: &tls.Config{
		ServerName: serverName,
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h3"},
	}})
	conn.SetTransportParameters(nil)
	if err := conn.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for {
		event := conn.NextEvent()
		switch {
		case event.Kind == tls.QUICNoEvent:
			t.Fatal("the QUIC client sent no ClientHello")
		case event.Kind == tls.QUICWriteData && event.Level == tls.QUICEncryptionLevelInitial:
			return bytes.Clone(event.Data)
		}
	}
}

// cryptoFrame is a CRYPTO frame carrying data at offset of the CRYPTO stream.
type cryptoFrame struct {
	offset int
	data   []byte
}

// sealInitial returns a QUIC v1 client Initial packet for destConnID with
// packet number pn that carries frames (RFC 9000, Section 17.2.2; RFC 9001,
// Section 5).
func sealInitial(t *testing.T, destConnID []byte, pn uint32, frames ...cryptoFrame) []byte {
	t.Helper()
	keys, err := newInitialKeys(&quicV1, destConnID)
	if err != nil {
		t.Fatal(err)
	}
	var payload []byte
	for _, frame := range frames {
		payload = append(payload, 0x06)
		payload = quicvarint.Append(payload, uint64(frame.offset))
		payload = quicvarint.Append(payload, uint64(len(frame.data)))
		payload = append(payload, frame.data...)
	}
	payload = append(payload, make([]byte, 32)...) // PADDING, so a header protection sample exists

	const pnLen = 4
	header := []byte{0xc0 | (pnLen - 1), 0, 0, 0, 1, byte(len(destConnID))}
	header = append(header, destConnID...)
	header = append(header, 0, 0) // no Source Connection ID or token
	header = quicvarint.AppendWithLen(header, uint64(pnLen+len(payload)+keys.aead.Overhead()), 2)
	pnOffset := len(header)
	header = binary.BigEndian.AppendUint32(header, pn)

	nonce := make([]byte, keys.aead.NonceSize())
	binary.BigEndian.PutUint32(nonce[len(nonce)-pnLen:], pn)
	packet := keys.aead.Seal(header, nonce, payload, header)

	mask := make([]byte, keys.hp.BlockSize())
	keys.hp.Encrypt(mask, packet[pnOffset+4:pnOffset+4+len(mask)])
	packet[0] ^= mask[0] & 0x0f
	for i := range pnLen {
		packet[pnOffset+i] ^= mask[1+i]
	}
	return packet
}

// serverNameLengthOffset returns the offset of the host_name length field in
// a ClientHello for serverName.
func serverNameLengthOffset(t *testing.T, hello []byte, serverName string) int {
	t.Helper()
	index := bytes.Index(hello, []byte(serverName))
	if index < 3 || hello[index-3] != 0 || int(binary.BigEndian.Uint16(hello[index-2:])) != len(serverName) {
		t.Fatalf("no host_name %q in the ClientHello", serverName)
	}
	return index - 2
}

var testDestConnID = []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}

// A ClientHello missing only the two bytes of its host_name length is not a
// ClientHello with an empty server name: Chrome sends CRYPTO fragments as
// small as two bytes, so such a gap happens. The sniffer must wait for the
// missing fragment, then find the name.
func TestSniffQUICWaitsForMissingServerNameLength(t *testing.T) {
	const serverName = "gap.sniff.test"
	hello := quicClientHello(t, serverName)
	gap := serverNameLengthOffset(t, hello, serverName)

	first := sealInitial(t, testDestConnID, 0,
		cryptoFrame{0, hello[:gap]},
		cryptoFrame{gap + 2, hello[gap+2:]},
	)
	header, err := SniffQUIC(bytes.Clone(first))
	if !errors.Is(err, protocol.ErrProtoNeedMoreData) {
		domain := ""
		if header != nil {
			domain = header.Domain()
		}
		t.Fatalf("with the host_name length missing: SniffQUIC() = (%q, %v), want more data", domain, err)
	}

	second := sealInitial(t, testDestConnID, 1, cryptoFrame{gap, hello[gap : gap+2]})
	header, err = SniffQUIC(append(bytes.Clone(first), second...))
	if err != nil || header.Domain() != serverName {
		t.Fatalf("with every fragment: SniffQUIC() = (%v, %v), want %q", header, err, serverName)
	}
}

// Whichever part of the ClientHello is still missing, the sniffer must only
// ask for more data: it must neither report a server name nor reject the flow
// from bytes it has not received.
func TestSniffQUICNeverReadsMissingClientHelloBytes(t *testing.T) {
	hello := quicClientHello(t, "missing.sniff.test")
	for gap := 0; gap+2 <= len(hello); gap++ {
		packet := sealInitial(t, testDestConnID, 0,
			cryptoFrame{0, hello[:gap]},
			cryptoFrame{gap + 2, hello[gap+2:]},
		)
		header, err := SniffQUIC(packet)
		if !errors.Is(err, protocol.ErrProtoNeedMoreData) {
			domain := ""
			if header != nil {
				domain = header.Domain()
			}
			t.Fatalf("with bytes %d-%d of %d missing: SniffQUIC() = (%q, %v), want more data", gap, gap+1, len(hello), domain, err)
		}
	}
}

// The CRYPTO stream of a client's Initial packets starts with its
// ClientHello, so a stream starting with another handshake message is not
// worth waiting for.
func TestSniffQUICRejectsStreamWithoutClientHello(t *testing.T) {
	serverHello := []byte{2, 0, 0, 4, 3, 3, 0, 0} // handshake type 2
	_, err := SniffQUIC(sealInitial(t, testDestConnID, 0, cryptoFrame{0, serverHello}))
	if err == nil || errors.Is(err, protocol.ErrProtoNeedMoreData) {
		t.Fatalf("SniffQUIC() error = %v, want a rejection", err)
	}
}
