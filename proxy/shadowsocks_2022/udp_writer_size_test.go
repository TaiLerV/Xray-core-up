package shadowsocks_2022_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	stdnet "net"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	. "github.com/xtls/xray-core/proxy/shadowsocks_2022"
)

// packetConn records each Write as one UDP packet.
type packetConn struct {
	packets [][]byte
}

func (c *packetConn) Write(p []byte) (int, error) {
	c.packets = append(c.packets, bytes.Clone(p))
	return len(p), nil
}

// The client writer encodes each datagram as one UDP packet of at most
// buf.Size bytes, which is what Xray's server reads. It returned an error for
// a datagram that does not fit, which ended the UDP session; it must drop that
// datagram, as the VLESS and VMess writers drop theirs, and send the next.
func TestUDPWriterDropsDatagramsTooLargeForAPacket(t *testing.T) {
	method, err := GetCipherMethod(MethodAES128GCM)
	common.Must(err)
	key := make([]byte, method.KeySaltLength)
	common.Must2(rand.Read(key))
	clientCodec, err := NewUDPPacketCodec(method, [][]byte{key})
	common.Must(err)
	serverCodec, err := NewUDPServerCodec(method, key, time.Minute)
	common.Must(err)
	session, err := clientCodec.NewClientSession()
	common.Must(err)

	destination := net.UDPDestination(net.IPAddress([]byte{192, 0, 2, 7}), 5353)
	var conn packetConn
	writer := &UDPWriter{Writer: &conn, Destination: destination, Session: session}
	payloads := [][]byte{bytes.Repeat([]byte{1}, 100), bytes.Repeat([]byte{2}, 9000), bytes.Repeat([]byte{3}, 200)}
	mb := make(buf.MultiBuffer, len(payloads))
	for i, payload := range payloads {
		mb[i] = buf.NewWithSize(int32(len(payload)))
		mb[i].Write(payload)
	}
	if err := writer.WriteMultiBuffer(mb); err != nil {
		t.Fatalf("WriteMultiBuffer() = %v, want the datagram that does not fit dropped", err)
	}
	if len(conn.packets) != 2 {
		t.Fatalf("sent %d packets, want 2", len(conn.packets))
	}
	for i, want := range [][]byte{payloads[0], payloads[2]} {
		decoded, err := serverCodec.DecodePacket(conn.packets[i])
		common.Must(err)
		if !bytes.Equal(decoded.Payload, want) {
			t.Fatalf("packet %d carries %d bytes, want %d", i, len(decoded.Payload), len(want))
		}
	}

	// Any other error of the encoder still ends the session: a domain longer
	// than 255 bytes has no address encoding.
	unencodable := buf.FromBytes([]byte("ping"))
	unencodable.UDP = &net.Destination{Network: net.Network_UDP, Address: net.DomainAddress(strings.Repeat("a", 300) + ".example"), Port: 53}
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{unencodable, buf.FromBytes([]byte("pong"))}); err == nil {
		t.Fatal("WriteMultiBuffer() = nil, want the error of the destination it cannot encode")
	}
	if len(conn.packets) != 2 {
		t.Fatalf("sent %d packets after the error, want none", len(conn.packets)-2)
	}
}

type maxSizePacketConn struct {
	maxLen  int
	failErr error
	packets [][]byte
}

func (c *maxSizePacketConn) Write(p []byte) (int, error) {
	if c.failErr != nil {
		return 0, c.failErr
	}
	if len(p) > c.maxLen {
		return 0, &stdnet.OpError{Op: "write", Net: "udp", Err: syscall.EMSGSIZE}
	}
	c.packets = append(c.packets, bytes.Clone(p))
	return len(p), nil
}

func TestUDPWriterDropsDatagramsTheSocketRefusesAsTooLong(t *testing.T) {
	method, err := GetCipherMethod(MethodAES128GCM)
	common.Must(err)
	key := make([]byte, method.KeySaltLength)
	common.Must2(rand.Read(key))
	clientCodec, err := NewUDPPacketCodec(method, [][]byte{key})
	common.Must(err)
	serverCodec, err := NewUDPServerCodec(method, key, time.Minute)
	common.Must(err)
	session, err := clientCodec.NewClientSession()
	common.Must(err)

	destination := net.UDPDestination(net.IPAddress([]byte{192, 0, 2, 7}), 5353)
	conn := &maxSizePacketConn{maxLen: 200}
	writer := &UDPWriter{Writer: conn, Destination: destination, Session: session}
	payloads := [][]byte{bytes.Repeat([]byte{1}, 60), bytes.Repeat([]byte{2}, 400), bytes.Repeat([]byte{3}, 80)}
	mb := make(buf.MultiBuffer, len(payloads))
	for i, payload := range payloads {
		mb[i] = buf.NewWithSize(int32(len(payload)))
		mb[i].Write(payload)
	}
	if err := writer.WriteMultiBuffer(mb); err != nil {
		t.Fatalf("WriteMultiBuffer() = %v, want socket EMSGSIZE dropped", err)
	}
	if len(conn.packets) != 2 {
		t.Fatalf("sent %d packets, want 2", len(conn.packets))
	}
	for i, want := range [][]byte{payloads[0], payloads[2]} {
		decoded, err := serverCodec.DecodePacket(conn.packets[i])
		common.Must(err)
		if !bytes.Equal(decoded.Payload, want) {
			t.Fatalf("packet %d carries %d bytes, want %d", i, len(decoded.Payload), len(want))
		}
	}

	// Any other socket error still ends the session and drops the rest of mb.
	conn.failErr = stdnet.ErrClosed
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("ping")), buf.FromBytes([]byte("pong"))}); !errors.Is(err, stdnet.ErrClosed) {
		t.Fatalf("WriteMultiBuffer() = %v, want ErrClosed", err)
	}
}

type scriptedUDPReader struct {
	steps []struct {
		data []byte
		err  error
	}
	index int
}

func (r *scriptedUDPReader) Read(p []byte) (int, error) {
	if r.index >= len(r.steps) {
		return 0, io.EOF
	}
	step := r.steps[r.index]
	r.index++
	if step.err != nil {
		return 0, step.err
	}
	return copy(p, step.data), nil
}

func TestUDPReaderSkipsSocketTooLongError(t *testing.T) {
	method, err := GetCipherMethod(MethodAES128GCM)
	common.Must(err)
	key := make([]byte, method.KeySaltLength)
	common.Must2(rand.Read(key))
	clientCodec, err := NewUDPPacketCodec(method, [][]byte{key})
	common.Must(err)
	serverCodec, err := NewUDPServerCodec(method, key, time.Minute)
	common.Must(err)
	session, err := clientCodec.NewClientSession()
	common.Must(err)

	destination := net.UDPDestination(net.IPAddress([]byte{192, 0, 2, 7}), 5353)
	req, err := session.EncodePacket(destination, []byte("ping"))
	common.Must(err)
	decodedReq, err := serverCodec.DecodePacket(req.Bytes())
	req.Release()
	common.Must(err)
	replyWire, err := serverCodec.EncodeServerPacket(decodedReq.SessionID, destination, []byte("pong"))
	common.Must(err)

	reader := &UDPReader{
		Reader: &scriptedUDPReader{steps: []struct {
			data []byte
			err  error
		}{
			{err: &stdnet.OpError{Op: "read", Net: "udp", Err: syscall.EMSGSIZE}},
			{data: replyWire},
		}},
		Session: session,
	}
	mb, err := reader.ReadMultiBuffer()
	if err != nil {
		t.Fatalf("ReadMultiBuffer() = %v, want EMSGSIZE skipped and pong decoded", err)
	}
	defer buf.ReleaseMulti(mb)
	if len(mb) != 1 || string(mb[0].Bytes()) != "pong" {
		t.Fatalf("ReadMultiBuffer() = %q, want pong", mb[0].Bytes())
	}
	if _, err := reader.ReadMultiBuffer(); !errors.Is(err, io.EOF) {
		t.Fatalf("second ReadMultiBuffer() = %v, want EOF", err)
	}
}
