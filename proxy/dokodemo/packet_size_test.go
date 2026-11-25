package dokodemo

import (
	"bytes"
	"context"
	"errors"
	stdnet "net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
)

// replyDispatcher answers each dispatched UDP session with replies, written to
// the inbound's link at once, and returns the error of that write.
type replyDispatcher struct {
	replies func() buf.MultiBuffer
}

func (*replyDispatcher) Type() interface{} { return nil }
func (*replyDispatcher) Start() error      { return nil }
func (*replyDispatcher) Close() error      { return nil }

func (*replyDispatcher) Dispatch(context.Context, net.Destination) (*transport.Link, error) {
	return nil, errors.New("not implemented")
}

func (d *replyDispatcher) DispatchLink(_ context.Context, _ net.Destination, link *transport.Link) error {
	return link.Writer.WriteMultiBuffer(d.replies())
}

// payloads returns a buffer for each payload.
func payloads(sent ...[]byte) buf.MultiBuffer {
	mb := make(buf.MultiBuffer, len(sent))
	for i, payload := range sent {
		mb[i] = buf.NewWithSize(int32(len(payload)))
		mb[i].Write(payload)
	}
	return mb
}

// receive reads the datagrams want from sink, in turn.
func receive(t *testing.T, sink *net.UDPConn, want ...[]byte) {
	t.Helper()
	received := make([]byte, 65536)
	for _, payload := range want {
		if err := sink.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		n, _, err := sink.ReadFrom(received)
		if err != nil {
			t.Fatalf("waiting for the datagram of %d bytes: %v", len(payload), err)
		}
		if !bytes.Equal(received[:n], payload) {
			t.Fatalf("received a datagram of %d bytes, want the one of %d", n, len(payload))
		}
	}
}

func loopbackPair(t *testing.T) (sink *net.UDPConn, conn *net.UDPConn) {
	t.Helper()
	sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.LocalHostIP.IP()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sink.Close() })
	conn, err = net.DialUDP("udp", nil, sink.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return sink, conn
}

// The outbounds hand dokodemo-door a UDP reply whole, up to the 65535 bytes
// their framings allow, but the socket back to the client refuses one longer
// than an IP packet holds with EMSGSIZE, which ended the UDP session. The
// inbound drops that reply and sends the next; any other error still ends the
// session.
func TestProcessDropsRepliesTheSocketRefusesAsTooLong(t *testing.T) {
	sink, conn := loopbackPair(t)
	door := new(DokodemoDoor)
	config := &Config{RewriteAddress: net.NewIPOrDomain(net.LocalHostIP), RewritePort: 53, AllowedNetworks: []net.Network{net.Network_UDP}}
	if err := door.Init(config, policy.DefaultManager{}, nil); err != nil {
		t.Fatal(err)
	}
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{})
	dispatcher := &replyDispatcher{replies: func() buf.MultiBuffer {
		return payloads([]byte("ping"), bytes.Repeat([]byte{2}, 65508), []byte("pong"))
	}}
	if err := door.Process(ctx, net.Network_UDP, conn, dispatcher); err != nil {
		t.Fatalf("Process() = %v, want the reply the socket refuses dropped", err)
	}
	receive(t, sink, []byte("ping"), []byte("pong"))

	conn.Close()
	dispatcher.replies = func() buf.MultiBuffer { return payloads([]byte("ping")) }
	if err := door.Process(ctx, net.Network_UDP, conn, dispatcher); !errors.Is(err, stdnet.ErrClosed) {
		t.Fatalf("Process() = %v, want the error of the closed socket", err)
	}
}

// In TPROXY mode the replies leave through sockets bound to their sources.
// A socket that refused a reply as too long was closed and forgotten, and a
// refusal on the inbound's own socket ended the session. The writer drops the
// reply and keeps the socket.
func TestPacketWriterDropsRepliesTheSocketRefusesAsTooLong(t *testing.T) {
	for name, source := range map[string]func(net.Destination) *net.Destination{
		"own socket":    func(net.Destination) *net.Destination { return nil },
		"source socket": func(d net.Destination) *net.Destination { return &d },
	} {
		t.Run(name, func(t *testing.T) {
			sink, _ := loopbackPair(t)
			conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.LocalHostIP.IP()})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { conn.Close() })
			dest := net.DestinationFromAddr(conn.LocalAddr())
			writer := NewPacketWriter(conn, &dest, 0, sink.LocalAddr().(*net.UDPAddr))
			mb := payloads([]byte("ping"), bytes.Repeat([]byte{2}, 65508), []byte("pong"))
			for _, b := range mb {
				b.UDP = source(dest)
			}
			if err := writer.WriteMultiBuffer(mb); err != nil {
				t.Fatalf("WriteMultiBuffer() = %v, want the reply the socket refuses dropped", err)
			}
			receive(t, sink, []byte("ping"), []byte("pong"))
			if _, err := conn.WriteTo([]byte("open"), sink.LocalAddr()); err != nil {
				t.Fatalf("the writer closed the socket that refused a reply: %v", err)
			}
		})
	}
}

type addressOnly struct{ net.Address }

type recordingPacketConn struct {
	mu     sync.Mutex
	writes int
	closed bool
}

func (c *recordingPacketConn) ReadFrom([]byte) (int, stdnet.Addr, error) { select {} }
func (c *recordingPacketConn) WriteTo(p []byte, _ stdnet.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes++
	return len(p), nil
}

func (c *recordingPacketConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (*recordingPacketConn) LocalAddr() stdnet.Addr          { return &stdnet.UDPAddr{} }
func (*recordingPacketConn) SetDeadline(time.Time) error     { return nil }
func (*recordingPacketConn) SetReadDeadline(time.Time) error { return nil }
func (*recordingPacketConn) SetWriteDeadline(time.Time) error {
	return nil
}

// PacketWriter must key source sockets by IP value, not by a pointer into a
// released packet buffer slab.
func TestPacketWriterReusesTargetSocketForSlabAddresses(t *testing.T) {
	ipv4 := [4]byte{192, 0, 2, 1}
	for _, test := range []struct {
		name   string
		target net.Destination
		set    func(*buf.Buffer)
	}{
		{name: "managed ipv4", target: net.UDPDestination(net.IPv4Address(ipv4), 443), set: func(b *buf.Buffer) { b.SetManagedUDPIPv4(ipv4, 443) }},
		{name: "IP without NetIPAddr", target: net.UDPDestination(net.IPv4Address(ipv4), 443), set: func(b *buf.Buffer) {
			b.SetManagedUDPDestination(net.UDPDestination(addressOnly{net.IPv4Address(ipv4)}, 443))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			target := &recordingPacketConn{}
			writer := NewPacketWriter(target, &test.target, 0, &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: 9}).(*PacketWriter)
			fallback := &recordingPacketConn{}
			writer.conn = fallback
			mb := make(buf.MultiBuffer, 0, 3)
			for range 3 {
				reply := buf.New()
				reply.WriteString("reply")
				test.set(reply)
				mb = append(mb, reply)
			}
			if err := writer.WriteMultiBuffer(mb); err != nil {
				t.Fatal(err)
			}
			if target.writes != 3 || fallback.writes != 0 || len(writer.conns) != 1 {
				t.Fatalf("target socket got %d of 3 replies, fallback %d; writer holds %d sockets, want 1", target.writes, fallback.writes, len(writer.conns))
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			if !target.closed {
				t.Fatal("Close left the target socket open")
			}
		})
	}
}

func TestPacketWriterClosesUnkeyedSocket(t *testing.T) {
	target := &recordingPacketConn{}
	destination := net.UDPDestination(net.DomainAddress("example.com"), 443)
	writer := NewPacketWriter(target, &destination, 0, &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: 9}).(*PacketWriter)
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if !target.closed {
		t.Fatal("Close left the socket of a non-IP destination open")
	}
}
