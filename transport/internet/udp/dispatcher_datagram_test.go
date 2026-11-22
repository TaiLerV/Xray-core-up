package udp_test

import (
	"bytes"
	"context"
	"errors"
	gonet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport"
	. "github.com/xtls/xray-core/transport/internet/udp"
	"github.com/xtls/xray-core/transport/pipe"
)

// dialDispatcherLink returns the packet connection of DialDispatcher, as
// core.DialUDP gives it, with the ends of its link that an outbound holds:
// the reader of what the connection writes and the writer of what it reads.
func dialDispatcherLink(t *testing.T) (gonet.PacketConn, *pipe.Reader, *pipe.Writer) {
	t.Helper()
	uplinkReader, uplinkWriter := pipe.New(pipe.WithoutSizeLimit())
	downlinkReader, downlinkWriter := pipe.New(pipe.WithoutSizeLimit())
	dispatcher := &TestDispatcher{OnDispatch: func(context.Context, net.Destination) (*transport.Link, error) {
		return &transport.Link{Reader: downlinkReader, Writer: uplinkWriter}, nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	conn, err := DialDispatcher(ctx, dispatcher)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		conn.Close()
		downlinkWriter.Close()
		uplinkReader.Interrupt()
	})
	return conn, uplinkReader, downlinkWriter
}

// The packet connection of DialDispatcher copied what it was written into a
// regular buffer: of a datagram above buf.Size it dispatched the first 8192
// bytes as a whole one and reported a short write without an error. It
// dispatches the datagram in one buffer of its size.
func TestDispatcherConnWritesDatagramsWhole(t *testing.T) {
	conn, uplinkReader, _ := dialDispatcherLink(t)
	destination := &gonet.UDPAddr{IP: gonet.IPv4(127, 0, 0, 1), Port: 53}
	for _, payload := range [][]byte{bytes.Repeat([]byte{1}, 9000), bytes.Repeat([]byte{2}, buf.Size), []byte("ping")} {
		n, err := conn.WriteTo(payload, destination)
		if err != nil || n != len(payload) {
			t.Fatalf("wrote %d bytes of a datagram of %d: %v", n, len(payload), err)
		}
		mb, err := uplinkReader.ReadMultiBufferTimeout(5 * time.Second)
		if err != nil {
			t.Fatalf("waiting for the datagram of %d bytes: %v", len(payload), err)
		}
		lengths := make([]int32, 0, len(mb))
		for _, b := range mb {
			lengths = append(lengths, b.Len())
		}
		whole := len(mb) == 1 && bytes.Equal(mb[0].Bytes(), payload)
		buf.ReleaseMulti(mb)
		if !whole {
			t.Fatalf("dispatched buffers of %v bytes, want the datagram of %d bytes whole", lengths, len(payload))
		}
	}
}

// ReadFrom copied the start of a reply longer than the buffer into it and
// dropped the rest without a sign, as a UDP socket does. It drops such a
// reply and returns the next.
func TestDispatcherConnDropsRepliesLongerThanTheRead(t *testing.T) {
	conn, _, downlinkWriter := dialDispatcherLink(t)
	// the dispatcher reads replies only once a datagram has opened the link
	if _, err := conn.WriteTo([]byte("ping"), &gonet.UDPAddr{IP: gonet.IPv4(127, 0, 0, 1), Port: 53}); err != nil {
		t.Fatal(err)
	}
	sent := [][]byte{bytes.Repeat([]byte{1}, buf.Size+1), bytes.Repeat([]byte{2}, buf.Size), []byte("pong")}
	var buffers []*buf.Buffer
	for _, reply := range sent {
		var b *buf.Buffer
		if len(reply) > buf.Size {
			b = buf.NewWithSize(int32(len(reply)))
		} else {
			b = buf.New()
			b.SetManagedUDPIPv4([4]byte{127, 0, 0, 7}, 5300)
		}
		buffers = append(buffers, b)
		_, _ = b.Write(reply)
		if err := downlinkWriter.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
			t.Fatal(err)
		}
	}
	type read struct {
		payload []byte
		source  gonet.Addr
		err     error
	}
	p := make([]byte, buf.Size)
	for _, want := range sent[1:] {
		done := make(chan read, 1)
		go func() {
			n, source, err := conn.ReadFrom(p)
			done <- read{bytes.Clone(p[:n]), source, err}
		}()
		select {
		case got := <-done:
			if got.err != nil {
				t.Fatalf("waiting for the reply of %d bytes: %v", len(want), got.err)
			}
			if got.source == nil || got.source.String() != "127.0.0.7:5300" {
				t.Errorf("reply source = %v, want 127.0.0.7:5300", got.source)
			}
			if !bytes.Equal(got.payload, want) {
				t.Fatalf("unexpected reply payload of %d bytes, want %d bytes", len(got.payload), len(want))
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("no reply of %d bytes within 5s", len(want))
		}
	}
	for i, b := range buffers {
		if b.Cap() != 0 {
			t.Errorf("reply %d still owns its buffer after ReadFrom", i)
		}
	}
}

func TestDispatcherConnEmptyReadLeavesQueuedReply(t *testing.T) {
	conn, _, writer := dialDispatcherLink(t)
	if _, err := conn.WriteTo([]byte("open"), &gonet.UDPAddr{IP: gonet.IPv4(127, 0, 0, 1), Port: 53}); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("pong"))}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if n, _, err := conn.ReadFrom(nil); n != 0 || err != nil {
		t.Fatalf("empty read returned (%d, %v)", n, err)
	}
	var p [4]byte
	n, _, err := conn.ReadFrom(p[:])
	if err != nil || string(p[:n]) != "pong" {
		t.Fatalf("read after empty read = %q, %v", p[:n], err)
	}
}

func TestDispatcherConnReportsDispatchRefusal(t *testing.T) {
	refused := errors.New("route refused")
	router := &TestDispatcher{OnDispatch: func(context.Context, net.Destination) (*transport.Link, error) {
		return nil, refused
	}}
	conn, err := DialDispatcher(t.Context(), router)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if n, err := conn.WriteTo([]byte("ping"), &gonet.UDPAddr{IP: gonet.IPv4(127, 0, 0, 1), Port: 53}); n != 0 || !errors.Is(err, refused) {
		t.Fatalf("write refused by router returned (%d, %v)", n, err)
	}
	b := buf.New()
	b.WriteString("ping")
	NewDispatcher(router, nil).Dispatch(t.Context(), net.UDPDestination(net.LocalHostIP, 53), b)
	if b.Cap() != 0 {
		t.Fatal("refused dispatch retained its payload")
	}
}

func TestDispatcherHonorsReplacedDomainDestination(t *testing.T) {
	conn, _, writer := dialDispatcherLink(t)
	if _, err := conn.WriteTo([]byte("open"), &gonet.UDPAddr{IP: gonet.IPv4(127, 0, 0, 1), Port: 53}); err != nil {
		t.Fatal(err)
	}
	b := buf.New()
	b.SetManagedUDPDomain("previous.example", 53)
	current := net.UDPDestination(net.LocalHostIP, 5300)
	b.UDP = &current
	b.WriteString("pong")
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	var p [4]byte
	n, addr, err := conn.ReadFrom(p[:])
	if err != nil || addr == nil || addr.String() != "127.0.0.1:5300" || string(p[:n]) != "pong" {
		t.Fatalf("read %q from %v, %v", p[:n], addr, err)
	}
}
