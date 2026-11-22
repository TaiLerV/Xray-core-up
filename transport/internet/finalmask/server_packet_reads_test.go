package finalmask_test

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"github.com/xtls/xray-core/transport/internet/finalmask/xdns"
	"github.com/xtls/xray-core/transport/internet/udp"
	"golang.org/x/net/dns/dnsmessage"
)

type recordingXDNSServer struct {
	*xdns.Config
	socket net.PacketConn
}

func (m *recordingXDNSServer) WrapPacketConnServer(conn net.PacketConn, addr net.Addr, lc *finalmask.ListenConfig) (net.PacketConn, error) {
	m.socket = conn
	return m.Config.WrapPacketConnServer(conn, addr, lc)
}

func TestRawListenerPreservesXDNSServerPacketReads(t *testing.T) {
	mask := &recordingXDNSServer{Config: &xdns.Config{Domains: []*xdns.DomainProto{{Name: "test.example", LenLimit: 255, LabelLimit: 63, Types: []int32{16}}}}}
	var socket net.PacketConn
	stack := finalmask.NewFinalMask(nil, []finalmask.UDPMask{mask}, nil, nil, nil,
		func(ctx context.Context, addr net.Addr) (net.PacketConn, error) {
			var err error
			socket, err = (&net.ListenConfig{}).ListenPacket(ctx, "udp4", addr.String())
			return socket, err
		})
	plain, err := stack.ListenPacket(t.Context(), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = plain.Close() })
	hub, err := udp.ListenUDP(t.Context(), xnet.LocalHostIP, 0, &internet.MemoryStreamConfig{FinalMask: stack})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	// The server owns its read size, including the native truncation semantics.
	if mask.socket != socket {
		t.Fatalf("hub gave xdns %T, want its original UDP socket", mask.socket)
	}

	query := dnsmessage.Message{Header: dnsmessage.Header{ID: 123}, Questions: []dnsmessage.Question{{
		Name: dnsmessage.MustNewName("test.example."), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET,
	}}}
	wire, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	exchange := func(addr net.Addr) []byte {
		t.Helper()
		client, err := net.DialUDP("udp4", nil, addr.(*net.UDPAddr))
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := client.Write(wire); err != nil {
			t.Fatal(err)
		}
		var packet [512]byte
		n, err := client.Read(packet[:])
		if err != nil {
			t.Fatal(err)
		}
		var reply dnsmessage.Message
		if err := reply.Unpack(packet[:n]); err != nil {
			t.Fatal(err)
		}
		if !reply.Response || reply.ID != query.ID || reply.RCode != dnsmessage.RCodeSuccess {
			t.Fatalf("unexpected apex reply: %+v", reply.Header)
		}
		return packet[:n]
	}
	if want, got := exchange(plain.LocalAddr()), exchange(hub.Addr()); !bytes.Equal(want, got) {
		t.Fatalf("hub reply %x differs from plain listener reply %x", got, want)
	}
}
