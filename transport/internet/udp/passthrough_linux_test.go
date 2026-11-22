package udp

import (
	"context"
	"net"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"github.com/xtls/xray-core/transport/internet/finalmask/filter"
)

func TestPassthroughFilterPreservesHubPacketMetadata(t *testing.T) {
	settings := &internet.SocketConfig{ReceiveOriginalDestAddress: true}
	stack := finalmask.NewFinalMask(nil, []finalmask.UDPMask{&filter.Config{}}, nil, nil, nil,
		func(ctx context.Context, addr net.Addr) (net.PacketConn, error) {
			return internet.ListenSystemPacket(ctx, addr, settings)
		})
	hub, err := ListenUDP(t.Context(), xnet.LocalHostIP, 0, &internet.MemoryStreamConfig{FinalMask: stack, SocketSettings: settings})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	client, err := net.DialUDP("udp4", nil, hub.Addr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-hub.Receive():
		if p == nil {
			t.Fatal("hub closed")
		}
		defer p.Payload.Release()
		want := xnet.DestinationFromAddr(hub.Addr())
		if p.PhysicalPeer != p.Source || p.Target != want {
			t.Fatalf("peer %v, want %v; target %v, want %v", p.PhysicalPeer, p.Source, p.Target, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no datagram delivered")
	}
}
