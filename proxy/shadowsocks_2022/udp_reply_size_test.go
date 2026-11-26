package shadowsocks_2022

import (
	"bytes"
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

// ServerUDPSession.EncodeServerPacket wrote the reply header, address and
// payload into an 8192-byte Buffer without checking ErrBufferFull, so a whole
// reply above ~8150 bytes was truncated and AEAD-sealed as an ~8.2 KiB packet
// that clients with larger buffers accepted as valid. Keep large replies whole.
func TestEncodeServerPacketKeepsLargeRepliesWhole(t *testing.T) {
	dests := []net.Destination{
		net.UDPDestination(net.IPAddress([]byte{192, 0, 2, 7}), 5353),
		net.UDPDestination(net.ParseAddress("2001:db8::7"), 5353),
		net.UDPDestination(net.DomainAddress("example.com"), 5353),
	}
	sizes := []int{8150, 8166, 8192, 9000, 65450}
	for _, methodName := range []string{MethodAES128GCM, MethodChaCha20Poly1305} {
		t.Run(methodName, func(t *testing.T) {
			method, err := GetCipherMethod(methodName)
			common.Must(err)
			key := make([]byte, method.KeySaltLength)
			common.Must2(rand.Read(key))
			clientCodec, err := NewUDPPacketCodec(method, [][]byte{key})
			common.Must(err)
			serverCodec, err := NewUDPServerCodec(method, key, time.Minute)
			common.Must(err)
			clientSession, err := clientCodec.NewClientSession()
			common.Must(err)

			req, err := clientSession.EncodePacket(dests[0], []byte("ping"))
			common.Must(err)
			decodedReq, err := serverCodec.DecodePacket(req.Bytes())
			req.Release()
			common.Must(err)

			for _, dest := range dests {
				for _, size := range sizes {
					want := bytes.Repeat([]byte{byte(size), 0x5A}, size/2)
					if len(want) < size {
						want = append(want, 0xA5)
					}
					wire, err := serverCodec.EncodeServerPacket(decodedReq.SessionID, dest, want)
					if err != nil {
						t.Fatalf("dest=%v size=%d: EncodeServerPacket: %v", dest, size, err)
					}
					decoded, err := clientSession.DecodePacket(wire)
					if err != nil {
						t.Fatalf("dest=%v size=%d: DecodePacket(%d wire bytes): %v", dest, size, len(wire), err)
					}
					if decoded.Destination != dest {
						t.Fatalf("dest=%v size=%d: got destination %v", dest, size, decoded.Destination)
					}
					if !bytes.Equal(decoded.Payload, want) {
						t.Fatalf("dest=%v size=%d: got %d-byte payload from %d wire bytes, want %d bytes whole", dest, size, len(decoded.Payload), len(wire), len(want))
					}
				}
			}
		})
	}
}

// The outbounds hand the Shadowsocks 2022 server a UDP reply whole, up to
// 65535 bytes, but the socket back to the client refuses a packet longer than
// an IP packet holds with EMSGSIZE, which ended the reply loop and with it
// every later reply of the session. With a real server encoder, a 9000-byte
// reply stays whole on the wire while a 65508-byte reply exceeds the IP packet
// limit, hits socket EMSGSIZE, and is dropped without ending the session.
func TestUDPReplyLoopDropsRepliesTheSocketRefusesAsTooLong(t *testing.T) {
	type replyCase struct {
		name       string
		methodName string
	}
	for _, tc := range []replyCase{
		{name: "plain"},
		{name: "aes-128-gcm", methodName: MethodAES128GCM},
		{name: "chacha20-poly1305", methodName: MethodChaCha20Poly1305},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.LocalHostIP.IP()})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { sink.Close() })
			conn, err := net.DialUDP("udp", nil, sink.LocalAddr().(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { conn.Close() })

			dest := net.UDPDestination(net.LocalHostIP, 53)
			var encode func(net.Destination, []byte) ([]byte, error)
			var decode func([]byte) ([]byte, error)
			if tc.methodName != "" {
				method, err := GetCipherMethod(tc.methodName)
				common.Must(err)
				key := make([]byte, method.KeySaltLength)
				common.Must2(rand.Read(key))
				clientCodec, err := NewUDPPacketCodec(method, [][]byte{key})
				common.Must(err)
				serverCodec, err := NewUDPServerCodec(method, key, time.Minute)
				common.Must(err)
				clientSession, err := clientCodec.NewClientSession()
				common.Must(err)

				req, err := clientSession.EncodePacket(dest, []byte("init"))
				common.Must(err)
				decodedReq, err := serverCodec.DecodePacket(req.Bytes())
				req.Release()
				common.Must(err)

				encode = func(d net.Destination, payload []byte) ([]byte, error) {
					return serverCodec.EncodeServerPacket(decodedReq.SessionID, d, payload)
				}
				decode = func(wire []byte) ([]byte, error) {
					pkt, err := clientSession.DecodePacket(wire)
					if err != nil {
						return nil, err
					}
					return pkt.Payload, nil
				}
			} else {
				decode = func(wire []byte) ([]byte, error) {
					return bytes.Clone(wire), nil
				}
			}

			// as the server builds a session: its idle timer comes before the
			// reply loop, which updates it and stops it when the link ends
			s := &ServerUDPSession{}
			s.timer = signal.CancelAfterInactivity(context.Background(), func() {}, time.Minute)
			s.UpdateConn(conn)
			reader, writer := pipe.New(pipe.WithoutSizeLimit())
			whole9k := bytes.Repeat([]byte{0x3C}, 9000)
			wholeBuf := buf.NewWithSize(int32(len(whole9k)))
			common.Must2(wholeBuf.Write(whole9k))
			tooLong := buf.NewWithSize(65508)
			tooLong.Extend(65508)
			replies := buf.MultiBuffer{buf.FromBytes([]byte("ping")), wholeBuf, tooLong, buf.FromBytes([]byte("pong"))}
			if err := writer.WriteMultiBuffer(replies); err != nil {
				t.Fatal(err)
			}
			writer.Close()
			done := make(chan struct{})
			go func() {
				handleUDPResponse(s, &transport.Link{Reader: reader}, dest, encode)
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("the reply loop did not end with its link")
			}

			received := make([]byte, 65536)
			for _, want := range [][]byte{[]byte("ping"), whole9k, []byte("pong")} {
				if err := sink.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatal(err)
				}
				n, _, err := sink.ReadFrom(received)
				if err != nil {
					t.Fatalf("waiting for %d-byte reply: %v", len(want), err)
				}
				got, err := decode(received[:n])
				if err != nil {
					t.Fatalf("decoding %d wire bytes (want %d-byte payload): %v", n, len(want), err)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("received a reply of %d bytes, want %d", len(got), len(want))
				}
			}
		})
	}
}
