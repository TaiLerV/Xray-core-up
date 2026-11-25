package shadowsocks

import (
	"context"
	"io"
	stdnet "net"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xctx "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type captureLog struct {
	messages chan string
}

func (c captureLog) Handle(msg log.Message) {
	if m, ok := msg.(*log.GeneralMessage); ok {
		select {
		case c.messages <- m.String():
		default:
		}
	}
}

type silentLog struct{}

func (silentLog) Handle(log.Message)        {}
func (silentLog) Enabled(log.Severity) bool { return false }

type ssDropTestConn struct {
	request []byte
	read    bool
	closeCh chan struct{}
}

func (c *ssDropTestConn) Read(p []byte) (int, error) {
	if !c.read {
		c.read = true
		return copy(p, c.request), nil
	}
	<-c.closeCh
	return 0, io.EOF
}

func (c *ssDropTestConn) Write([]byte) (int, error) {
	return 0, &stdnet.OpError{Op: "write", Net: "udp", Err: syscall.EMSGSIZE}
}

func (c *ssDropTestConn) Close() error { return nil }
func (c *ssDropTestConn) LocalAddr() stdnet.Addr {
	return &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: 8388}
}

func (c *ssDropTestConn) RemoteAddr() stdnet.Addr {
	return &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: 40000}
}
func (c *ssDropTestConn) SetDeadline(time.Time) error      { return nil }
func (c *ssDropTestConn) SetReadDeadline(time.Time) error  { return nil }
func (c *ssDropTestConn) SetWriteDeadline(time.Time) error { return nil }

type ssReplyDispatcher struct {
	reply []byte
}

func (*ssReplyDispatcher) Type() interface{} { return nil }
func (*ssReplyDispatcher) Start() error      { return nil }
func (*ssReplyDispatcher) Close() error      { return nil }
func (*ssReplyDispatcher) DispatchLink(context.Context, net.Destination, *transport.Link) error {
	return nil
}

func (d *ssReplyDispatcher) Dispatch(context.Context, net.Destination) (*transport.Link, error) {
	uplinkReader, uplinkWriter := pipe.New(pipe.WithoutSizeLimit())
	downlinkReader, downlinkWriter := pipe.New(pipe.WithoutSizeLimit())
	go func() {
		defer downlinkWriter.Close()
		mb, err := uplinkReader.ReadMultiBufferTimeout(5 * time.Second)
		if err == nil {
			buf.ReleaseMulti(mb)
		}
		b := buf.New()
		b.Write(d.reply)
		_ = downlinkWriter.WriteMultiBuffer(buf.MultiBuffer{b})
	}()
	return &transport.Link{Reader: downlinkReader, Writer: uplinkWriter}, nil
}

func TestHandleUDPPayloadLogsSocketTooLongDrop(t *testing.T) {
	capture := captureLog{messages: make(chan string, 16)}
	log.RegisterHandler(capture)
	t.Cleanup(func() { log.RegisterHandler(silentLog{}) })

	account, err := (&Account{Password: "password", CipherType: CipherType_AES_128_GCM}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	user := &protocol.MemoryUser{Account: account}
	validator := new(Validator)
	if err := validator.Add(user); err != nil {
		t.Fatal(err)
	}
	reqBuf, err := EncodeUDPPacket(&protocol.RequestHeader{
		Version: Version,
		Command: protocol.RequestCommandUDP,
		Address: net.LocalHostIP,
		Port:    53,
		User:    user,
	}, []byte("ping"))
	if err != nil {
		t.Fatal(err)
	}
	reqWire := append([]byte(nil), reqBuf.Bytes()...)
	reqBuf.Release()

	conn := &ssDropTestConn{
		request: reqWire,
		closeCh: make(chan struct{}),
	}
	ctx := xctx.ContextWithID(context.Background(), 7002)
	ctx = session.ContextWithInbound(ctx, &session.Inbound{
		Name:   "shadowsocks",
		Source: net.UDPDestination(net.LocalHostIP, 40000),
	})

	done := make(chan error, 1)
	go func() {
		done <- (&Server{validator: validator}).handleUDPPayload(ctx, conn, &ssReplyDispatcher{reply: []byte("pong")})
	}()

	deadline := time.After(5 * time.Second)
	for {
		select {
		case m := <-capture.messages:
			if strings.Contains(m, "dropped a UDP reply of") && strings.Contains(m, "too long") {
				close(conn.closeCh)
				<-done
				return
			}
		case <-deadline:
			close(conn.closeCh)
			<-done
			t.Fatal("EMSGSIZE reply drop was not logged at debug level")
		}
	}
}
