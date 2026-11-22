//go:build unix || windows

package finalmask

import (
	"net"
	"os"
	"syscall"
	"testing"
)

type tooLongThenReply struct {
	reads int
}

func (s *tooLongThenReply) ReadMsgUDP(payload, _ []byte) (int, int, int, *net.UDPAddr, error) {
	s.reads++
	if s.reads == 1 {
		return len(payload), 0, 0, nil, &net.OpError{Op: "read", Net: "udp", Err: os.NewSyscallError("recvfrom", syscall.EMSGSIZE)}
	}
	return copy(payload, "next"), 0, 0, &net.UDPAddr{Port: 42}, nil
}

func TestWholeDatagramConnDropsMessageTooLong(t *testing.T) {
	socket := new(tooLongThenReply)
	conn := wholeDatagramConn{socket: socket}
	var payload [8]byte
	n, peer, err := conn.ReadFrom(payload[:])
	if err != nil || peer == nil || peer.String() != ":42" || string(payload[:n]) != "next" || socket.reads != 2 {
		t.Fatalf("ReadFrom after %d reads = %q, %v, %v", socket.reads, payload[:n], peer, err)
	}
}
