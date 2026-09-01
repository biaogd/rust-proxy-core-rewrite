package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	vmess "github.com/metacubex/sing-vmess"
	"github.com/metacubex/sing-vmess/packetaddr"
	E "github.com/metacubex/sing/common/exceptions"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

type echoHandler struct {
	expectedHost string
	expectedPort uint
	packetMode   string
	output       sync.Mutex
}

var _ vmess.Handler = (*echoHandler)(nil)

func (h *echoHandler) NewConnection(_ context.Context, conn net.Conn, metadata M.Metadata) error {
	defer conn.Close()
	destination := metadata.Destination
	host := destination.Fqdn
	if host == "" && destination.Addr.IsValid() {
		host = destination.Addr.String()
	}
	if h.expectedHost != "" && host != h.expectedHost {
		return fmt.Errorf("unexpected destination host %q", host)
	}
	if h.expectedPort != 0 && uint(destination.Port) != h.expectedPort {
		return fmt.Errorf("unexpected destination port %d", destination.Port)
	}
	h.output.Lock()
	fmt.Printf("CONNECT %s:%d\n", host, destination.Port)
	h.output.Unlock()
	_, err := io.Copy(conn, conn)
	return err
}

func (h *echoHandler) NewPacketConnection(_ context.Context, conn N.PacketConn, _ M.Metadata) error {
	if h.packetMode == "reject" {
		return E.New("UDP is outside the selected authority mode")
	}
	defer conn.Close()
	packets, ok := conn.(net.PacketConn)
	if !ok {
		return E.New("VMess packet connection lacks net.PacketConn")
	}
	if h.packetMode == "packetaddr" {
		packets = packetaddr.NewConn(packets, M.Socksaddr{})
	}
	buffer := make([]byte, 65_535)
	for {
		length, address, err := packets.ReadFrom(buffer)
		if err != nil {
			return err
		}
		destination := M.SocksaddrFromNet(address)
		host := destination.Fqdn
		if host == "" && destination.Addr.IsValid() {
			host = destination.Addr.String()
		}
		h.output.Lock()
		fmt.Printf("PACKET %s %s:%d %d\n", h.packetMode, host, destination.Port, length)
		h.output.Unlock()
		if _, err := packets.WriteTo(buffer[:length], address); err != nil {
			return err
		}
	}
}

func (h *echoHandler) NewError(_ context.Context, err error) {
	h.output.Lock()
	fmt.Fprintln(os.Stderr, err)
	h.output.Unlock()
}

func main() {
	listen := flag.String("listen", "127.0.0.1:0", "TCP listen address")
	uuid := flag.String("uuid", "", "accepted VMess UUID")
	alterID := flag.Int("alter-id", 0, "accepted VMess AlterID count")
	expectedHost := flag.String("expected-host", "", "expected target host")
	expectedPort := flag.Uint("expected-port", 0, "expected target port")
	packetMode := flag.String("packet-mode", "reject", "reject, standard, packetaddr, or xudp")
	flag.Parse()
	if *uuid == "" {
		fmt.Fprintln(os.Stderr, "missing -uuid")
		os.Exit(2)
	}

	switch *packetMode {
	case "reject", "standard", "packetaddr", "xudp":
	default:
		fmt.Fprintln(os.Stderr, "invalid -packet-mode")
		os.Exit(2)
	}
	handler := &echoHandler{
		expectedHost: *expectedHost,
		expectedPort: *expectedPort,
		packetMode:   *packetMode,
	}
	service := vmess.NewService[string](handler, vmess.ServiceWithDisableHeaderProtection())
	if err := service.UpdateUsers([]string{"phase6d"}, []string{*uuid}, []int{*alterID}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := service.Start(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer service.Close()

	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer listener.Close()
	fmt.Printf("READY %s\n", listener.Addr())
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		go func() {
			if err := service.NewConnection(context.Background(), conn, M.Metadata{}); err != nil {
				_ = conn.Close()
				handler.NewError(context.Background(), err)
			}
		}()
	}
}
