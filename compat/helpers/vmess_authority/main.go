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
	E "github.com/metacubex/sing/common/exceptions"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

type echoHandler struct {
	expectedHost string
	expectedPort uint
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

func (h *echoHandler) NewPacketConnection(context.Context, N.PacketConn, M.Metadata) error {
	return E.New("UDP is outside Phase 6D-A")
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
	flag.Parse()
	if *uuid == "" {
		fmt.Fprintln(os.Stderr, "missing -uuid")
		os.Exit(2)
	}

	handler := &echoHandler{expectedHost: *expectedHost, expectedPort: *expectedPort}
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
