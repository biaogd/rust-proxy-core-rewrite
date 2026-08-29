package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/metacubex/sing-shadowsocks/shadowaead"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/network"
)

type relayHandler struct{}

func (relayHandler) NewConnection(_ context.Context, conn net.Conn, metadata M.Metadata) error {
	upstream, err := net.Dial("tcp", metadata.Destination.String())
	if err != nil {
		return err
	}
	go func() { _, _ = io.Copy(upstream, conn) }()
	_, err = io.Copy(conn, upstream)
	return err
}

func (relayHandler) NewPacketConnection(context.Context, network.PacketConn, M.Metadata) error {
	return nil
}

func (relayHandler) NewError(context.Context, error) {}

func main() {
	password := flag.String("password", "", "Shadowsocks password")
	cipherName := flag.String("cipher", "aes-256-gcm", "Shadowsocks cipher")
	flag.Parse()

	service, err := shadowaead.NewService(*cipherName, nil, *password, 300, relayHandler{})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(ln.Addr().String())
	os.Stdout.Sync()

	for {
		client, err := ln.Accept()
		if err != nil {
			continue
		}
		go func(client net.Conn) {
			_ = service.NewConnection(context.Background(), client, M.Metadata{
				Protocol: "shadowsocks",
				Source:   M.SocksaddrFromNet(client.RemoteAddr()),
			})
		}(client)
	}
}
