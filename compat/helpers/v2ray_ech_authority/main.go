package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/metacubex/mihomo/component/ech"
	ss "github.com/metacubex/sing-shadowsocks"
	"github.com/metacubex/sing-shadowsocks/shadowaead"
	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	tls "github.com/metacubex/tls"
)

type relayHandler struct{}

func (relayHandler) NewConnection(_ context.Context, inbound net.Conn, metadata M.Metadata) error {
	outbound, err := net.Dial("tcp", metadata.Destination.String())
	if err != nil {
		return err
	}
	defer outbound.Close()
	done := make(chan error, 1)
	go func() {
		_, copyErr := io.Copy(outbound, inbound)
		done <- copyErr
	}()
	_, err = io.Copy(inbound, outbound)
	if err == nil {
		err = <-done
	}
	return err
}

func (relayHandler) NewPacketConnection(context.Context, N.PacketConn, M.Metadata) error {
	return errors.New("UDP is outside the v2ray-plugin TCP authority")
}

func (relayHandler) NewError(_ context.Context, err error) {
	fmt.Fprintln(os.Stderr, err)
}

type websocketConn struct {
	net.Conn
	buffer bytes.Reader
}

func (conn *websocketConn) Read(payload []byte) (int, error) {
	for conn.buffer.Len() == 0 {
		message, _, err := wsutil.ReadClientData(conn.Conn)
		if err != nil {
			return 0, err
		}
		conn.buffer.Reset(message)
	}
	return conn.buffer.Read(payload)
}

func (conn *websocketConn) Write(payload []byte) (int, error) {
	if err := wsutil.WriteServerBinary(conn.Conn, payload); err != nil {
		return 0, err
	}
	return len(payload), nil
}

func main() {
	if len(os.Args) != 7 {
		panic("usage: v2ray-ech-authority LISTEN PASSWORD CIPHER CERT KEY ECH_KEY")
	}
	listen, password, cipher := os.Args[1], os.Args[2], os.Args[3]
	certificate, privateKey, echKey := os.Args[4], os.Args[5], os.Args[6]

	keyPair, err := tls.LoadX509KeyPair(certificate, privateKey)
	if err != nil {
		panic(err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{keyPair},
		NextProtos:   []string{"http/1.1"},
		MinVersion:   tls.VersionTLS13,
	}
	if err := ech.LoadECHKey(echKey, tlsConfig); err != nil {
		panic(err)
	}
	service, err := shadowaead.NewService(cipher, nil, password, int64((5 * time.Minute).Seconds()), relayHandler{})
	if err != nil {
		panic(err)
	}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	fmt.Printf("READY %s\n", listener.Addr())
	for {
		raw, acceptErr := listener.Accept()
		if acceptErr != nil {
			panic(acceptErr)
		}
		go serve(raw, tlsConfig, service)
	}
}

func serve(raw net.Conn, tlsConfig *tls.Config, service ss.Service) {
	defer raw.Close()
	connection := tls.Server(raw, tlsConfig)
	if err := connection.Handshake(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	if !connection.ConnectionState().ECHAccepted {
		fmt.Fprintln(os.Stderr, "connection did not negotiate ECH")
		return
	}
	if _, err := ws.Upgrade(connection); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	wrapped := &websocketConn{Conn: connection}
	metadata := M.Metadata{Protocol: "shadowsocks", Source: M.SocksaddrFromNet(raw.RemoteAddr())}
	if err := service.NewConnection(context.Background(), wrapped, metadata); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}

var _ N.TCPConnectionHandler = relayHandler{}
var _ N.UDPConnectionHandler = relayHandler{}
var _ N.UDPHandler = serviceUdpGuard{}

// Keep the helper compile-time honest about not accidentally wiring UDP.
type serviceUdpGuard struct{}

func (serviceUdpGuard) NewPacket(context.Context, N.PacketConn, *buf.Buffer, M.Metadata) error {
	return errors.New("UDP disabled")
}
