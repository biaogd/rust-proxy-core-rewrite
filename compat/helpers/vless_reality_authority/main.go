package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/gofrs/uuid/v5"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inner"
	"github.com/metacubex/mihomo/listener/reality"
	"github.com/metacubex/mihomo/listener/sing_vless"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

const (
	defaultPrivateKey = "yMqyglp3FKXPpjcrwNfBYCQS-UrXduKhlDVqqlnMrWw"
	defaultShortID    = "10f897e26c4b9478"
	defaultServerName = "itunes.apple.com"
	defaultDest       = "itunes.apple.com:443"
)

type echoHandler struct {
	output       sync.Mutex
	innerTLS     *tls.Config
	innerTLSPort uint16
}

var _ sing_vless.Handler = (*echoHandler)(nil)

func (handler *echoHandler) NewConnection(_ context.Context, conn net.Conn, metadata M.Metadata) error {
	defer conn.Close()
	destination := metadata.Destination
	host := destination.Fqdn
	if host == "" && destination.Addr.IsValid() {
		host = destination.Addr.String()
	}
	handler.output.Lock()
	fmt.Printf("CONNECT %s:%d\n", host, destination.Port)
	handler.output.Unlock()
	if handler.innerTLS != nil && destination.Port == handler.innerTLSPort {
		inner := tls.Server(conn, handler.innerTLS)
		if err := inner.Handshake(); err != nil {
			return err
		}
		handler.output.Lock()
		fmt.Printf("INNER_TLS %s %x\n", inner.ConnectionState().ServerName, inner.ConnectionState().CipherSuite)
		handler.output.Unlock()
		_, err := io.Copy(inner, inner)
		return err
	}
	_, err := io.Copy(conn, conn)
	return err
}

func (handler *echoHandler) NewPacketConnection(_ context.Context, conn N.PacketConn, _ M.Metadata) error {
	conn.Close()
	return nil
}

func (handler *echoHandler) NewError(_ context.Context, err error) {
	fmt.Fprintln(os.Stderr, err)
}

type destTunnel struct{}

func (destTunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata) {
	defer conn.Close()
	address := metadata.String()
	if metadata.Host != "" {
		address = net.JoinHostPort(metadata.Host, fmt.Sprintf("%d", metadata.DstPort))
	}
	remote, err := net.Dial("tcp", address)
	if err != nil {
		return
	}
	defer remote.Close()
	go func() { _, _ = io.Copy(remote, conn) }()
	_, _ = io.Copy(conn, remote)
}

func (destTunnel) HandleUDPPacket(_ C.UDPPacket, _ *C.Metadata) {}

func (destTunnel) NatTable() C.NatTable { return nil }

func main() {
	listen := flag.String("listen", "127.0.0.1:0", "TCP listen address")
	uuidText := flag.String("uuid", "", "accepted VLESS UUID")
	privateKey := flag.String("reality-private-key", defaultPrivateKey, "REALITY private key (raw URL-safe base64)")
	shortID := flag.String("reality-short-id", defaultShortID, "REALITY short id (hex)")
	serverName := flag.String("reality-server-name", defaultServerName, "REALITY server name")
	dest := flag.String("reality-dest", defaultDest, "REALITY dest host:port")
	flow := flag.String("flow", "", "optional VLESS flow")
	innerTLSCertificate := flag.String("inner-tls-cert", "", "optional nested TLS certificate")
	innerTLSPrivateKey := flag.String("inner-tls-key", "", "optional nested TLS private key")
	innerTLSPort := flag.Uint("inner-tls-port", 0, "destination port that terminates nested TLS")
	flag.Parse()
	if *uuidText == "" {
		fmt.Fprintln(os.Stderr, "missing -uuid")
		os.Exit(2)
	}
	if _, err := uuid.FromString(*uuidText); err != nil {
		_ = uuid.NewV5(uuid.Nil, *uuidText)
	}
	if *flow != "" && *flow != "xtls-rprx-vision" {
		fmt.Fprintln(os.Stderr, "invalid -flow")
		os.Exit(2)
	}
	if (*innerTLSCertificate == "") != (*innerTLSPrivateKey == "") || *innerTLSPort > 65535 {
		fmt.Fprintln(os.Stderr, "invalid nested TLS configuration")
		os.Exit(2)
	}

	tunnel := destTunnel{}
	inner.New(tunnel)

	builder, err := reality.Config{
		Dest:        *dest,
		PrivateKey:  *privateKey,
		ShortID:     []string{*shortID},
		ServerNames: []string{*serverName},
	}.Build(tunnel)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer listener.Close()
	listener = builder.NewListener(listener)

	var innerTLS *tls.Config
	if *innerTLSCertificate != "" {
		certificate, err := tls.LoadX509KeyPair(*innerTLSCertificate, *innerTLSPrivateKey)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		innerTLS = &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
		}
	}
	handler := &echoHandler{innerTLS: innerTLS, innerTLSPort: uint16(*innerTLSPort)}
	service := sing_vless.NewService[string](handler)
	service.UpdateUsers([]string{"phase6e"}, []string{*uuidText}, []string{*flow})

	fmt.Printf("READY %s\n", listener.Addr().String())
	for {
		conn, err := listener.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		go func(connection net.Conn) {
			defer connection.Close()
			if err := service.NewConnection(context.Background(), connection, M.Metadata{}); err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
		}(conn)
	}
}
