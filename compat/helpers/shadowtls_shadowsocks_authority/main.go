package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/transport/shadowtls"
	ss "github.com/metacubex/sing-shadowsocks"
	"github.com/metacubex/sing-shadowsocks/shadowaead_2022"
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
	return fmt.Errorf("UDP is outside the shadow-tls TCP authority")
}

func (relayHandler) NewError(_ context.Context, err error) {
	fmt.Fprintln(os.Stderr, err)
}

func main() {
	if len(os.Args) != 6 && len(os.Args) != 7 && len(os.Args) != 8 {
		panic("usage: shadowtls-shadowsocks-authority LISTEN PASSWORD CIPHER PLUGIN_PASSWORD VERSION [STRICT] [CLIENT_CA_PEM]")
	}
	listen := os.Args[1]
	password := os.Args[2]
	cipher := os.Args[3]
	pluginPassword := os.Args[4]
	version, err := strconv.Atoi(os.Args[5])
	if err != nil {
		panic(err)
	}
	strictMode := version == 3
	if len(os.Args) >= 7 {
		strictMode = os.Args[6] != "0"
	}
	var clientCAPEM []byte
	if len(os.Args) == 8 {
		clientCAPEM, err = os.ReadFile(os.Args[7])
		if err != nil {
			panic(err)
		}
	}

	camouflageAddr, err := startCamouflageServer(version == 1 || (version == 3 && !strictMode), clientCAPEM)
	if err != nil {
		panic(err)
	}
	serverConfig, err := newServerConfig(version, pluginPassword, camouflageAddr, strictMode)
	if err != nil {
		panic(err)
	}
	service, err := shadowaead_2022.NewServiceWithPassword(
		cipher,
		password,
		int64((5*time.Minute).Seconds()),
		relayHandler{},
		time.Now,
	)
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
		go serve(raw, serverConfig, service)
	}
}

func serve(raw net.Conn, serverConfig *shadowtls.ServerConfig, service ss.Service) {
	defer raw.Close()
	shadowConn, err := shadowtls.Server(context.Background(), raw, serverConfig)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	metadata := M.Metadata{
		Protocol: "shadowsocks",
		Source:   M.SocksaddrFromNet(raw.RemoteAddr()),
	}
	if err := service.NewConnection(context.Background(), shadowConn, metadata); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}

func startCamouflageServer(tls12Only bool, clientCAPEM []byte) (string, error) {
	certificatePEM, privateKeyPEM, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		return "", err
	}
	certificate, err := tls.X509KeyPair([]byte(certificatePEM), []byte(privateKeyPEM))
	if err != nil {
		return "", err
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		NextProtos:   append([]string(nil), shadowtls.DefaultALPN...),
		MinVersion:   tls.VersionTLS12,
	}
	if tls12Only {
		config.MaxVersion = tls.VersionTLS12
	}
	if len(clientCAPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(clientCAPEM) {
			return "", fmt.Errorf("invalid client CA PEM")
		}
		config.ClientCAs = pool
		config.ClientAuth = tls.RequireAndVerifyClientCert
	}
	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	listener := tls.NewListener(rawListener, config)
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return listener.Addr().String(), nil
}

func newServerConfig(version int, pluginPassword, camouflageAddr string, strictMode bool) (*shadowtls.ServerConfig, error) {
	handshake := shadowtls.HandshakeConfig{
		Server: camouflageAddr,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		},
	}
	var users []shadowtls.User
	if version == 3 {
		users = []shadowtls.User{{Name: "phase6c-user", Password: pluginPassword}}
	}
	return shadowtls.NewServerConfig(
		version,
		pluginPassword,
		users,
		handshake,
		nil,
		strictMode,
		shadowtls.WildcardSNIOff,
	)
}

var _ N.TCPConnectionHandler = relayHandler{}
var _ N.UDPConnectionHandler = relayHandler{}
var _ N.UDPHandler = serviceUdpGuard{}

type serviceUdpGuard struct{}

func (serviceUdpGuard) NewPacket(context.Context, N.PacketConn, *buf.Buffer, M.Metadata) error {
	return fmt.Errorf("UDP disabled")
}
