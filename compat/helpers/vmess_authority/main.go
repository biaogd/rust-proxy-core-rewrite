package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"

	"github.com/gobwas/ws/wsutil"
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

type websocketConn struct {
	net.Conn
	reader io.ReadWriter
	buffer bytes.Reader
}

type bufferedReadWriter struct {
	io.Reader
	io.Writer
}

func (conn *websocketConn) Read(payload []byte) (int, error) {
	for conn.buffer.Len() == 0 {
		message, _, err := wsutil.ReadClientData(conn.reader)
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

func (h *echoHandler) observe(format string, values ...any) {
	h.output.Lock()
	fmt.Printf(format, values...)
	h.output.Unlock()
}

func upgradeWebSocket(
	connection net.Conn,
	expectedHost string,
	expectedPath string,
) (net.Conn, string, string, error) {
	reader := bufio.NewReader(connection)
	request, err := http.ReadRequest(reader)
	if err != nil {
		return nil, "", "", err
	}
	defer request.Body.Close()
	if request.Method != http.MethodGet || request.Header.Get("Upgrade") != "websocket" {
		return nil, "", "", fmt.Errorf("invalid WebSocket upgrade")
	}
	if expectedHost != "" && request.Host != expectedHost {
		return nil, "", "", fmt.Errorf("unexpected WebSocket host %q", request.Host)
	}
	if expectedPath != "" && request.URL.RequestURI() != expectedPath {
		return nil, "", "", fmt.Errorf("unexpected WebSocket path %q", request.URL.RequestURI())
	}
	key := request.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return nil, "", "", fmt.Errorf("missing WebSocket key")
	}
	digest := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	accept := base64.StdEncoding.EncodeToString(digest[:])
	_, err = fmt.Fprintf(
		connection,
		"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
		accept,
	)
	if err != nil {
		return nil, "", "", err
	}
	return &websocketConn{
		Conn: connection,
		reader: bufferedReadWriter{
			Reader: reader,
			Writer: connection,
		},
	}, request.Host, request.URL.RequestURI(), nil
}

func serve(
	raw net.Conn,
	service *vmess.Service[string],
	handler *echoHandler,
	tlsConfig *tls.Config,
	transport string,
	expectedWSHost string,
	expectedWSPath string,
) {
	defer raw.Close()
	var connection net.Conn = raw
	if tlsConfig != nil {
		tlsConnection := tls.Server(raw, tlsConfig)
		if err := tlsConnection.Handshake(); err != nil {
			return
		}
		handler.observe("TLS %s\n", tlsConnection.ConnectionState().ServerName)
		connection = tlsConnection
	}
	if transport == "ws" {
		wrapped, host, path, err := upgradeWebSocket(connection, expectedWSHost, expectedWSPath)
		if err != nil {
			handler.NewError(context.Background(), err)
			return
		}
		handler.observe("WS %s %s\n", host, path)
		connection = wrapped
	}
	if err := service.NewConnection(context.Background(), connection, M.Metadata{}); err != nil {
		handler.NewError(context.Background(), err)
	}
}

func main() {
	listen := flag.String("listen", "127.0.0.1:0", "TCP listen address")
	uuid := flag.String("uuid", "", "accepted VMess UUID")
	alterID := flag.Int("alter-id", 0, "accepted VMess AlterID count")
	expectedHost := flag.String("expected-host", "", "expected target host")
	expectedPort := flag.Uint("expected-port", 0, "expected target port")
	packetMode := flag.String("packet-mode", "reject", "reject, standard, packetaddr, or xudp")
	transport := flag.String("transport", "tcp", "tcp or ws")
	tlsCertificate := flag.String("tls-cert", "", "optional TLS certificate")
	tlsPrivateKey := flag.String("tls-key", "", "optional TLS private key")
	expectedWSHost := flag.String("expected-ws-host", "", "expected WebSocket Host")
	expectedWSPath := flag.String("expected-ws-path", "", "expected WebSocket request target")
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
	if *transport != "tcp" && *transport != "ws" {
		fmt.Fprintln(os.Stderr, "invalid -transport")
		os.Exit(2)
	}
	if (*tlsCertificate == "") != (*tlsPrivateKey == "") {
		fmt.Fprintln(os.Stderr, "-tls-cert and -tls-key must be paired")
		os.Exit(2)
	}
	var tlsConfig *tls.Config
	if *tlsCertificate != "" {
		keyPair, err := tls.LoadX509KeyPair(*tlsCertificate, *tlsPrivateKey)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{keyPair},
			NextProtos:   []string{"http/1.1"},
			MinVersion:   tls.VersionTLS12,
		}
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
		go serve(
			conn,
			service,
			handler,
			tlsConfig,
			*transport,
			*expectedWSHost,
			*expectedWSPath,
		)
	}
}
